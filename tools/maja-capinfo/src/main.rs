use std::{
    collections::HashSet,
    fs::File,
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::{Args, Parser, ValueEnum};
use log::{debug, error};
use maja::{
    capture::CaptureReader,
    packet::{
        flow::FlowIdSymmetric,
        layer::{
            eth::Eth,
            ip::{protocol::IpProtocol, v4::Ipv4},
            sll::Sll,
            tcp::Tcp,
            udp::Udp,
        },
    },
};
use polars::prelude::*;

/// maja-capinfo
///
/// A tool to get information about capture files.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about)]
struct Cli {
    #[command(flatten)]
    flags: Flags,

    /// Input capture files
    inputs: Vec<PathBuf>,
}

/// CLI arguments
#[derive(Debug, Args)]
struct Flags {
    /// Whether to dump the inner metadata of all packets in the capture file
    #[arg(short, long, value_enum)]
    dump: Option<DumpFormat>,

    /// The output directory for dumped files. If not specified, the same directory as the input file will be used.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// The number of top items to display in the statistics
    #[arg(short = 'k', long, default_value_t = 10)]
    top_k: u32,
}

/// Supported dump formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DumpFormat {
    Csv,
    Parquet,
}

fn main() -> anyhow::Result<()> {
    let logger = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .build();
    let level = logger.filter();
    let multi = indicatif::MultiProgress::new();
    indicatif_log_bridge::LogWrapper::new(multi.clone(), logger).try_init()?;
    log::set_max_level(level);

    let cli = Cli::parse();

    debug!("CLI arguments: {:?}", cli);

    for input in cli.inputs {
        info(&input, &cli.flags, &multi)?;
    }

    Ok(())
}

/// Statistics collected during processing
#[derive(Debug)]
struct Stats {
    total_packets: u64,

    total_l2_bytes: u64,
    total_l3_bytes: u64,

    empty_packets: u64,
    errors: u64,

    first_timestamp: i64,
    last_timestamp: i64,

    is_ordered: bool,

    flow_set: HashSet<FlowIdSymmetric>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            total_packets: 0,
            total_l2_bytes: 0,
            total_l3_bytes: 0,
            empty_packets: 0,
            errors: 0,
            first_timestamp: i64::MAX,
            last_timestamp: i64::MIN,
            is_ordered: true,
            flow_set: HashSet::new(),
        }
    }
}

#[derive(Debug, Default)]
struct PacketMetadata {
    timestamp: i64,
    length: u32,
    eth_type: u16,
    src_ip4: Option<u32>,
    dst_ip4: Option<u32>,
    ip_proto: Option<u8>,
    tos: Option<u8>,
    ttl: Option<u8>,
    total_length: Option<u16>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    tcp_flags: Option<u8>,
    tcp_window: Option<u16>,
    tcp_data_offset: Option<u8>,
    udp_length: Option<u16>,
}

#[derive(Debug, Default)]
struct PacketMetadataCollection {
    timestamp: Vec<i64>,
    length: Vec<u32>,
    eth_type: Vec<u16>,
    src_ip4: Vec<u32>,
    dst_ip4: Vec<u32>,
    ip_proto: Vec<u8>,
    tos: Vec<u8>,
    ttl: Vec<u8>,
    total_length: Vec<u16>,
    src_port: Vec<u16>,
    dst_port: Vec<u16>,
    tcp_flags: Vec<u8>,
    tcp_window: Vec<u16>,
    tcp_data_offset: Vec<u8>,
    udp_length: Vec<u16>,
}

impl PacketMetadataCollection {
    fn push(&mut self, metadata: PacketMetadata) {
        self.timestamp.push(metadata.timestamp);
        self.length.push(metadata.length);
        self.eth_type.push(metadata.eth_type);
        self.src_ip4.push(metadata.src_ip4.unwrap_or(0));
        self.dst_ip4.push(metadata.dst_ip4.unwrap_or(0));
        self.ip_proto.push(metadata.ip_proto.unwrap_or(0));
        self.tos.push(metadata.tos.unwrap_or(0));
        self.ttl.push(metadata.ttl.unwrap_or(0));
        self.total_length.push(metadata.total_length.unwrap_or(0));
        self.src_port.push(metadata.src_port.unwrap_or(0));
        self.dst_port.push(metadata.dst_port.unwrap_or(0));
        self.tcp_flags.push(metadata.tcp_flags.unwrap_or(0));
        self.tcp_window.push(metadata.tcp_window.unwrap_or(0));
        self.tcp_data_offset
            .push(metadata.tcp_data_offset.unwrap_or(0));
        self.udp_length.push(metadata.udp_length.unwrap_or(0));
    }

    fn into_dataframe(self) -> PolarsResult<DataFrame> {
        df!(
            "timestamp" => self.timestamp,
            "length" => self.length,
            "eth_type" => self.eth_type,
            "src_ip4" => self.src_ip4,
            "dst_ip4" => self.dst_ip4,
            "ip_proto" => self.ip_proto,
            "tos" => self.tos,
            "ttl" => self.ttl,
            "total_length" => self.total_length,
            "src_port" => self.src_port,
            "dst_port" => self.dst_port,
            "tcp_flags" => self.tcp_flags,
            "tcp_window" => self.tcp_window,
            "tcp_data_offset" => self.tcp_data_offset,
            "udp_length" => self.udp_length
        )
    }
}

/// Process a single capture file
fn info(file_path: &PathBuf, args: &Flags, multi: &indicatif::MultiProgress) -> anyhow::Result<()> {
    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len();

    let mut reader = maja::capture::SniffedReader::new(file)?;
    let format = reader.format();
    debug!("CaptureFileReader {:?}", reader);

    let pg = multi
        .add(indicatif::ProgressBar::no_length().with_finish(indicatif::ProgressFinish::Abandon));
    pg.set_style(indicatif::ProgressStyle::with_template(
        "[{elapsed_precise}] {human_pos:>12} pkts    {msg}",
    )?);
    pg.set_message(file_path.display().to_string());
    pg.enable_steady_tick(Duration::from_secs(1));

    let start = Instant::now();
    let mut stats = Stats::default();
    let mut curr_timestamp = i64::MIN;
    let mut metadatas = PacketMetadataCollection::default();

    loop {
        pg.inc(1);

        let mut metadata = PacketMetadata::default();

        let packet = reader.next_packet();
        let packet = match packet {
            Ok(Some(packet)) => packet,
            Ok(None) => break,
            Err(e) => {
                stats.errors += 1;
                error!("Error reading packet: {}", e);
                continue;
            }
        };

        if packet.timestamp < curr_timestamp {
            stats.is_ordered = false;
        }
        curr_timestamp = packet.timestamp;

        stats.first_timestamp = stats.first_timestamp.min(packet.timestamp);
        stats.last_timestamp = stats.last_timestamp.max(packet.timestamp);

        stats.total_packets += 1;
        stats.total_l2_bytes += packet.original_length as u64;

        metadata.timestamp = packet.timestamp;
        metadata.length = packet.original_length;

        let link_type = packet.link_type;

        if packet.data.is_empty() {
            debug!("Empty packet data, skipping");
            stats.empty_packets += 1;
            continue;
        }

        let mut packet = maja::packet::Packet::new(packet.data);
        if let Err(err) = packet.try_parse_with_link_type(link_type, Default::default()) {
            debug!("{err}");
            continue;
        }

        if let Some(eth) = packet.layer_viewer(Eth) {
            metadata.eth_type = eth.eth_type().raw();
        } else if let Some(sll) = packet.layer_viewer(Sll) {
            metadata.eth_type = sll.protocol_type().raw();
        }

        if let Some(ipv4) = packet.layer_viewer(Ipv4) {
            stats.total_l3_bytes += ipv4.total_length().get() as u64;

            metadata.src_ip4 = Some(ipv4.src().raw());
            metadata.dst_ip4 = Some(ipv4.dst().raw());
            metadata.ip_proto = Some(ipv4.protocol().raw());
            metadata.tos = Some(ipv4.tos().raw());
            metadata.ttl = Some(ipv4.ttl().raw());
            metadata.total_length = Some(ipv4.total_length().get());

            if let Some(tcp) = packet.layer_viewer(Tcp) {
                metadata.src_port = Some(tcp.src_port().raw());
                metadata.dst_port = Some(tcp.dst_port().raw());
                metadata.tcp_flags = Some(tcp.flags().raw());
                metadata.tcp_window = Some(tcp.window_size().get());
                metadata.tcp_data_offset = Some(tcp.data_offset().get());

                stats.flow_set.insert(FlowIdSymmetric::new((
                    ipv4.src().get(),
                    ipv4.dst().get(),
                    tcp.src_port().get(),
                    tcp.dst_port().get(),
                    IpProtocol::Tcp,
                )));
            } else if let Some(udp) = packet.layer_viewer(Udp) {
                metadata.src_port = Some(udp.src_port().raw());
                metadata.dst_port = Some(udp.dst_port().raw());
                metadata.udp_length = Some(udp.length().get());

                stats.flow_set.insert(FlowIdSymmetric::new((
                    ipv4.src().get(),
                    ipv4.dst().get(),
                    udp.src_port().get(),
                    udp.dst_port().get(),
                    IpProtocol::Udp,
                )));
            }
        }

        metadatas.push(metadata);
    }

    let df = metadatas.into_dataframe()?;
    let lf = df.lazy();

    let agg = lf
        .clone()
        .select([
            // Length statistics
            col("length").mean().alias("length_mean"),
            col("length").min().alias("length_min"),
            col("length").max().alias("length_max"),
            col("length").std(1).alias("length_std"),
            // IP statistics
            col("src_ip4").n_unique().alias("unique_src_ips"),
            col("dst_ip4").n_unique().alias("unique_dst_ips"),
            // Protocol counts
            col("ip_proto").eq(6).sum().alias("tcp_count"),
            col("ip_proto").eq(17).sum().alias("udp_count"),
            // Port statistics
            col("src_port").n_unique().alias("unique_src_ports"),
            col("dst_port").n_unique().alias("unique_dst_ports"),
        ])
        .collect()?;

    let top_src_ips = lf
        .clone()
        .group_by(["src_ip4"])
        .agg([
            col("src_ip4").count().alias("count"),
            col("length").sum().alias("bytes"),
        ])
        .sort(
            ["count"],
            SortMultipleOptions::default().with_order_descending(true),
        )
        .limit(args.top_k)
        .collect()?;

    let top_dst_ips = lf
        .clone()
        .group_by(["dst_ip4"])
        .agg([
            col("dst_ip4").count().alias("count"),
            col("length").sum().alias("bytes"),
        ])
        .sort(
            ["count"],
            SortMultipleOptions::default().with_order_descending(true),
        )
        .limit(args.top_k)
        .collect()?;

    let top_src_ports = lf
        .clone()
        .group_by(["src_port"])
        .agg([
            col("src_port").count().alias("count"),
            col("length").sum().alias("bytes"),
        ])
        .sort(
            ["count"],
            SortMultipleOptions::default().with_order_descending(true),
        )
        .limit(args.top_k)
        .collect()?;

    let top_dst_ports = lf
        .clone()
        .group_by(["dst_port"])
        .agg([
            col("dst_port").count().alias("count"),
            col("length").sum().alias("bytes"),
        ])
        .sort(
            ["count"],
            SortMultipleOptions::default().with_order_descending(true),
        )
        .limit(args.top_k)
        .collect()?;

    let processing_time = start.elapsed();

    pg.finish_and_clear();

    let humanize = human_format::Formatter::new();

    // Print statistics
    println!("{}", "=".repeat(70));
    println!("File:               {}", file_path.display());
    println!("  Format:           {:?}", format);
    println!("  Size:             {}B", humanize.format(file_size as f64));
    println!("  Processing Time:  {:.6} s", processing_time.as_secs_f64());
    println!("  Interfaces:");
    for (i, iface) in reader.interfaces().iter().enumerate() {
        println!(
            "    #{i:<15}LinkType = {}, SnapLen = {}, Resolution = {}",
            iface.link_type, iface.snap_len, iface.resolution
        );
    }

    println!("\nPacket Statistics:");
    println!(
        "  Total Packets:    {}",
        humanize.format(stats.total_packets as f64)
    );
    println!(
        "  Total L2 Bytes:   {}B",
        humanize.format(stats.total_l2_bytes as f64)
    );
    println!(
        "    Avg L2 Length:  {:.2}B",
        stats.total_l2_bytes as f64 / stats.total_packets as f64
    );
    println!(
        "  Total L3 Bytes:   {}B",
        humanize.format(stats.total_l3_bytes as f64)
    );
    println!(
        "    Avg L3 Length:  {:.2}B",
        stats.total_l3_bytes as f64 / stats.total_packets as f64
    );
    println!("  Empty Packets:    {}", stats.empty_packets);
    println!("  Errors:           {}", stats.errors);
    println!("  Ordered:          {}", stats.is_ordered);

    let first_packet_time = temporal_rs::Instant::try_new(stats.first_timestamp as i128)?;
    let last_packet_time = temporal_rs::Instant::try_new(stats.last_timestamp as i128)?;

    println!(
        "  First packet:     {} ({})",
        temporal_rs::ZonedDateTime::try_new_from_instant(
            first_packet_time,
            temporal_rs::UtcOffset::from_minutes(0).into(),
            temporal_rs::Calendar::ISO
        )?,
        stats.first_timestamp
    );
    println!(
        "  Last packet:      {} ({})",
        temporal_rs::ZonedDateTime::try_new_from_instant(
            last_packet_time,
            temporal_rs::UtcOffset::from_minutes(0).into(),
            temporal_rs::Calendar::ISO
        )?,
        stats.last_timestamp
    );

    let duration = last_packet_time.since(&first_packet_time, Default::default())?;
    println!("  Duration:         {}", duration);

    let duration = duration
        .total(temporal_rs::options::Unit::Second, None)?
        .as_inner();
    println!(
        "  Throughput:       {}pps, {}Bps",
        humanize.format(stats.total_packets as f64 / duration),
        humanize.format(stats.total_l2_bytes as f64 / duration)
    );

    println!("\nAggregated Statistics:");
    println!(
        "  Length:           {:.2} (± {:.2}) [{}, {}] Bytes",
        agg.column("length_mean")?.f64()?.get(0).unwrap_or(0.0),
        agg.column("length_std")?.f64()?.get(0).unwrap_or(0.0),
        agg.column("length_min")?.u32()?.get(0).unwrap_or(0),
        agg.column("length_max")?.u32()?.get(0).unwrap_or(0),
    );

    println!(
        "  Unique SRC IP:    {}",
        agg.column("unique_src_ips")?.u32()?.get(0).unwrap_or(0)
    );
    println!(
        "  Unique DST IP:    {}",
        agg.column("unique_dst_ips")?.u32()?.get(0).unwrap_or(0)
    );

    println!(
        "  TCP Count:        {}",
        agg.column("tcp_count")?.u32()?.get(0).unwrap_or(0)
    );
    println!(
        "  UDP Count:        {}",
        agg.column("udp_count")?.u32()?.get(0).unwrap_or(0)
    );

    println!(
        "  Unique SRC Ports: {}",
        agg.column("unique_src_ports")?.u32()?.get(0).unwrap_or(0)
    );
    println!(
        "  Unique DST Ports: {}",
        agg.column("unique_dst_ports")?.u32()?.get(0).unwrap_or(0)
    );
    println!("  Unique 5-tuple:   {}", stats.flow_set.len());

    println!("\nTop10 Statistics:");
    println!("  Top 10 SRC IPs:");
    for row in 0..args.top_k {
        if let Some(record) = top_src_ips.get(row as usize) {
            let src_ip4: u32 = record[0].try_extract()?;
            let count: u32 = record[1].try_extract()?;
            let bytes: u64 = record[2].try_extract()?;
            println!(
                "    {:<15} {:>8}pkts, {:>8}B",
                std::net::Ipv4Addr::from(src_ip4),
                humanize.format(count as f64),
                humanize.format(bytes as f64)
            );
        }
    }
    println!("  Top 10 DST IPs:");
    for row in 0..args.top_k {
        if let Some(record) = top_dst_ips.get(row as usize) {
            let dst_ip4: u32 = record[0].try_extract()?;
            let count: u32 = record[1].try_extract()?;
            let bytes: u64 = record[2].try_extract()?;
            println!(
                "    {:<15} {:>8}pkts, {:>8}B",
                std::net::Ipv4Addr::from(dst_ip4),
                humanize.format(count as f64),
                humanize.format(bytes as f64)
            );
        }
    }
    println!("  Top 10 SRC Ports:");
    for row in 0..args.top_k {
        if let Some(record) = top_src_ports.get(row as usize) {
            let src_port: u16 = record[0].try_extract()?;
            let count: u32 = record[1].try_extract()?;
            let bytes: u64 = record[2].try_extract()?;
            println!(
                "    {:<15} {:>8}pkts, {:>8}B",
                src_port,
                humanize.format(count as f64),
                humanize.format(bytes as f64)
            );
        }
    }
    println!("  Top 10 DST Ports:");
    for row in 0..args.top_k {
        if let Some(record) = top_dst_ports.get(row as usize) {
            let dst_port: u16 = record[0].try_extract()?;
            let count: u32 = record[1].try_extract()?;
            let bytes: u64 = record[2].try_extract()?;
            println!(
                "    {:<15} {:>8}pkts, {:>8}B",
                dst_port,
                humanize.format(count as f64),
                humanize.format(bytes as f64)
            );
        }
    }

    if let Some(dump_format) = args.dump {
        let dump_start = Instant::now();
        let dump_path;

        match dump_format {
            DumpFormat::Csv => {
                dump_path = if let Some(ref out_dir) = args.output {
                    out_dir
                        .join(file_path.file_name().expect("Invalid input file name"))
                        .with_extension("csv")
                } else {
                    file_path.with_extension("csv")
                };
                debug!("Dumping to CSV: {}", dump_path.display());

                lf.sink(
                    SinkDestination::File {
                        target: SinkTarget::Path(
                            dump_path
                                .to_str()
                                .expect("The output path is not valid")
                                .into(),
                        ),
                    },
                    FileWriteFormat::Csv(Default::default()),
                    UnifiedSinkArgs::default(),
                )?
                .collect()?;
            }

            DumpFormat::Parquet => {
                dump_path = if let Some(ref out_dir) = args.output {
                    out_dir
                        .join(file_path.file_name().expect("Invalid input file name"))
                        .with_extension("parquet")
                } else {
                    file_path.with_extension("parquet")
                };
                debug!("Dumping to Parquet: {}", dump_path.display());

                lf.sink(
                    SinkDestination::File {
                        target: SinkTarget::Path(
                            dump_path
                                .to_str()
                                .expect("The output path is not valid")
                                .into(),
                        ),
                    },
                    FileWriteFormat::Parquet(Default::default()),
                    UnifiedSinkArgs::default(),
                )?
                .collect()?;
            }
        }

        let dump_time = dump_start.elapsed();

        println!("\nExport Statistics:");
        println!("  Output File: {}", dump_path.display());
        println!("  Format:                  {dump_format:>12?}");
        println!("  Elapsed Time:   {:>12.6} s", dump_time.as_secs_f64());
    }

    println!("{}", "=".repeat(70));

    Ok(())
}
