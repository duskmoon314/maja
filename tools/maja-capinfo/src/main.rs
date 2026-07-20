use std::{
    fs::File,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use clap::{Args, Parser};
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

mod analysis;
mod metadata;

use analysis::Stats;
use metadata::{DumpFormat, DumpResult, MetadataDumper, PacketMetadata};

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
    top_k: usize,

    /// The maximum number of packet metadata rows buffered before a dump batch is written
    #[arg(long, default_value_t = unsafe { NonZeroUsize::new_unchecked(65536) })]
    batch_size: NonZeroUsize,
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

/// Process a single capture file
fn info(file_path: &Path, args: &Flags, multi: &indicatif::MultiProgress) -> anyhow::Result<()> {
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

    let mut dumper = args
        .dump
        .map(|dump_format| {
            MetadataDumper::new(
                dump_path(file_path, args.output.as_deref(), dump_format),
                dump_format,
                args.batch_size.into(),
            )
        })
        .transpose()?;

    let start = Instant::now();
    let mut stats = Stats::default();

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

        stats.update_with_packet(packet.timestamp, packet.original_length);

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

        stats.update_with_metadata(&metadata);
        if let Some(dumper) = &mut dumper {
            dumper.push(metadata)?;
        }
    }

    let dump_result = dumper.map(MetadataDumper::finish).transpose()?;
    let processing_time = start.elapsed().saturating_sub(
        dump_result
            .as_ref()
            .map_or(Duration::ZERO, |result| result.elapsed),
    );

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
        average(stats.total_l2_bytes, stats.total_packets)
    );
    println!(
        "  Total L3 Bytes:   {}B",
        humanize.format(stats.total_l3_bytes as f64)
    );
    println!(
        "    Avg L3 Length:  {:.2}B",
        average(stats.total_l3_bytes, stats.total_packets)
    );
    println!("  Empty Packets:    {}", stats.empty_packets);
    println!("  Errors:           {}", stats.errors);
    println!("  Ordered:          {}", stats.is_ordered);

    let duration_seconds = if let (Some(first_timestamp), Some(last_timestamp)) =
        (stats.first_timestamp, stats.last_timestamp)
    {
        let first_packet_time = temporal_rs::Instant::try_new(first_timestamp as i128)?;
        let last_packet_time = temporal_rs::Instant::try_new(last_timestamp as i128)?;

        println!(
            "  First packet:     {} ({})",
            temporal_rs::ZonedDateTime::try_new_from_instant(
                first_packet_time,
                temporal_rs::UtcOffset::from_minutes(0).into(),
                temporal_rs::Calendar::ISO
            )?,
            first_timestamp
        );
        println!(
            "  Last packet:      {} ({})",
            temporal_rs::ZonedDateTime::try_new_from_instant(
                last_packet_time,
                temporal_rs::UtcOffset::from_minutes(0).into(),
                temporal_rs::Calendar::ISO
            )?,
            last_timestamp
        );

        let duration = last_packet_time.since(&first_packet_time, Default::default())?;
        println!("  Duration:         {}", duration);
        duration
            .total(temporal_rs::options::Unit::Second, None)?
            .as_inner()
    } else {
        println!("  First packet:     N/A");
        println!("  Last packet:      N/A");
        println!("  Duration:         N/A");
        0.0
    };
    println!(
        "  Throughput:       {}pps, {}Bps",
        humanize.format(rate(stats.total_packets, duration_seconds)),
        humanize.format(rate(stats.total_l2_bytes, duration_seconds))
    );

    println!("\nAggregated Statistics:");
    println!(
        "  Length:           {:.2} (± {:.2}) [{}, {}] Bytes",
        stats.lengths.mean(),
        stats.lengths.std_dev(1),
        stats.lengths.min(),
        stats.lengths.max(),
    );

    println!("  Unique SRC IP:    {}", stats.unique_src_ips());
    println!("  Unique DST IP:    {}", stats.unique_dst_ips());
    println!("  TCP Count:        {}", stats.tcp_count);
    println!("  UDP Count:        {}", stats.udp_count);
    println!("  Unique SRC Ports: {}", stats.unique_src_ports());
    println!("  Unique DST Ports: {}", stats.unique_dst_ports());
    println!("  Unique 5-tuple:   {}", stats.flow_set.len());

    println!("\nTop{} Statistics:", args.top_k);
    println!("  Top {} SRC IPs:", args.top_k);
    for (src_ip4, value) in stats.top_src_ips(args.top_k) {
        println!(
            "    {:<15} {:>8}pkts, {:>8}B",
            std::net::Ipv4Addr::from(src_ip4),
            humanize.format(value.count as f64),
            humanize.format(value.bytes as f64)
        );
    }
    println!("  Top {} DST IPs:", args.top_k);
    for (dst_ip4, value) in stats.top_dst_ips(args.top_k) {
        println!(
            "    {:<15} {:>8}pkts, {:>8}B",
            std::net::Ipv4Addr::from(dst_ip4),
            humanize.format(value.count as f64),
            humanize.format(value.bytes as f64)
        );
    }
    println!("  Top {} SRC Ports:", args.top_k);
    for (src_port, value) in stats.top_src_ports(args.top_k) {
        println!(
            "    {:<15} {:>8}pkts, {:>8}B",
            src_port,
            humanize.format(value.count as f64),
            humanize.format(value.bytes as f64)
        );
    }
    println!("  Top {} DST Ports:", args.top_k);
    for (dst_port, value) in stats.top_dst_ports(args.top_k) {
        println!(
            "    {:<15} {:>8}pkts, {:>8}B",
            dst_port,
            humanize.format(value.count as f64),
            humanize.format(value.bytes as f64)
        );
    }

    if let Some(DumpResult {
        path,
        format,
        elapsed,
    }) = dump_result
    {
        println!("\nExport Statistics:");
        println!("  Output File: {}", path.display());
        println!("  Format:                  {format:>12?}");
        println!("  Elapsed Time:   {:>12.6} s", elapsed.as_secs_f64());
    }

    println!("{}", "=".repeat(70));

    Ok(())
}

fn dump_path(file_path: &Path, output: Option<&Path>, format: DumpFormat) -> PathBuf {
    let extension = match format {
        DumpFormat::Csv => "csv",
        DumpFormat::Parquet => "parquet",
    };

    output
        .map(|directory| directory.join(file_path.file_name().expect("Invalid input file name")))
        .unwrap_or_else(|| file_path.to_path_buf())
        .with_extension(extension)
}

fn average(total: u64, count: u64) -> f64 {
    total as f64 / count as f64
}

fn rate(total: u64, duration_seconds: f64) -> f64 {
    total as f64 / duration_seconds
}
