use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet, LinkedList, hash_map::Entry},
    fs::File,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{ArgAction, Parser, ValueEnum};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use log::{debug, info};
use maja::{
    capture::{
        CaptureReader, SniffedReader, format::pcap::PcapWriter, interface::Resolution,
        link_type::LinkType, packet::PacketRecord,
    },
    packet::{
        Packet, ParseOptions,
        flow::{FlowId, FlowIdAsymmetric, FlowIdSymmetric},
        layer::{ip::protocol::IpProtocol, ip::v4::Ipv4, tcp::Tcp, udp::Udp},
    },
};

/// Split granularity for capture files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SplitGranularity {
    /// Split by source IPv4 address.
    SrcIp,
    /// Split by destination IPv4 address.
    DstIp,
    /// Source and destination IPv4 addresses.
    Tuple2,
    /// Source and destination IPv4 addresses, sorted symmetrically.
    Tuple2Sym,
    /// Source and destination IPv4 addresses plus IP protocol.
    Tuple3,
    /// Symmetric source/destination IPv4 addresses plus IP protocol.
    Tuple3Sym,
    /// Source and destination IPv4 addresses and ports.
    Tuple4,
    /// Symmetric source/destination IPv4 addresses and ports.
    Tuple4Sym,
    /// Source and destination IPv4 addresses, ports, and IP protocol.
    Tuple5,
    /// Symmetric source/destination IPv4 addresses, ports, and IP protocol.
    Tuple5Sym,
}

/// maja-splitcap
///
/// Split a pcap or pcapng capture into per-flow pcap files.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about)]
struct Cli {
    /// Input capture file.
    input: PathBuf,

    /// Output directory for split pcap files.
    output: PathBuf,

    /// Split granularity.
    #[arg(short, long, value_enum, default_value_t = SplitGranularity::Tuple5Sym)]
    granularity: SplitGranularity,

    /// Number of largest flows to write. Use 0 for all flows.
    #[arg(short, long, default_value_t = 0)]
    number: usize,

    /// Use two-pass mode to avoid storing packet data for unselected flows.
    #[arg(long)]
    two_pass: bool,

    /// Override the output pcap snapshot length.
    ///
    /// If omitted, the writer uses the first discovered capture interface
    /// snaplen, or 65535 if the input does not provide one.
    #[arg(long)]
    snap_len: Option<u32>,

    /// Override output pcap timestamp precision.
    ///
    /// Omit this to preserve the input precision. Use `--nanosecond` or
    /// `--nanosecond=true` for nanosecond pcap output, and
    /// `--nanosecond=false` for microsecond pcap output.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true", action = ArgAction::Set)]
    nanosecond: Option<bool>,
}

/// Runtime wrapper for the selected flow-id directionality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SplitFlowId {
    Symmetric(FlowIdSymmetric),
    Asymmetric(FlowIdAsymmetric),
}

impl SplitFlowId {
    fn from_info(granularity: SplitGranularity, info: FlowInfo) -> Self {
        match granularity {
            SplitGranularity::SrcIp => Self::Asymmetric(FlowIdAsymmetric::new(info.src_ip)),
            SplitGranularity::DstIp => Self::Asymmetric(FlowIdAsymmetric::new(info.dst_ip)),
            SplitGranularity::Tuple2 => {
                Self::Asymmetric(FlowIdAsymmetric::new((info.src_ip, info.dst_ip)))
            }
            SplitGranularity::Tuple2Sym => {
                Self::Symmetric(FlowIdSymmetric::new((info.src_ip, info.dst_ip)))
            }
            SplitGranularity::Tuple3 => Self::Asymmetric(FlowIdAsymmetric::new((
                info.src_ip,
                info.dst_ip,
                info.protocol,
            ))),
            SplitGranularity::Tuple3Sym => Self::Symmetric(FlowIdSymmetric::new((
                info.src_ip,
                info.dst_ip,
                info.protocol,
            ))),
            SplitGranularity::Tuple4 => Self::Asymmetric(FlowIdAsymmetric::new((
                info.src_ip,
                info.dst_ip,
                info.src_port,
                info.dst_port,
            ))),
            SplitGranularity::Tuple4Sym => Self::Symmetric(FlowIdSymmetric::new((
                info.src_ip,
                info.dst_ip,
                info.src_port,
                info.dst_port,
            ))),
            SplitGranularity::Tuple5 => Self::Asymmetric(FlowIdAsymmetric::new((
                info.src_ip,
                info.dst_ip,
                info.src_port,
                info.dst_port,
                info.protocol,
            ))),
            SplitGranularity::Tuple5Sym => Self::Symmetric(FlowIdSymmetric::new((
                info.src_ip,
                info.dst_ip,
                info.src_port,
                info.dst_port,
                info.protocol,
            ))),
        }
    }

    fn to_filename(&self) -> String {
        fn flow_id_filename<const SYMMETRIC: bool>(flow_id: &FlowId<SYMMETRIC>) -> String {
            match flow_id {
                FlowId::Ip(ip) => format!("{ip}.pcap"),
                FlowId::Tuple2(ip1, ip2) => format!("{ip1}_{ip2}.pcap"),
                FlowId::Tuple3(ip1, ip2, protocol) => {
                    format!("{ip1}_{ip2}_{protocol}.pcap")
                }
                FlowId::Tuple4(ip1, ip2, port1, port2) => {
                    format!("{ip1}:{port1}_{ip2}:{port2}.pcap")
                }
                FlowId::Tuple5(ip1, ip2, port1, port2, protocol) => {
                    format!("{ip1}:{port1}_{ip2}:{port2}_{protocol}.pcap",)
                }
            }
        }

        match self {
            Self::Symmetric(flow_id) => flow_id_filename(flow_id),
            Self::Asymmetric(flow_id) => flow_id_filename(flow_id),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FlowInfo {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: IpProtocol,
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug, Clone, Copy)]
struct OutputPcapConfig {
    snap_len: u32,
    nanosecond: bool,
}

fn process_packet(packet: &PacketRecord<'_>) -> Option<FlowInfo> {
    let mut parsed = Packet::new(packet.data.as_ref());
    parsed
        .try_parse_with_link_type(packet.link_type, ParseOptions::default())
        .ok()?;

    let ipv4 = parsed.layer_viewer(Ipv4)?;
    let protocol = ipv4.protocol().get();
    let (src_port, dst_port) = if let Some(tcp) = parsed.layer_viewer(Tcp) {
        (tcp.src_port().get(), tcp.dst_port().get())
    } else if let Some(udp) = parsed.layer_viewer(Udp) {
        (udp.src_port().get(), udp.dst_port().get())
    } else {
        (0, 0)
    };

    Some(FlowInfo {
        src_ip: IpAddr::V4(ipv4.src().get()),
        dst_ip: IpAddr::V4(ipv4.dst().get()),
        protocol,
        src_port,
        dst_port,
    })
}

fn main() -> anyhow::Result<()> {
    let logger = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .build();
    let level = logger.filter();

    let multi = MultiProgress::new();
    LogWrapper::new(multi.clone(), logger).try_init()?;
    log::set_max_level(level);

    let args = Cli::parse();
    std::fs::create_dir_all(&args.output)?;

    let reader = SniffedReader::open(&args.input)?;
    let format = format!("{:?}", reader.format());

    info!("Input format: {format}");
    info!(
        "Mode: {}",
        if args.two_pass {
            "two-pass"
        } else {
            "single-pass"
        }
    );
    if args.number > 0 {
        info!("Writing top {} flows", args.number);
    }
    debug!("CLI arguments: {args:?}");

    if args.two_pass {
        drop(reader);
        two_pass_split(args, multi)?;
    } else {
        single_pass_split(args, reader, multi)?;
    }

    Ok(())
}

fn output_pcap_config(reader: &SniffedReader<File>, args: &Cli) -> OutputPcapConfig {
    let interfaces = reader.interfaces();
    let snap_len = args
        .snap_len
        .or_else(|| interfaces.first().map(|interface| interface.snap_len))
        .unwrap_or(65535);

    let nanosecond = args.nanosecond.unwrap_or_else(|| match reader {
        SniffedReader::Pcap(reader) => reader.nanosecond,
        SniffedReader::Pcapng(_) => reader
            .interfaces()
            .iter()
            .any(|interface| matches!(interface.resolution, Resolution::PowerOfTen(9))),
    });

    OutputPcapConfig {
        snap_len,
        nanosecond,
    }
}

fn log_capture_interfaces(reader: &SniffedReader<File>) {
    let interfaces = reader.interfaces();
    if interfaces.is_empty() {
        info!("No capture interface metadata discovered");
        return;
    }

    for (index, interface) in interfaces.iter().enumerate() {
        if index == 0 {
            info!("Default link type: {}", interface.link_type);
            info!("SnapLen: {}", interface.snap_len);
            info!("Resolution: {}", interface.resolution);
        } else {
            info!(
                "Interface {index}: link type {}, SnapLen {}, Resolution {}",
                interface.link_type, interface.snap_len, interface.resolution
            );
        }
    }
}

fn log_output_config(output_config: OutputPcapConfig) {
    info!("Output SnapLen: {}", output_config.snap_len);
    info!(
        "Output timestamp precision: {}",
        if output_config.nanosecond {
            "nanoseconds"
        } else {
            "microseconds"
        }
    );
}

fn single_pass_split(
    args: Cli,
    mut reader: SniffedReader<File>,
    multi: MultiProgress,
) -> anyhow::Result<()> {
    let pg = packet_progress(&multi, &args.input, "reading");

    let mut flows: HashMap<SplitFlowId, LinkedList<PacketRecord<'static>>> = HashMap::new();
    let mut total_packets = 0u64;
    let mut skipped_packets = 0u64;
    let mut written_packets = 0u64;

    while let Some(packet) = reader.next_packet()? {
        total_packets += 1;
        pg.inc(1);

        let Some(flow_info) = process_packet(&packet) else {
            skipped_packets += 1;
            debug!("Skipping non-IPv4 or malformed packet");
            continue;
        };

        let flow_key = SplitFlowId::from_info(args.granularity, flow_info);
        flows
            .entry(flow_key)
            .or_default()
            .push_back(packet.to_owned());
    }

    pg.finish_and_clear();
    log_capture_interfaces(&reader);
    let output_config = output_pcap_config(&reader, &args);
    log_output_config(output_config);

    let mut selected_flows = flows.into_iter().collect::<Vec<_>>();
    selected_flows.sort_by_key(|(_, packet_list)| Reverse(packet_list.len()));
    if args.number > 0 {
        selected_flows.truncate(args.number);
    }

    let total_flows = selected_flows.len();
    let top_flows = selected_flows
        .iter()
        .take(10)
        .map(|(flow_key, packets)| (flow_key.clone(), packets.len() as u64))
        .collect::<Vec<_>>();

    let pg = flow_progress(&multi, selected_flows.len() as u64, "writing");
    for (flow_key, packet_list) in selected_flows {
        let Some(first_packet) = packet_list.front() else {
            continue;
        };
        let mut writer = create_writer(
            &args.output,
            &flow_key,
            first_packet.link_type,
            output_config,
        )?;

        written_packets += packet_list.len() as u64;
        for packet in packet_list {
            writer.write_packet(&packet)?;
        }

        writer.flush()?;
        pg.inc(1);
    }
    pg.finish_and_clear();

    print_summary(
        "Split Summary",
        total_packets,
        written_packets,
        skipped_packets,
        total_flows as u64,
        &top_flows,
    );

    Ok(())
}

fn two_pass_split(args: Cli, multi: MultiProgress) -> anyhow::Result<()> {
    info!("Pass 1/2: counting packets per flow");

    let mut reader = SniffedReader::open(&args.input)?;
    let pg = packet_progress(&multi, &args.input, "pass 1");

    let mut flow_counts: HashMap<SplitFlowId, u64> = HashMap::new();
    let mut total_packets = 0u64;
    let mut skipped_packets = 0u64;

    while let Some(packet) = reader.next_packet()? {
        total_packets += 1;
        pg.inc(1);

        let Some(flow_info) = process_packet(&packet) else {
            skipped_packets += 1;
            continue;
        };

        let flow_key = SplitFlowId::from_info(args.granularity, flow_info);
        *flow_counts.entry(flow_key).or_default() += 1;
    }

    pg.finish_and_clear();
    log_capture_interfaces(&reader);
    let output_config = output_pcap_config(&reader, &args);
    log_output_config(output_config);
    info!("Pass 1 complete: {} flows found", flow_counts.len());

    let mut flows_by_count = flow_counts.into_iter().collect::<Vec<_>>();
    flows_by_count.sort_by_key(|(_, count)| Reverse(*count));

    let selected_flow_counts = if args.number > 0 {
        flows_by_count
            .into_iter()
            .take(args.number)
            .collect::<Vec<_>>()
    } else {
        flows_by_count
    };
    let selected_flows = selected_flow_counts
        .iter()
        .map(|(flow_key, _)| flow_key.clone())
        .collect::<HashSet<_>>();

    info!("Pass 2/2: extracting {} flows", selected_flows.len());

    let mut reader = SniffedReader::open(&args.input)?;
    let pg = packet_progress(&multi, &args.input, "pass 2");

    let mut writers: HashMap<SplitFlowId, PcapWriter<File>> = HashMap::new();
    let mut packet_counts: HashMap<SplitFlowId, u64> = HashMap::new();
    let mut written_packets = 0u64;

    while let Some(packet) = reader.next_packet()? {
        pg.inc(1);

        let Some(flow_info) = process_packet(&packet) else {
            continue;
        };

        let flow_key = SplitFlowId::from_info(args.granularity, flow_info);
        if !selected_flows.contains(&flow_key) {
            continue;
        }

        let writer = match writers.entry(flow_key.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let writer =
                    create_writer(&args.output, &flow_key, packet.link_type, output_config)?;
                entry.insert(writer)
            }
        };

        writer.write_packet(&packet)?;
        *packet_counts.entry(flow_key).or_default() += 1;
        written_packets += 1;
    }

    for (_, mut writer) in writers {
        writer.flush()?;
    }
    pg.finish_and_clear();

    let mut top_flows = packet_counts.into_iter().collect::<Vec<_>>();
    top_flows.sort_by_key(|(_, count)| Reverse(*count));
    top_flows.truncate(10);

    print_summary(
        "Split Summary (Two-Pass Mode)",
        total_packets,
        written_packets,
        skipped_packets,
        selected_flows.len() as u64,
        &top_flows,
    );

    Ok(())
}

fn packet_progress(multi: &MultiProgress, input: &Path, stage: &'static str) -> ProgressBar {
    let pg = multi.add(ProgressBar::new_spinner().with_finish(indicatif::ProgressFinish::Abandon));
    pg.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] {prefix} {human_pos:>12} pkts | {msg}")
            .expect("progress style is valid"),
    );
    pg.set_prefix(stage);
    pg.set_message(input.display().to_string());
    pg.enable_steady_tick(Duration::from_secs(1));
    pg
}

fn flow_progress(multi: &MultiProgress, total: u64, stage: &'static str) -> ProgressBar {
    let pg = multi.add(ProgressBar::new(total).with_finish(indicatif::ProgressFinish::Abandon));
    pg.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {prefix} {human_pos:>12}/{human_len:>12} flows | {msg}",
        )
        .expect("progress style is valid"),
    );
    pg.set_prefix(stage);
    pg.set_message("output");
    pg.enable_steady_tick(Duration::from_secs(1));
    pg
}

fn create_writer(
    output_dir: &Path,
    flow_key: &SplitFlowId,
    link_type: LinkType,
    output_config: OutputPcapConfig,
) -> anyhow::Result<PcapWriter<File>> {
    let filename = flow_key.to_filename();
    let path = output_dir.join(&filename);
    let file = File::create(&path)?;
    debug!("Created output file: {}", path.display());
    Ok(PcapWriter::new(
        file,
        false,
        output_config.nanosecond,
        output_config.snap_len,
        link_type,
    )?)
}

fn print_summary(
    title: &str,
    total_packets: u64,
    written_packets: u64,
    skipped_packets: u64,
    output_flows: u64,
    top_flows: &[(SplitFlowId, u64)],
) {
    println!("\n{}", "=".repeat(70));
    println!("{title}");
    println!("{}", "=".repeat(70));
    println!("Total packets processed: {total_packets}");
    println!("Packets written:         {written_packets}");
    println!("Packets skipped:         {skipped_packets}");
    println!("Output flows/files:      {output_flows}");
    println!("Top flows by packet count:");
    println!("{:-<70}", "");
    for (key, count) in top_flows.iter().take(10) {
        println!("{:50} {:>15} packets", key.to_filename(), count);
    }
    println!("{}", "=".repeat(70));
}
