use std::{
    fs::File,
    io::Write,
    net::IpAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use clap::{Args, Parser};
use log::{debug, error, info};
use maja::{
    packet::layer::{ip::v6::Ipv6, sll::Sll},
    prelude::*,
};

mod analysis;
mod interval;
mod metadata;
mod report;

use analysis::Stats;
use interval::{IntervalStats, write_interval_stats};
use metadata::{DumpFormat, MetadataDumper, PacketMetadata};
use report::{CaptureReport, FileReport, ReportFormat, write_reports};

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

    /// The output directory for generated files. If not specified, the input directory is used.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// The number of top items to display in the statistics
    #[arg(short = 'k', long, default_value_t = 10)]
    top_k: usize,

    /// The maximum number of packet metadata rows buffered before a dump batch is written
    #[arg(long, default_value_t = unsafe { NonZeroUsize::new_unchecked(65536) })]
    batch_size: NonZeroUsize,

    /// Report output format
    #[arg(long, value_enum, default_value_t)]
    format: ReportFormat,

    /// Write each report to a file instead of stdout
    #[arg(long)]
    report_file: bool,

    /// Export exact per-interval statistics
    #[arg(long, value_enum, value_name = "FORMAT")]
    interval_stats: Option<DumpFormat>,

    /// Width of exported statistics intervals
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = parse_interval,
        default_value = "1s",
        requires = "interval_stats"
    )]
    interval: NonZeroU64,
}

fn parse_interval(value: &str) -> Result<NonZeroU64, String> {
    let mut formatter = human_format::Formatter::new();
    formatter.with_scales(human_format::Scales::Time());
    let seconds = formatter
        .try_parse(value)
        .map_err(|error| format!("invalid duration: {error}"))?;
    let nanoseconds = seconds * 1_000_000_000.0;

    if !nanoseconds.is_finite() || nanoseconds < 1.0 {
        return Err("duration must be at least 1ns".to_string());
    }
    if nanoseconds >= i64::MAX as f64 {
        return Err("duration is too large".to_string());
    }

    let rounded = nanoseconds.round();
    let tolerance = (nanoseconds.abs() * f64::EPSILON * 4.0).max(1e-6);
    if (nanoseconds - rounded).abs() > tolerance {
        return Err("duration must resolve to a whole number of nanoseconds".to_string());
    }

    NonZeroU64::new(rounded as u64).ok_or_else(|| "duration must be positive".to_string())
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

    let mut reports = Vec::with_capacity(cli.inputs.len());
    for input in &cli.inputs {
        reports.push(analyze(input, &cli.flags, &multi)?);
    }

    if cli.flags.report_file {
        for (input, report) in cli.inputs.iter().zip(&reports) {
            write_report_file(
                &report_path(
                    input,
                    cli.flags.output.as_deref(),
                    cli.flags.format.extension(),
                ),
                report,
                cli.flags.format,
            )?;
        }
    } else {
        write_reports(std::io::stdout().lock(), &reports, cli.flags.format)?;
    }

    Ok(())
}

/// Process a single capture file
fn analyze(
    file_path: &Path,
    args: &Flags,
    multi: &indicatif::MultiProgress,
) -> anyhow::Result<CaptureReport> {
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
    let mut interval_stats = args
        .interval_stats
        .map(|_| IntervalStats::new(args.interval));

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
        if let Some(interval_stats) = &mut interval_stats {
            interval_stats.update_with_packet(packet.timestamp, packet.original_length);
        }

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

        extract_packet_metadata(&packet, &mut metadata, &mut stats);

        stats.update_with_metadata(&metadata);
        if let Some(interval_stats) = &mut interval_stats {
            interval_stats.update_with_metadata(&metadata);
        }
        if let Some(dumper) = &mut dumper {
            dumper.push(metadata)?;
        }
    }

    let interval_export = match (&interval_stats, args.interval_stats) {
        (Some(stats), Some(format)) => Some(write_interval_stats(
            stats,
            interval_path(file_path, args.output.as_deref(), format),
            format,
        )?),
        _ => None,
    };
    if let Some(export) = &interval_export {
        info!("Interval statistics written to {}", export.path.display());
    }

    let dump_result = dumper.map(MetadataDumper::finish).transpose()?;
    let export_time = dump_result
        .as_ref()
        .map_or(Duration::ZERO, |result| result.elapsed)
        .saturating_add(
            interval_export
                .as_ref()
                .map_or(Duration::ZERO, |result| result.elapsed),
        );
    let processing_time = start.elapsed().saturating_sub(export_time);

    pg.finish_and_clear();

    Ok(CaptureReport::new(
        FileReport::new(
            file_path,
            format,
            file_size,
            processing_time,
            &reader.interfaces(),
        ),
        &stats,
        args.top_k,
        dump_result,
    ))
}

fn extract_packet_metadata<T: AsRef<[u8]>>(
    packet: &maja::packet::Packet<T>,
    metadata: &mut PacketMetadata,
    stats: &mut Stats,
) {
    if let Some(eth) = packet.layer_viewer(Eth) {
        metadata.eth_type = eth.eth_type().raw();
    } else if let Some(sll) = packet.layer_viewer(Sll) {
        metadata.eth_type = sll.protocol_type().raw();
    }

    if let Some(ipv4) = packet.layer_viewer(Ipv4) {
        stats.total_l3_bytes += u64::from(ipv4.total_length().get());

        metadata.src_ip = Some(IpAddr::V4(ipv4.src().get()));
        metadata.dst_ip = Some(IpAddr::V4(ipv4.dst().get()));
        metadata.ip_proto = Some(ipv4.protocol().raw());
        metadata.tos = Some(ipv4.tos().raw());
        metadata.ttl = Some(ipv4.ttl().raw());
        metadata.total_length = Some(ipv4.total_length().get());
    } else if let Some(ipv6) = packet.layer_viewer(Ipv6) {
        let payload_length = ipv6.payload_length().get();
        stats.total_l3_bytes += u64::from(payload_length) + 40;

        metadata.src_ip = Some(IpAddr::V6(ipv6.src().get()));
        metadata.dst_ip = Some(IpAddr::V6(ipv6.dst().get()));
        metadata.ip_proto = Some(ipv6.next_header().raw());
        metadata.tos = Some(ipv6.traffic_class().get());
        metadata.ttl = Some(ipv6.hop_limit().get());
        metadata.ipv6_payload_length = Some(payload_length);
    }

    if metadata.src_ip.is_some() {
        if let Some(tcp) = packet.layer_viewer(Tcp) {
            metadata.ip_proto = Some(u8::from(IpProtocol::Tcp));
            metadata.src_port = Some(tcp.src_port().raw());
            metadata.dst_port = Some(tcp.dst_port().raw());
            metadata.tcp_flags = Some(tcp.flags().raw());
            metadata.tcp_window = Some(tcp.window_size().get());
            metadata.tcp_data_offset = Some(tcp.data_offset().get());
        } else if let Some(udp) = packet.layer_viewer(Udp) {
            metadata.ip_proto = Some(u8::from(IpProtocol::Udp));
            metadata.src_port = Some(udp.src_port().raw());
            metadata.dst_port = Some(udp.dst_port().raw());
            metadata.udp_length = Some(udp.length().get());
        }
    }
}

fn dump_path(file_path: &Path, output: Option<&Path>, format: DumpFormat) -> PathBuf {
    output
        .map(|directory| directory.join(file_path.file_name().expect("Invalid input file name")))
        .unwrap_or_else(|| file_path.to_path_buf())
        .with_extension(format.extension())
}

fn interval_path(file_path: &Path, output: Option<&Path>, format: DumpFormat) -> PathBuf {
    output
        .map(|directory| directory.join(file_path.file_name().expect("Invalid input file name")))
        .unwrap_or_else(|| file_path.to_path_buf())
        .with_extension(format!("intervals.{}", format.extension()))
}

fn report_path(file_path: &Path, output: Option<&Path>, extension: &str) -> PathBuf {
    output
        .map(|directory| directory.join(file_path.file_name().expect("Invalid input file name")))
        .unwrap_or_else(|| file_path.to_path_buf())
        .with_extension(format!("capinfo.{extension}"))
}

fn write_report_file(
    path: &Path,
    report: &CaptureReport,
    format: ReportFormat,
) -> anyhow::Result<()> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(directory)?;

    let mut tempfile = tempfile::NamedTempFile::new_in(directory)?;
    write_reports(&mut tempfile, std::slice::from_ref(report), format)?;
    tempfile.flush()?;
    tempfile.persist(path)?;
    info!("Report written to {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn extracts_ipv6_udp_metadata() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2);
        let mut frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd, // Ethernet
            0x60, 0, 0, 0, // Version, traffic class, and flow label
            0, 8, // Payload length
            17, 64, // UDP and hop limit
        ];
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&dst.octets());
        frame.extend_from_slice(&[0x04, 0xd2, 0x16, 0x2e, 0, 8, 0, 0]);

        let mut packet = maja::packet::Packet::new(frame);
        packet
            .try_parse_with_link_type(LinkType::Ethernet, Default::default())
            .unwrap();
        let mut metadata = PacketMetadata::default();
        let mut stats = Stats::default();
        extract_packet_metadata(&packet, &mut metadata, &mut stats);

        assert_eq!(metadata.src_ip, Some(IpAddr::V6(src)));
        assert_eq!(metadata.dst_ip, Some(IpAddr::V6(dst)));
        assert_eq!(metadata.ip_proto, Some(u8::from(IpProtocol::Udp)));
        assert_eq!(metadata.src_port, Some(1_234));
        assert_eq!(metadata.dst_port, Some(5_678));
        assert_eq!(metadata.tos, Some(0));
        assert_eq!(metadata.ttl, Some(64));
        assert_eq!(metadata.ipv6_payload_length, Some(8));
        assert_eq!(stats.total_l3_bytes, 48);
    }

    #[test]
    fn interval_parser_accepts_time_suffixes() {
        assert_eq!(parse_interval("1s").unwrap().get(), 1_000_000_000);
        assert_eq!(parse_interval("500ms").unwrap().get(), 500_000_000);
        assert_eq!(parse_interval("1.5m").unwrap().get(), 90_000_000_000);
    }

    #[test]
    fn interval_parser_rejects_invalid_durations() {
        assert!(parse_interval("0s").is_err());
        assert!(parse_interval("0.5ns").is_err());
        assert!(parse_interval("1fortnight").is_err());
    }

    #[test]
    fn interval_export_is_optional_and_interval_requires_it() {
        let cli = Cli::try_parse_from(["maja-capinfo"]).unwrap();
        assert_eq!(cli.flags.interval_stats, None);
        assert_eq!(cli.flags.interval.get(), 1_000_000_000);

        let cli = Cli::try_parse_from(["maja-capinfo", "--interval-stats", "csv"]).unwrap();
        assert_eq!(cli.flags.interval_stats, Some(DumpFormat::Csv));
        assert_eq!(cli.flags.interval.get(), 1_000_000_000);

        assert!(Cli::try_parse_from(["maja-capinfo", "--interval", "500ms"]).is_err());
    }

    #[test]
    fn interval_output_path_is_distinct_from_metadata_dump() {
        let capture = Path::new("captures/input.pcap");
        let output = Path::new("exports");

        assert_eq!(
            interval_path(capture, Some(output), DumpFormat::Csv),
            Path::new("exports/input.intervals.csv")
        );
        assert_eq!(
            dump_path(capture, Some(output), DumpFormat::Csv),
            Path::new("exports/input.csv")
        );
    }
}
