use std::{
    fs::File,
    io::Write,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use clap::{Args, Parser};
use log::{debug, error, info};
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
mod report;

use analysis::Stats;
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
