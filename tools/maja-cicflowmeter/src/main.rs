use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

mod flow;

use anyhow::{Context, Result, bail};
use clap::Parser;
use flow::{CICFLOWMETER_HEADER, FlowGenerator, FlowPacket};
use log::{debug, info, warn};
use maja::capture::{CaptureReader, SniffedReader};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about)]
struct Cli {
    /// Input pcap/pcapng file or directory.
    input: PathBuf,

    /// Output directory for generated CSV files.
    output: PathBuf,

    /// Recurse into nested input directories.
    #[arg(long)]
    recursive: bool,

    /// Flow timeout, for example 120s, 500ms, or 1m.
    #[arg(long, value_parser = parse_duration, default_value = "120s")]
    flow_timeout: i64,

    /// Active/idle split timeout, for example 5s or 500ms.
    #[arg(long, value_parser = parse_duration, default_value = "5s")]
    activity_timeout: i64,

    /// Label written in the final CSV column.
    #[arg(long, default_value = "NeedManualLabel")]
    label: String,

    /// Replace existing output files.
    #[arg(long)]
    overwrite: bool,
}

fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .try_init()?;

    let cli = Cli::parse();
    if cli.flow_timeout <= 0 || cli.activity_timeout <= 0 {
        bail!("timeouts must be positive");
    }
    let inputs = collect_inputs(&cli.input, cli.recursive)?;
    if inputs.is_empty() {
        bail!(
            "no pcap or pcapng files found under {}",
            cli.input.display()
        );
    }
    fs::create_dir_all(&cli.output)
        .with_context(|| format!("create output directory {}", cli.output.display()))?;

    for input in inputs {
        let output = cli.output.join(output_name(&input));
        if output.exists() && !cli.overwrite {
            bail!(
                "output file already exists: {} (use --overwrite)",
                output.display()
            );
        }
        info!("processing {} -> {}", input.display(), output.display());
        process_file(&input, &output, &cli)?;
    }
    Ok(())
}

fn process_file(input: &Path, output: &Path, cli: &Cli) -> Result<()> {
    let mut reader =
        SniffedReader::open(input).with_context(|| format!("open capture {}", input.display()))?;
    let file = if cli.overwrite {
        File::create(output)
    } else {
        OpenOptions::new().write(true).create_new(true).open(output)
    }?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{}", CICFLOWMETER_HEADER.join(","))?;
    let mut generator = FlowGenerator::new(cli.flow_timeout, cli.activity_timeout);
    let mut packets = 0u64;
    let mut flows = 0u64;
    let mut skipped = 0u64;

    while let Some(record) = reader.next_packet()? {
        packets += 1;
        match FlowPacket::from_record(&record) {
            Ok(Some(packet)) => {
                for row in generator.add(packet, &cli.label) {
                    if row.values().len() == CICFLOWMETER_HEADER.len() {
                        writeln!(writer, "{}", row.to_csv())?;
                        flows += 1;
                    }
                }
            }
            Ok(None) => skipped += 1,
            Err(error) => {
                skipped += 1;
                debug!("skip packet {} in {}: {}", packets, input.display(), error);
            }
        }
    }
    for row in generator.finish(&cli.label) {
        writeln!(writer, "{}", row.to_csv())?;
        flows += 1;
    }
    writer.flush()?;
    if skipped > 0 {
        warn!(
            "{}: processed {packets} packets, emitted {flows} flows, skipped {skipped} packets",
            input.display()
        );
    } else {
        info!(
            "{}: processed {packets} packets, emitted {flows} flows",
            input.display()
        );
    }
    Ok(())
}

fn collect_inputs(input: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    if input.is_file() {
        if is_capture(input) {
            return Ok(vec![input.to_path_buf()]);
        }
        bail!("input is not a pcap or pcapng file: {}", input.display());
    }
    if !input.is_dir() {
        bail!("input does not exist: {}", input.display());
    }
    let mut files = Vec::new();
    collect_dir(input, recursive, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_dir(dir: &Path, recursive: bool, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in
        fs::read_dir(dir).with_context(|| format!("read input directory {}", dir.display()))?
    {
        let path = entry?.path();
        if path.is_file() && is_capture(&path) {
            files.push(path);
        } else if recursive && path.is_dir() {
            collect_dir(&path, true, files)?;
        }
    }
    Ok(())
}

fn is_capture(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase())
            .as_deref(),
        Some("pcap" | "pcapng" | "cap")
    )
}

fn output_name(input: &Path) -> String {
    format!(
        "{}.csv",
        input
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("capture")
    )
}

fn parse_duration(value: &str) -> Result<i64, String> {
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    if split == 0 {
        return Err("duration must start with an integer".into());
    }
    let number: i64 = value[..split]
        .parse()
        .map_err(|_| "duration is too large".to_string())?;
    let unit = &value[split..];
    let multiplier = match unit {
        "ns" => 1,
        "us" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        "m" => 60_000_000_000,
        "h" => 3_600_000_000_000,
        _ => return Err("duration unit must be ns, us, ms, s, m, or h".into()),
    };
    number
        .checked_mul(multiplier)
        .ok_or_else(|| "duration is too large".to_string())
}
