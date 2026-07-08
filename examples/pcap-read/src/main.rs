use std::path::PathBuf;

use clap::Parser;
use maja::capture::{CaptureReader, SniffedReader};

#[derive(Debug, Parser)]
struct Cli {
    /// Path to the capture file to read
    #[arg(value_name = "CAPTURE_FILE")]
    input: PathBuf,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    let mut reader = SniffedReader::open(&cli.input)?;

    while let Ok(Some(record)) = reader.next_packet() {
        let mut packet = maja::packet::Packet::new(record.data);

        packet.parse_with_link_type(record.link_type, Default::default());

        println!("{packet}");
    }

    Ok(())
}
