use std::path::PathBuf;

use clap::Parser;
use maja::capture::format::pcap::PcapSliceReader;
use memmap2::Mmap;

#[derive(Debug, Parser)]
struct Cli {
    /// Path to the classic pcap capture file to read
    #[arg(value_name = "CAPTURE_FILE")]
    input: PathBuf,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    let file = std::fs::File::open(&cli.input)?;
    // SAFETY: the file is opened read-only and treated as immutable for the
    // lifetime of the mapping.
    let mmap = unsafe { Mmap::map(&file)? };

    let mut reader = PcapSliceReader::new(&mmap[..])?;

    // Records borrow directly from the mapping with the slice's lifetime, so
    // they can all be collected without copying a single packet byte.
    let mut records = Vec::new();
    while let Some(located) = reader.next_packet_with_offset()? {
        records.push((located.offset, located.packet));
    }

    for (offset, record) in &records {
        let mut packet = maja::packet::Packet::new(record.data.clone());
        packet.parse_with_link_type(record.link_type, Default::default());
        println!("offset={offset:>12} {packet}");
    }

    let ordered = records.windows(2).all(|w| w[0].1 <= w[1].1);
    println!(
        "{} packets, {} bytes mapped, timestamps {}",
        records.len(),
        mmap.len(),
        if ordered { "in order" } else { "OUT OF ORDER" },
    );

    Ok(())
}
