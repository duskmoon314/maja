//! Reorder packets in a capture file by timestamp.
//!
//! The input file (pcap or pcapng) is memory-mapped and scanned once to
//! build a compact index of `(timestamp, offset, record_len)` per packet —
//! no packet bytes are copied while indexing, so memory usage stays
//! proportional to the packet count, not the capture size. The sorted output
//! is then written by copying the original record bytes verbatim from the
//! mapping, preserving the input format, byte order, and timestamp
//! precision.
//!
//! For pcapng input, blocks before the first packet block (SHB, IDBs) are
//! copied first, packet blocks follow in timestamp order, and any non-packet
//! blocks after the first packet (NRB, ISB, ...) keep their original order
//! at the end. Multi-section captures are reordered section by section:
//! packet blocks never cross a section boundary, because their interface
//! IDs refer to the interface list of their own section. Interface
//! description blocks appearing after packet blocks are hoisted after the
//! initial interface descriptions, preserving interface numbering. Simple
//! packet blocks (which carry no timestamps) are rejected.

use std::{
    ffi::OsString,
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail, ensure};
use clap::Parser;
use maja::capture::{
    CaptureError, CaptureFormat, SniffedSliceReader,
    format::{
        pcap::{PcapHeader, PcapSliceReader},
        pcapng::{PcapngBlock, PcapngSliceReader},
    },
};
use memmap2::Mmap;

/// Maximum number of misplaced packets listed individually in dry-run output.
const DRY_RUN_DETAIL_LIMIT: usize = 100;

/// maja-reordercap
///
/// Reorder packets in a capture file by timestamp.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about)]
struct Cli {
    /// Path to the input capture file
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Path to the output file (default: <input>.reordered.<format>)
    #[arg(value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Report out-of-order packets without writing any output
    #[arg(short = 'd', long)]
    dry_run: bool,

    /// Do not write output when the input is already ordered
    #[arg(short = 'n', long)]
    no_output: bool,
}

/// Compact index entry for one packet record: everything needed to copy the
/// record verbatim from the mapped input after sorting.
#[derive(Debug, Clone, Copy)]
struct PacketIndex {
    /// Timestamp in nanoseconds since the Unix epoch
    timestamp: i64,
    /// Byte offset of the packet record in the input file
    offset: usize,
    /// Total record length in bytes (record header + captured data, or the
    /// whole block for pcapng)
    record_len: usize,
}

/// A packet whose timestamp is earlier than the latest one seen before it.
#[derive(Debug, Clone, Copy)]
struct Misplaced {
    /// Frame number of the misplaced packet (1-based, global across sections)
    frame: usize,
    /// Timestamp of the misplaced packet in nanoseconds
    timestamp: i64,
    /// Frame number holding the latest timestamp seen so far
    latest_frame: usize,
    /// How much earlier this packet is than `latest_frame`, in nanoseconds
    backward: i64,
}

/// Packet index plus out-of-order detection, built in a single scan.
#[derive(Debug, Default)]
struct Scan {
    index: Vec<PacketIndex>,
    misplaced: Vec<Misplaced>,
    max_timestamp: i64,
    latest_frame: usize,
}

impl Scan {
    fn new() -> Self {
        Self {
            max_timestamp: i64::MIN,
            ..Default::default()
        }
    }

    fn push(&mut self, timestamp: i64, offset: usize, record_len: usize, frame: usize) {
        if timestamp < self.max_timestamp {
            self.misplaced.push(Misplaced {
                frame,
                timestamp,
                latest_frame: self.latest_frame,
                backward: self.max_timestamp - timestamp,
            });
        } else {
            self.max_timestamp = timestamp;
            self.latest_frame = frame;
        }

        self.index.push(PacketIndex {
            timestamp,
            offset,
            record_len,
        });
    }
}

/// One independently reorderable part of the input: a whole pcap capture, or
/// a single section of a pcapng capture.
#[derive(Debug)]
struct SectionScan {
    /// Byte range before the first packet record (the pcap global header, or
    /// the SHB and IDBs of a pcapng section), copied verbatim
    prefix: (usize, usize),
    /// Interface description blocks that appear after the first packet
    /// block, as `(offset, len)` in original order. They are hoisted right
    /// after `prefix`: keeping their relative order preserves interface
    /// numbering, and every packet block still follows all of them.
    late_idbs: Vec<(usize, usize)>,
    /// Packet index and out-of-order information
    scan: Scan,
    /// Non-packet blocks after the first packet block as `(offset, len)`,
    /// copied in original order after the sorted packets (pcapng only)
    suffix: Vec<(usize, usize)>,
}

/// Scan a classic pcap capture.
fn scan_pcap(data: &[u8]) -> anyhow::Result<Vec<SectionScan>> {
    let mut reader = PcapSliceReader::new(data)?;

    let mut scan = Scan::new();
    while let Some(located) = reader.next_packet_with_offset()? {
        let frame = scan.index.len() + 1;
        scan.push(
            located.packet.timestamp,
            located.offset,
            located.raw.len(),
            frame,
        );
    }

    Ok(vec![SectionScan {
        prefix: (0, PcapHeader::LEN),
        late_idbs: Vec::new(),
        scan,
        suffix: Vec::new(),
    }])
}

/// Scan a pcapng capture section by section, keeping non-packet blocks out
/// of the sort.
fn scan_pcapng(data: &[u8]) -> anyhow::Result<Vec<SectionScan>> {
    let mut reader = PcapngSliceReader::new(data)?;

    let mut sections = Vec::new();
    let mut in_section = false;
    let mut section_start = 0;
    let mut prefix_end = None;
    let mut late_idbs = Vec::new();
    let mut scan = Scan::new();
    let mut suffix = Vec::new();
    let mut frame = 0;

    while let Some(record) = reader.next_block()? {
        match &record.block {
            PcapngBlock::SectionHeader(_) => {
                if in_section {
                    // Close the current section and start a new one.
                    sections.push(SectionScan {
                        prefix: (
                            section_start,
                            prefix_end.unwrap_or(record.offset) - section_start,
                        ),
                        late_idbs: std::mem::take(&mut late_idbs),
                        scan: std::mem::take(&mut scan),
                        suffix: std::mem::take(&mut suffix),
                    });
                }
                in_section = true;
                section_start = record.offset;
                prefix_end = None;
                scan = Scan::new();
            }

            PcapngBlock::InterfaceDescription(_) => {
                // Late IDBs keep their relative order so interface numbering
                // is preserved; they are emitted right after the prefix.
                if prefix_end.is_some() {
                    late_idbs.push((record.offset, record.raw.len()));
                }
            }

            PcapngBlock::SimplePacket(_) => {
                bail!("pcapng simple packet blocks have no timestamps and cannot be reordered");
            }

            PcapngBlock::EnhancedPacket(ep) => {
                let interface = reader
                    .interface_descriptions()
                    .get(ep.interface_id as usize)
                    .ok_or(CaptureError::InvalidPcapngPacketInterfaceId(
                        ep.interface_id,
                    ))?;
                prefix_end.get_or_insert(record.offset);
                frame += 1;
                scan.push(
                    ep.packet_timestamp(interface),
                    record.offset,
                    record.raw.len(),
                    frame,
                );
            }

            PcapngBlock::Raw { .. } => {
                if prefix_end.is_some() {
                    suffix.push((record.offset, record.raw.len()));
                }
            }
        }
    }

    if in_section {
        sections.push(SectionScan {
            prefix: (
                section_start,
                prefix_end.unwrap_or(data.len()) - section_start,
            ),
            late_idbs,
            scan,
            suffix,
        });
    }

    Ok(sections)
}

/// Derive the default output path: `foo.pcap` becomes `foo.reordered.pcap`,
/// with the extension following the detected capture format.
fn default_output(input: &Path, format: CaptureFormat) -> PathBuf {
    let mut name = match input.file_stem() {
        Some(stem) => stem.to_os_string(),
        None => OsString::from("output"),
    };
    name.push(".reordered.");
    name.push(match format {
        CaptureFormat::Pcap => "pcap",
        CaptureFormat::Pcapng => "pcapng",
    });
    input.with_file_name(name)
}

/// Format a nanosecond timestamp as `seconds.nanoseconds`.
fn format_timestamp(ns: i64) -> String {
    format!(
        "{}.{:09}",
        ns.div_euclid(1_000_000_000),
        ns.rem_euclid(1_000_000_000)
    )
}

/// Write the reordered capture section by section: the prefix verbatim, then
/// every packet record in timestamp order, then any trailing non-packet
/// blocks — all copied byte-for-byte from the input.
fn write_reordered(data: &[u8], sections: &[SectionScan], output: &Path) -> anyhow::Result<()> {
    let file =
        File::create(output).with_context(|| format!("failed to create {}", output.display()))?;
    let mut writer = BufWriter::new(file);

    for section in sections {
        writer.write_all(&data[section.prefix.0..section.prefix.0 + section.prefix.1])?;
        for &(offset, len) in &section.late_idbs {
            writer.write_all(&data[offset..offset + len])?;
        }
        for entry in &section.scan.index {
            writer.write_all(&data[entry.offset..entry.offset + entry.record_len])?;
        }
        for &(offset, len) in &section.suffix {
            writer.write_all(&data[offset..offset + len])?;
        }
    }
    writer.flush()?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    let file = File::open(&cli.input)
        .with_context(|| format!("failed to open {}", cli.input.display()))?;
    // SAFETY: the file is opened read-only and treated as immutable for the
    // lifetime of the mapping.
    let mmap = unsafe { Mmap::map(&file)? };

    let format = SniffedSliceReader::new(&mmap[..])?.format();
    let mut sections = match format {
        CaptureFormat::Pcap => scan_pcap(&mmap[..])?,
        CaptureFormat::Pcapng => scan_pcapng(&mmap[..])?,
    };

    let output = cli
        .output
        .unwrap_or_else(|| default_output(&cli.input, format));

    let same_file = match (cli.input.canonicalize(), output.canonicalize()) {
        (Ok(input), Ok(output)) => input == output,
        _ => cli.input == output,
    };
    ensure!(
        !same_file,
        "output {} would overwrite the input file",
        output.display()
    );

    let total: usize = sections.iter().map(|s| s.scan.index.len()).sum();
    let misplaced_count: usize = sections.iter().map(|s| s.scan.misplaced.len()).sum();
    let ordered = misplaced_count == 0;
    println!(
        "{}: {} packets, {} out of order",
        cli.input.display(),
        total,
        misplaced_count
    );

    if cli.dry_run {
        let mut shown = 0;
        for m in sections
            .iter()
            .flat_map(|section| section.scan.misplaced.iter())
            .take(DRY_RUN_DETAIL_LIMIT)
        {
            println!(
                "frame #{}: ts {} is {} ns earlier than frame #{} (ts {})",
                m.frame,
                format_timestamp(m.timestamp),
                m.backward,
                m.latest_frame,
                format_timestamp(m.timestamp + m.backward),
            );
            shown += 1;
        }
        if misplaced_count > shown {
            println!("... and {} more", misplaced_count - shown);
        }
        return Ok(());
    }

    if ordered && cli.no_output {
        println!("input is already ordered, no output written");
        return Ok(());
    }

    // Stable sort keeps the original order of packets with equal timestamps.
    for section in &mut sections {
        section.scan.index.sort_by_key(|entry| entry.timestamp);
    }
    write_reordered(&mmap[..], &sections, &output)?;

    println!("wrote {} packets to {}", total, output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_name() {
        assert_eq!(
            default_output(Path::new("foo.pcap"), CaptureFormat::Pcap),
            Path::new("foo.reordered.pcap")
        );
        assert_eq!(
            default_output(Path::new("/tmp/foo.pcap"), CaptureFormat::Pcap),
            Path::new("/tmp/foo.reordered.pcap")
        );
        assert_eq!(
            default_output(Path::new("foo"), CaptureFormat::Pcap),
            Path::new("foo.reordered.pcap")
        );
        assert_eq!(
            default_output(Path::new("foo"), CaptureFormat::Pcapng),
            Path::new("foo.reordered.pcapng")
        );
        assert_eq!(
            default_output(Path::new("foo.cap"), CaptureFormat::Pcap),
            Path::new("foo.reordered.pcap")
        );
    }

    /// Little-endian Interface Description Block (Ethernet, snap len 1024).
    fn pcapng_idb() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&20u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // link type: Ethernet
        out.extend_from_slice(&0u16.to_le_bytes()); // reserved
        out.extend_from_slice(&1024u32.to_le_bytes()); // snap len
        out.extend_from_slice(&20u32.to_le_bytes());
        out
    }

    /// Little-endian Enhanced Packet Block with a 4-byte payload.
    fn pcapng_epb(interface_id: u32, timestamp_us: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let total = 8 + 20 + 4 + 4; // header + fixed fields + padded data + trailing
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&interface_id.to_le_bytes());
        out.extend_from_slice(&((timestamp_us >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&(timestamp_us as u32).to_le_bytes());
        out.extend_from_slice(&4u32.to_le_bytes()); // captured len
        out.extend_from_slice(&4u32.to_le_bytes()); // original len
        out.extend_from_slice(&[0u8; 4]); // packet data
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out
    }

    /// Build a little-endian pcapng section with one Ethernet interface and
    /// one 4-byte packet per given microsecond timestamp.
    fn pcapng_section(timestamps_us: &[u64]) -> Vec<u8> {
        let mut out = Vec::new();

        // Section Header Block
        out.extend_from_slice(&[0x0A, 0x0D, 0x0D, 0x0A]);
        out.extend_from_slice(&28u32.to_le_bytes());
        out.extend_from_slice(&[0x4D, 0x3C, 0x2B, 0x1A]); // little-endian magic
        out.extend_from_slice(&1u16.to_le_bytes()); // major version
        out.extend_from_slice(&0u16.to_le_bytes()); // minor version
        out.extend_from_slice(&(-1i64).to_le_bytes()); // section length
        out.extend_from_slice(&28u32.to_le_bytes());

        out.extend_from_slice(&pcapng_idb());

        for &ts in timestamps_us {
            out.extend_from_slice(&pcapng_epb(0, ts));
        }

        out
    }

    #[test]
    fn scan_pcapng_multi_section() {
        // Out of order within the section.
        let mut data = pcapng_section(&[200, 100]);
        // Ordered within itself, but its timestamps precede section 1's.
        data.extend_from_slice(&pcapng_section(&[50, 150]));

        let mut sections = scan_pcapng(&data).unwrap();
        assert_eq!(sections.len(), 2);

        // Misplacement is tracked per section: only frame #2 is out of
        // order, even though section 2's timestamps are all earlier than
        // section 1's.
        let misplaced: Vec<_> = sections
            .iter()
            .flat_map(|section| section.scan.misplaced.iter())
            .collect();
        assert_eq!(misplaced.len(), 1);
        assert_eq!(misplaced[0].frame, 2);

        // Sorting applies per section.
        for section in &mut sections {
            section.scan.index.sort_by_key(|entry| entry.timestamp);
        }
        let timestamps: Vec<i64> = sections[0]
            .scan
            .index
            .iter()
            .map(|entry| entry.timestamp)
            .collect();
        assert_eq!(timestamps, [100_000, 200_000]);
        let timestamps: Vec<i64> = sections[1]
            .scan
            .index
            .iter()
            .map(|entry| entry.timestamp)
            .collect();
        assert_eq!(timestamps, [50_000, 150_000]);
    }

    #[test]
    fn scan_pcapng_late_idb() {
        // One packet on interface 0, then a second interface is described,
        // then an earlier packet on interface 1.
        let mut data = pcapng_section(&[200]);
        data.extend_from_slice(&pcapng_idb());
        data.extend_from_slice(&pcapng_epb(1, 100));

        let sections = scan_pcapng(&data).unwrap();
        assert_eq!(sections.len(), 1);

        // The late IDB is hoisted after the prefix rather than rejected.
        assert_eq!(sections[0].late_idbs.len(), 1);
        assert_eq!(sections[0].scan.index.len(), 2);

        // The interface-1 packet is earlier than the interface-0 one.
        assert_eq!(sections[0].scan.misplaced.len(), 1);
        assert_eq!(sections[0].scan.misplaced[0].frame, 2);
    }
}
