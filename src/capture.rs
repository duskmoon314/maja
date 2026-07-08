//! Capture file format detection and shared reader traits.
//!
//! The capture module exposes a common [`CaptureReader`](crate::capture::CaptureReader) trait
//! over classic pcap and pcapng readers. Packet bytes are returned as borrowed
//! [`PacketRecord`](crate::capture::packet::PacketRecord) values so callers can parse them
//! without copying.

use std::io::{Chain, Cursor, Read};

/// Endian-aware integer readers used by capture format parsers.
pub mod endian;
/// Concrete pcap and pcapng format implementations.
pub mod format;
/// Capture interface metadata such as link type, snap length, and timestamp resolution.
pub mod interface;
/// Capture link-layer type registry.
pub mod link_type;
/// Timestamped packet record shared by capture readers and writers.
pub mod packet;

/// Error returned while opening, reading, or writing capture files.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// I/O error from underlying reader/writer.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Convert from UTF-8 error.
    #[error("Parse UTF-8 error: {0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    /// Convert from slice error.
    #[error("TryFromSlice error: {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Invalid or unrecognized magic number in file header.
    #[error("invalid magic number: {0:#010X}")]
    InvalidMagicNumber(u32),

    /// Missing Interface Description Block in Pcapng file.
    #[error("missing Interface Description Block in Pcapng file")]
    MissingPcapngInterfaceDescriptionBlock,

    /// Invalid Pcapng packet with wrong interface ID.
    #[error("invalid Pcapng packet with wrong interface ID: {0}")]
    InvalidPcapngPacketInterfaceId(u32),
}

/// Common interface implemented by supported capture readers.
///
/// Readers expose their interface metadata and yield borrowed packet records
/// from the underlying input stream.
pub trait CaptureReader {
    /// Return interface metadata discovered in the capture.
    fn interfaces(&self) -> Vec<interface::Interface>;

    /// Read the next packet record, returning `Ok(None)` at end of input.
    fn next_packet(&mut self) -> Result<Option<packet::PacketRecord<'_>>, CaptureError>;
}

/// Capture container format detected from a file magic value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureFormat {
    /// Classic libpcap file format.
    Pcap,
    /// pcapng block-based file format.
    Pcapng,
}

impl CaptureFormat {
    /// Detect a capture format from the first four bytes of a file.
    pub fn from_magic_bytes(magic: [u8; 4]) -> Result<Self, CaptureError> {
        let magic_number = u32::from_be_bytes(magic);
        match magic_number {
            format::pcap::magic::BE_USEC
            | format::pcap::magic::BE_NSEC
            | format::pcap::magic::LE_USEC
            | format::pcap::magic::LE_NSEC => Ok(Self::Pcap),
            _ if format::pcapng::BlockType::from(magic_number)
                == format::pcapng::BlockType::SectionHeader =>
            {
                Ok(Self::Pcapng)
            }
            _ => Err(CaptureError::InvalidMagicNumber(magic_number)),
        }
    }
}

/// # SniffedReader: Auto detects the capture format
#[derive(Debug)]
pub enum SniffedReader<R: Read> {
    /// Reader for a classic pcap stream.
    Pcap(format::pcap::PcapReader<Chain<Cursor<[u8; 4]>, R>>),
    /// Reader for a pcapng stream.
    Pcapng(format::pcapng::PcapngReader<Chain<Cursor<[u8; 4]>, R>>),
}

impl<R: Read> SniffedReader<R> {
    /// Create a reader by sniffing the stream's magic bytes.
    ///
    /// The consumed magic bytes are chained back onto the reader before the
    /// concrete format parser is constructed.
    pub fn new(mut reader: R) -> Result<Self, CaptureError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        let reader = Cursor::new(magic).chain(reader);

        match CaptureFormat::from_magic_bytes(magic)? {
            CaptureFormat::Pcap => Ok(Self::Pcap(format::pcap::PcapReader::new(reader)?)),
            CaptureFormat::Pcapng => Ok(Self::Pcapng(format::pcapng::PcapngReader::new(reader)?)),
        }
    }

    /// Return the detected capture container format.
    pub fn format(&self) -> CaptureFormat {
        match self {
            Self::Pcap(_) => CaptureFormat::Pcap,
            Self::Pcapng(_) => CaptureFormat::Pcapng,
        }
    }
}

impl SniffedReader<std::fs::File> {
    /// Open a file and create a sniffed capture reader for it.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, CaptureError> {
        let file = std::fs::File::open(path)?;
        Self::new(file)
    }
}

impl<R: Read> CaptureReader for SniffedReader<R> {
    fn interfaces(&self) -> Vec<interface::Interface> {
        match self {
            Self::Pcap(reader) => reader.interfaces(),
            Self::Pcapng(reader) => reader.interfaces(),
        }
    }

    fn next_packet(&mut self) -> Result<Option<packet::PacketRecord<'_>>, CaptureError> {
        match self {
            Self::Pcap(reader) => reader.next_packet(),
            Self::Pcapng(reader) => reader.next_packet(),
        }
    }
}
