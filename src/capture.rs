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

    /// A capture structure ends before its expected length.
    #[error("truncated {0}")]
    TruncatedCapture(&'static str),

    /// Missing Interface Description Block in Pcapng file.
    #[error("missing Interface Description Block in Pcapng file")]
    MissingPcapngInterfaceDescriptionBlock,

    /// Invalid Pcapng packet with wrong interface ID.
    #[error("invalid Pcapng packet with wrong interface ID: {0}")]
    InvalidPcapngPacketInterfaceId(u32),

    /// Invalid Pcapng block total length field.
    #[error("invalid Pcapng block total length: {0}")]
    InvalidPcapngBlockTotalLength(u32),

    /// A Pcapng block's trailing total length does not match the leading one.
    #[error("{0} block total length mismatch: {1} != {2}")]
    PcapngBlockTotalLengthMismatch(&'static str, u32, u32),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::Display)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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

/// # SniffedSliceReader: auto-detects the capture format over a byte slice
///
/// The zero-copy counterpart of [`SniffedReader`]. Records returned by the
/// inherent [`next_packet`](Self::next_packet) borrow from the input slice
/// with lifetime `'a` rather than from the reader itself, so they may be held
/// across subsequent reads.
#[derive(Debug)]
pub enum SniffedSliceReader<'a> {
    /// Reader for a classic pcap slice.
    Pcap(format::pcap::PcapSliceReader<'a>),
    /// Reader for a pcapng slice.
    Pcapng(format::pcapng::PcapngSliceReader<'a>),
}

impl<'a> SniffedSliceReader<'a> {
    /// Create a reader by sniffing the slice's magic bytes.
    pub fn new(data: &'a [u8]) -> Result<Self, CaptureError> {
        let magic: [u8; 4] = data
            .get(..4)
            .and_then(|magic| magic.try_into().ok())
            .ok_or(CaptureError::TruncatedCapture("capture file header"))?;

        match CaptureFormat::from_magic_bytes(magic)? {
            CaptureFormat::Pcap => Ok(Self::Pcap(format::pcap::PcapSliceReader::new(data)?)),
            CaptureFormat::Pcapng => {
                Ok(Self::Pcapng(format::pcapng::PcapngSliceReader::new(data)?))
            }
        }
    }

    /// Return the detected capture container format.
    pub fn format(&self) -> CaptureFormat {
        match self {
            Self::Pcap(_) => CaptureFormat::Pcap,
            Self::Pcapng(_) => CaptureFormat::Pcapng,
        }
    }

    /// Read the next packet record, borrowing directly from the input slice.
    ///
    /// Unlike the [`CaptureReader`] implementation, records returned by this
    /// inherent method are tied to the input slice's lifetime `'a` rather than
    /// to the borrow of the reader, so they may be held across later reads.
    pub fn next_packet(&mut self) -> Result<Option<packet::PacketRecord<'a>>, CaptureError> {
        match self {
            Self::Pcap(reader) => reader.next_packet(),
            Self::Pcapng(reader) => reader.next_packet(),
        }
    }

    /// Read the next packet record along with the offset and raw bytes of its
    /// source record.
    pub fn next_packet_with_offset(
        &mut self,
    ) -> Result<Option<packet::LocatedPacketRecord<'a>>, CaptureError> {
        match self {
            Self::Pcap(reader) => reader.next_packet_with_offset(),
            Self::Pcapng(reader) => reader.next_packet_with_offset(),
        }
    }
}

impl<'a> CaptureReader for SniffedSliceReader<'a> {
    fn interfaces(&self) -> Vec<interface::Interface> {
        match self {
            Self::Pcap(reader) => reader.interfaces(),
            Self::Pcapng(reader) => reader.interfaces(),
        }
    }

    fn next_packet(&mut self) -> Result<Option<packet::PacketRecord<'_>>, CaptureError> {
        self.next_packet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Little-endian, microsecond pcap capture with a single 4-byte packet.
    const PCAP_DATA: [u8; 44] = [
        0xd4, 0xc3, 0xb2, 0xa1, // magic: little-endian, microsecond
        0x02, 0x00, 0x04, 0x00, // version 2.4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
        0xff, 0xff, 0x00, 0x00, // snap_len: 65535
        0x01, 0x00, 0x00, 0x00, // link type: Ethernet
        0x01, 0x00, 0x00, 0x00, // ts_sec: 1
        0xf4, 0x01, 0x00, 0x00, // ts_usec: 500
        0x04, 0x00, 0x00, 0x00, // incl_len: 4
        0x04, 0x00, 0x00, 0x00, // orig_len: 4
        0x01, 0x02, 0x03, 0x04, // packet data
    ];

    /// Big-endian pcapng capture (SHB + IDB + one EPB).
    fn pcapng_data() -> Vec<u8> {
        const SHB: [u8; 28] = [
            0x0A, 0x0D, 0x0D, 0x0A, // Block Type: Section Header
            0x00, 0x00, 0x00, 0x1C, // Block Total Length: 28
            0x1A, 0x2B, 0x3C, 0x4D, // Byte-Order Magic: big-endian
            0x00, 0x01, // Major Version: 1
            0x00, 0x00, // Minor Version: 0
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Section Length: -1
            0x00, 0x00, 0x00, 0x1C, // Block Total Length: 28
        ];
        const IDB: [u8; 20] = [
            0x00, 0x00, 0x00, 0x01, // Block Type: Interface Description
            0x00, 0x00, 0x00, 0x14, // Block Total Length: 20
            0x00, 0x01, // LinkType: Ethernet (1)
            0x00, 0x00, // Reserved
            0x00, 0x00, 0x04, 0x00, // SnapLen: 1024
            0x00, 0x00, 0x00, 0x14, // Block Total Length: 20
        ];
        const EPB: [u8; 80] = [
            0x00, 0x00, 0x00, 0x06, // Block Type: Enhanced Packet
            0x00, 0x00, 0x00, 0x50, // Block Total Length: 80
            0x00, 0x00, 0x00, 0x00, // Interface ID: 0
            0x00, 0x03, 0x7C, 0x58, // Timestamp (High)
            0x75, 0xE1, 0x2A, 0x94, // Timestamp (Low)
            0x00, 0x00, 0x00, 0x2E, // Captured Len: 46
            0x00, 0x00, 0x00, 0x2E, // Original Len: 46
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Dst MAC
            0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, // Src MAC
            0x08, 0x00, // Ethertype: IPv4
            0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, // IPv4 header
            0x40, 0x11, 0x00, 0x00, 10, 0, 1, 1, 10, 0, 1, 2, //
            0x04, 0xd2, 0x04, 0xd3, 0x00, 0x0c, 0x00, 0x00, // UDP header
            0x01, 0x02, 0x03, 0x04, // Payload
            0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x50, // Block Total Length: 80
        ];

        let mut data = Vec::new();
        data.extend_from_slice(&SHB);
        data.extend_from_slice(&IDB);
        data.extend_from_slice(&EPB);
        data
    }

    #[test]
    fn sniffed_slice_reader() {
        let mut reader = SniffedSliceReader::new(&PCAP_DATA).unwrap();
        assert_eq!(reader.format(), CaptureFormat::Pcap);
        let located = reader.next_packet_with_offset().unwrap().unwrap();
        assert_eq!(located.offset, 24);
        assert_eq!(located.packet.timestamp, 1_000_000_000 + 500_000);
        assert_eq!(&located.packet.data[..], [1, 2, 3, 4].as_slice());
        assert!(reader.next_packet().unwrap().is_none());

        let pcapng = pcapng_data();
        let mut reader = SniffedSliceReader::new(&pcapng).unwrap();
        assert_eq!(reader.format(), CaptureFormat::Pcapng);
        let located = reader.next_packet_with_offset().unwrap().unwrap();
        assert_eq!(located.offset, 48);
        assert_eq!(located.packet.timestamp, 981144306789012000);
        assert!(reader.next_packet().unwrap().is_none());

        // Too short to sniff.
        assert!(SniffedSliceReader::new(&PCAP_DATA[..3]).is_err());
    }
}
