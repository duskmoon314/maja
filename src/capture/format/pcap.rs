//! Classic PCAP format

use std::io::{BufReader, BufWriter, Read, Write};

use log::debug;

use crate::capture::{
    CaptureError, CaptureReader, endian::Endian, interface::Interface, link_type::LinkType,
    packet::{LocatedPacketRecord, PacketRecord},
};

/// PCAP global header magic numbers.
///
/// The magic number determines both byte order and whether packet timestamp
/// fractions are stored as microseconds or nanoseconds.
pub mod magic {
    /// Big-endian, microsecond timestamps
    pub const BE_USEC: u32 = 0xA1B2C3D4;
    /// Big-endian, nanosecond timestamps  
    pub const BE_NSEC: u32 = 0xA1B23C4D;
    /// Little-endian, microsecond timestamps
    pub const LE_USEC: u32 = 0xD4C3B2A1;
    /// Little-endian, nanosecond timestamps
    pub const LE_NSEC: u32 = 0x4D3CB2A1;
}

/// # PCAP file header
///
/// ```text
///                        1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |                          Magic Number                         |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |         Major Version         |         Minor Version         |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                           Reserved1                           |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |                           Reserved2                           |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 |                            SnapLen                            |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 20 |               LinkType and additional information             |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcapHeader {
    /// Magic number
    pub magic_number: u32,
    /// Major version number (usually 2)
    pub major_version: u16,
    /// Minor version number (usually 4)
    pub minor_version: u16,
    /// Reserved field 1 (usually 0)
    ///
    /// This field was historically used as "gmt to local correction" or "time zone offset".
    ///
    /// In modern PCAP files, this field is typically set to 0
    pub reserved_1: u32,
    /// Reserved field 2 (usually 0)
    ///
    /// This field was historically used as "accuracy of timestamps"
    ///
    /// In modern PCAP files, this field is typically set to 0
    pub reserved_2: u32,
    /// The maximum length of captured packets.
    pub snap_len: u32,
    // /// Additional information
    // pub additional_info: u16,
    // /// Link type (data link type)
    // pub link_type: u16,
    /// Additional information and link type (data link type)
    pub additional_info_link_type: u32,
}

impl PcapHeader {
    /// Length in bytes of the serialized global header.
    pub const LEN: usize = 24;

    /// Parse a global header from the first [`LEN`](Self::LEN) bytes of `data`.
    ///
    /// The magic number selects byte order and timestamp precision; both are
    /// recoverable from the returned header via [`is_big_endian`](Self::is_big_endian)
    /// and [`is_nanosecond`](Self::is_nanosecond).
    pub fn parse(data: &[u8]) -> Result<Self, CaptureError> {
        if data.len() < Self::LEN {
            return Err(CaptureError::TruncatedCapture("pcap global header"));
        }

        let magic_number = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let endian = match magic_number {
            magic::BE_USEC | magic::BE_NSEC => Endian::Big,
            magic::LE_USEC | magic::LE_NSEC => Endian::Little,
            _ => return Err(CaptureError::InvalidMagicNumber(magic_number)),
        };

        Ok(Self {
            magic_number,
            major_version: endian.read_u16(&data[4..]),
            minor_version: endian.read_u16(&data[6..]),
            reserved_1: endian.read_u32(&data[8..]),
            reserved_2: endian.read_u32(&data[12..]),
            snap_len: endian.read_u32(&data[16..]),
            additional_info_link_type: endian.read_u32(&data[20..]),
        })
    }

    /// Return the link-layer type stored in the lower 16 bits of the header.
    pub fn link_type(&self) -> LinkType {
        ((self.additional_info_link_type & 0xFFFF) as u16).into()
    }

    /// Return the byte order used by multi-byte fields in this file.
    pub fn endian(&self) -> Endian {
        if self.is_big_endian() {
            Endian::Big
        } else {
            Endian::Little
        }
    }

    /// Build the interface metadata described by this global header.
    pub fn to_interface(&self) -> Interface {
        Interface {
            link_type: self.link_type(),
            snap_len: self.snap_len,
            resolution: if self.is_nanosecond() {
                crate::capture::interface::Resolution::PowerOfTen(9)
            } else {
                crate::capture::interface::Resolution::PowerOfTen(6)
            },
        }
    }

    /// Return whether multi-byte fields in this file use big-endian encoding.
    pub fn is_big_endian(&self) -> bool {
        matches!(self.magic_number, magic::BE_USEC | magic::BE_NSEC)
    }

    /// Return whether packet timestamp fractions are nanoseconds.
    ///
    /// When this returns `false`, timestamp fractions are microseconds.
    pub fn is_nanosecond(self) -> bool {
        matches!(self.magic_number, magic::BE_NSEC | magic::LE_NSEC)
    }
}

/// # PCAP packet header
///
/// ```text
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |                      Timestamp (Seconds)                      |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |            Timestamp (Microseconds or nanoseconds)            |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                    Captured Packet Length                     |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |                    Original Packet Length                     |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcapPacketHeader {
    /// Timestamp (seconds)
    pub ts_sec: u32,
    /// Timestamp (microseconds or nanoseconds)
    pub ts_usec: u32,
    /// Captured packet length
    pub incl_len: u32,
    /// Original packet length
    pub orig_len: u32,
}

impl PcapPacketHeader {
    /// Length in bytes of the serialized packet header.
    pub const LEN: usize = 16;

    /// Parse a packet header from the first [`LEN`](Self::LEN) bytes of `data`
    /// using the capture's byte order.
    ///
    /// Callers must ensure `data` holds at least [`LEN`](Self::LEN) bytes.
    pub fn parse(data: &[u8], endian: Endian) -> Self {
        Self {
            ts_sec: endian.read_u32(&data[0..]),
            ts_usec: endian.read_u32(&data[4..]),
            incl_len: endian.read_u32(&data[8..]),
            orig_len: endian.read_u32(&data[12..]),
        }
    }

    /// Convert to universal Packet representation
    pub fn to_packet<'a>(
        &self,
        data: &'a [u8],
        // The capture's timestamp precision (microsecond or nanosecond)
        nanosecond: bool,
        link_type: LinkType,
    ) -> crate::capture::packet::PacketRecord<'a> {
        let ts_nsec = if nanosecond {
            self.ts_usec
        } else {
            self.ts_usec * 1000
        };
        let timestamp = (self.ts_sec as i64) * 1_000_000_000 + (ts_nsec as i64);

        crate::capture::packet::PacketRecord::new(timestamp, self.orig_len, data, link_type)
    }
}

impl PartialOrd for PcapPacketHeader {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PcapPacketHeader {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ts_sec
            .cmp(&other.ts_sec)
            .then(self.ts_usec.cmp(&other.ts_usec))
    }
}

#[derive(Debug)]
/// Streaming reader for classic PCAP files.
///
/// The reader owns an internal packet buffer and returns borrowed packet bytes
/// from that buffer. A later read invalidates the previous borrow, matching the
/// usual streaming-capture workflow.
pub struct PcapReader<R: Read> {
    /// The global header
    pub header: PcapHeader,

    /// Whether the file is big-endian
    pub big_endian: bool,

    /// Whether the timestamps are in nanosecond precision
    pub nanosecond: bool,

    /// The underlying reader
    reader: BufReader<R>,

    /// The internal buffer for reading packets
    buffer: Vec<u8>,
}

impl<R: Read> PcapReader<R> {
    /// Create a PCAP reader and parse the global header.
    ///
    /// The global header selects byte order, timestamp precision, snapshot
    /// length, and link type. Packet records are read lazily by
    /// [`read_packet_raw`](PcapReader::read_packet_raw) or the
    /// [`CaptureReader`] implementation.
    pub fn new(reader: R) -> Result<Self, CaptureError> {
        let mut reader = BufReader::new(reader);

        let mut buffer = [0u8; PcapHeader::LEN];
        reader.read_exact(&mut buffer)?;
        let header = PcapHeader::parse(&buffer)?;

        Ok(Self {
            big_endian: header.is_big_endian(),
            nanosecond: header.is_nanosecond(),
            header,
            reader,
            buffer: Vec::new(),
        })
    }

    /// Read the next raw PCAP packet record.
    ///
    /// Returns `Ok(None)` at end of file. The returned byte slice borrows the
    /// reader's internal buffer and is valid until the next read from this
    /// reader.
    pub fn read_packet_raw(&mut self) -> Result<Option<(PcapPacketHeader, &[u8])>, CaptureError> {
        let mut buffer = [0u8; PcapPacketHeader::LEN];
        match self.reader.read_exact(&mut buffer) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let endian = self.header.endian();
        let header = PcapPacketHeader::parse(&buffer, endian);

        if header.incl_len > self.header.snap_len {
            debug!(
                "packet's incl_len {} > snap_len {}",
                header.incl_len, self.header.snap_len
            );
        }

        // Read the packet data into the internal buffer
        self.buffer.resize(header.incl_len as usize, 0);
        self.reader.read_exact(&mut self.buffer)?;

        Ok(Some((header, &self.buffer[..header.incl_len as usize])))
    }
}

impl<R: Read> CaptureReader for PcapReader<R> {
    fn interfaces(&self) -> Vec<crate::capture::interface::Interface> {
        vec![self.header.to_interface()]
    }

    fn next_packet(
        &mut self,
    ) -> Result<Option<crate::capture::packet::PacketRecord<'_>>, CaptureError> {
        let nanosecond = self.nanosecond;
        let link_type = self.header.link_type();
        match self.read_packet_raw()? {
            Some((header, data)) => {
                let packet = header.to_packet(data, nanosecond, link_type);
                Ok(Some(packet))
            }
            None => Ok(None),
        }
    }
}

/// A raw packet record as stored in the capture: its byte offset, parsed
/// packet header, and borrowed packet data.
#[derive(Debug)]
pub struct PcapPacketRecord<'a> {
    /// Byte offset of the record header in the input slice
    pub offset: usize,

    /// Parsed packet record header
    pub header: PcapPacketHeader,

    /// Captured packet bytes borrowing from the input slice
    pub data: &'a [u8],
}

/// # Zero-copy PCAP reader over a byte slice
///
/// `PcapSliceReader` parses a classic PCAP capture held entirely in memory —
/// typically an `mmap`-backed slice — without copying packet bytes. Records
/// returned by the inherent [`next_packet`](Self::next_packet) borrow from the
/// input slice with lifetime `'a` rather than from the reader itself, so they
/// can be held across subsequent reads, collected, and sorted freely.
///
/// The reader also tracks the byte offset of every record, enabling
/// index-then-copy workflows such as reordering packets by timestamp with
/// memory bounded by the packet count rather than the capture size.
#[derive(Debug)]
pub struct PcapSliceReader<'a> {
    /// The global header
    pub header: PcapHeader,

    /// The underlying capture bytes
    data: &'a [u8],

    /// Offset of the next packet record
    pos: usize,
}

impl<'a> PcapSliceReader<'a> {
    /// Create a reader over a complete in-memory PCAP capture, parsing the
    /// global header.
    pub fn new(data: &'a [u8]) -> Result<Self, CaptureError> {
        let header = PcapHeader::parse(data)?;
        Ok(Self {
            header,
            data,
            pos: PcapHeader::LEN,
        })
    }

    /// Return the byte offset at which the next packet record starts.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read the next raw PCAP packet record.
    ///
    /// Returns `Ok(None)` when the slice is exhausted. The offset is the byte
    /// position of the record header within the original slice; the record
    /// (header plus data) spans `offset..offset + 16 + incl_len`.
    pub fn read_packet_raw(&mut self) -> Result<Option<PcapPacketRecord<'a>>, CaptureError> {
        let remaining = &self.data[self.pos..];
        if remaining.is_empty() {
            return Ok(None);
        }
        if remaining.len() < PcapPacketHeader::LEN {
            return Err(CaptureError::TruncatedCapture("pcap packet header"));
        }

        let offset = self.pos;
        let header = PcapPacketHeader::parse(remaining, self.header.endian());

        if header.incl_len > self.header.snap_len {
            debug!(
                "packet's incl_len {} > snap_len {}",
                header.incl_len, self.header.snap_len
            );
        }

        let data_start = self.pos + PcapPacketHeader::LEN;
        let data_end = data_start + header.incl_len as usize;
        if data_end > self.data.len() {
            return Err(CaptureError::TruncatedCapture("pcap packet data"));
        }
        self.pos = data_end;

        Ok(Some(PcapPacketRecord {
            offset,
            header,
            data: &self.data[data_start..data_end],
        }))
    }

    /// Read the next packet record, borrowing directly from the input slice.
    ///
    /// Unlike the [`CaptureReader`] implementation, records returned by this
    /// inherent method are tied to the input slice's lifetime `'a` rather than
    /// to the borrow of the reader, so they may be held across later reads.
    pub fn next_packet(&mut self) -> Result<Option<PacketRecord<'a>>, CaptureError> {
        match self.read_packet_raw()? {
            Some(PcapPacketRecord { header, data, .. }) => Ok(Some(header.to_packet(
                data,
                self.header.is_nanosecond(),
                self.header.link_type(),
            ))),
            None => Ok(None),
        }
    }

    /// Read the next packet record along with the offset and raw bytes of its
    /// source record.
    pub fn next_packet_with_offset(
        &mut self,
    ) -> Result<Option<LocatedPacketRecord<'a>>, CaptureError> {
        match self.read_packet_raw()? {
            Some(PcapPacketRecord {
                offset,
                header,
                data,
            }) => Ok(Some(LocatedPacketRecord {
                offset,
                raw: &self.data[offset..offset + PcapPacketHeader::LEN + data.len()],
                packet: header.to_packet(
                    data,
                    self.header.is_nanosecond(),
                    self.header.link_type(),
                ),
            })),
            None => Ok(None),
        }
    }
}

impl<'a> CaptureReader for PcapSliceReader<'a> {
    fn interfaces(&self) -> Vec<Interface> {
        vec![self.header.to_interface()]
    }

    fn next_packet(&mut self) -> Result<Option<PacketRecord<'_>>, CaptureError> {
        PcapSliceReader::next_packet(self)
    }
}

/// # PCAP writer
#[derive(Debug)]
pub struct PcapWriter<W: Write> {
    /// The PCAP header
    pub header: PcapHeader,

    /// Whether to write in big-endian format
    pub big_endian: bool,

    /// Whether to write timestamps in nanosecond precision
    pub nanosecond: bool,

    /// The underlying writer
    writer: BufWriter<W>,
}

impl<W: Write> PcapWriter<W> {
    /// Create a PCAP writer and immediately write the global header.
    ///
    /// `big_endian` controls the byte order used for subsequent numeric
    /// fields. `nanosecond` selects whether packet timestamp fractions are
    /// written as nanoseconds (`true`) or microseconds (`false`).
    pub fn new(
        writer: W,
        big_endian: bool,
        nanosecond: bool,
        snap_len: u32,
        link_type: LinkType,
    ) -> Result<Self, CaptureError> {
        let mut writer = BufWriter::new(writer);

        let magic_number = match (big_endian, nanosecond) {
            (true, false) => magic::BE_USEC,
            (true, true) => magic::BE_NSEC,
            (false, false) => magic::LE_USEC,
            (false, true) => magic::LE_NSEC,
        };

        let link_type: u16 = link_type.into();

        let header = PcapHeader {
            magic_number,
            major_version: 2,
            minor_version: 4,
            reserved_1: 0,
            reserved_2: 0,
            snap_len,
            additional_info_link_type: link_type as u32,
        };

        // Write the header
        writer.write_all(&magic_number.to_be_bytes())?;
        if big_endian {
            writer.write_all(&header.major_version.to_be_bytes())?;
            writer.write_all(&header.minor_version.to_be_bytes())?;
            writer.write_all(&header.reserved_1.to_be_bytes())?;
            writer.write_all(&header.reserved_2.to_be_bytes())?;
            writer.write_all(&header.snap_len.to_be_bytes())?;
            writer.write_all(&header.additional_info_link_type.to_be_bytes())?;
        } else {
            writer.write_all(&header.major_version.to_le_bytes())?;
            writer.write_all(&header.minor_version.to_le_bytes())?;
            writer.write_all(&header.reserved_1.to_le_bytes())?;
            writer.write_all(&header.reserved_2.to_le_bytes())?;
            writer.write_all(&header.snap_len.to_le_bytes())?;
            writer.write_all(&header.additional_info_link_type.to_le_bytes())?;
        }

        Ok(Self {
            header,
            big_endian,
            nanosecond,
            writer,
        })
    }

    /// Write a packet using raw header and data.
    pub fn write_packet_raw<T: AsRef<[u8]>>(
        &mut self,
        header: PcapPacketHeader,
        data: T,
    ) -> Result<(), CaptureError> {
        let data = data.as_ref();
        let incl_len = [header.incl_len, self.header.snap_len, data.len() as u32]
            .into_iter()
            .min()
            .unwrap(); // This should never panic as the iterator is non-empty

        if self.big_endian {
            self.writer.write_all(&header.ts_sec.to_be_bytes())?;
            self.writer.write_all(&header.ts_usec.to_be_bytes())?;
            self.writer.write_all(&incl_len.to_be_bytes())?;
            self.writer.write_all(&header.orig_len.to_be_bytes())?;
        } else {
            self.writer.write_all(&header.ts_sec.to_le_bytes())?;
            self.writer.write_all(&header.ts_usec.to_le_bytes())?;
            self.writer.write_all(&incl_len.to_le_bytes())?;
            self.writer.write_all(&header.orig_len.to_le_bytes())?;
        }

        self.writer.write_all(&data[..incl_len as usize])?;

        Ok(())
    }

    /// Write a PacketRecord to the PCAP file.
    pub fn write_packet(&mut self, packet: &PacketRecord) -> Result<(), CaptureError> {
        let ts_sec = (packet.timestamp / 1_000_000_000) as u32;
        let ts_nsec = (packet.timestamp % 1_000_000_000) as u32;
        let ts_usec = if self.nanosecond {
            ts_nsec
        } else {
            ts_nsec / 1000
        };

        let header = PcapPacketHeader {
            ts_sec,
            ts_usec,
            incl_len: packet.data.len() as u32,
            orig_len: packet.original_length,
        };

        self.write_packet_raw(header, &packet.data)
    }

    /// Flush any buffered PCAP bytes to the underlying writer.
    pub fn flush(&mut self) -> Result<(), CaptureError> {
        self.writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_writer() {
        let mut buffer = Vec::new();

        {
            let mut writer = PcapWriter::new(
                &mut buffer,
                true,  // big_endian
                false, // nanosecond
                65535, // snap_len
                LinkType::Ethernet,
            )
            .unwrap();

            let header = PcapPacketHeader {
                ts_sec: 1136142245, // 2006-01-02 03:04:05
                ts_usec: 123456,
                incl_len: 4,
                orig_len: 4,
            };

            writer.write_packet_raw(header, &[1, 2, 3, 4]).unwrap();
        }

        assert_eq!(
            buffer,
            vec![
                0xA1, 0xB2, 0xC3, 0xD4, // magic number
                0x00, 0x02, // major version
                0x00, 0x04, // minor version
                0x00, 0x00, 0x00, 0x00, // reserved1
                0x00, 0x00, 0x00, 0x00, // reserved2
                0x00, 0x00, 0xff, 0xff, // snap_len
                0x00, 0x00, // additional_info
                0x00, 0x01, // link_type (Ethernet)
                // Packet header
                0x43, 0xb8, 0x27, 0xa5, // ts_sec
                0x00, 0x01, 0xe2, 0x40, // ts_usec
                0x00, 0x00, 0x00, 0x04, // incl_len
                0x00, 0x00, 0x00, 0x04, // orig_len
                // Packet data
                1, 2, 3, 4,
            ]
        );
    }

    #[test]
    fn pcap_slice_reader() {
        use std::borrow::Cow;

        // Build a little-endian, microsecond capture in memory.
        let mut buffer = Vec::new();
        {
            let mut writer = PcapWriter::new(
                &mut buffer,
                false, // big_endian
                false, // nanosecond
                65535, // snap_len
                LinkType::Ethernet,
            )
            .unwrap();

            writer
                .write_packet_raw(
                    PcapPacketHeader {
                        ts_sec: 1,
                        ts_usec: 500,
                        incl_len: 4,
                        orig_len: 4,
                    },
                    [1, 2, 3, 4],
                )
                .unwrap();
            writer
                .write_packet_raw(
                    PcapPacketHeader {
                        ts_sec: 2,
                        ts_usec: 250_000,
                        incl_len: 2,
                        orig_len: 4,
                    },
                    [5, 6],
                )
                .unwrap();
        }

        let mut reader = PcapSliceReader::new(&buffer).unwrap();
        assert_eq!(reader.header.link_type(), LinkType::Ethernet);
        assert_eq!(reader.position(), PcapHeader::LEN);

        // Records borrow from the input slice and can be held across reads.
        let first = reader.next_packet_with_offset().unwrap().unwrap();
        let second = reader.next_packet_with_offset().unwrap().unwrap();

        assert!(matches!(first.packet.data, Cow::Borrowed(_)));
        assert_eq!(first.offset, PcapHeader::LEN);
        assert_eq!(first.raw.len(), PcapPacketHeader::LEN + 4);
        assert_eq!(
            first.raw,
            &buffer[first.offset..first.offset + first.raw.len()]
        );
        assert_eq!(second.offset, PcapHeader::LEN + PcapPacketHeader::LEN + 4);
        assert_eq!(first.packet.timestamp, 1_000_000_000 + 500_000);
        assert_eq!(&first.packet.data[..], [1, 2, 3, 4].as_slice());
        assert_eq!(second.packet.timestamp, 2_000_000_000 + 250_000_000);
        assert_eq!(&second.packet.data[..], [5, 6].as_slice());
        assert!(second.packet.is_truncated());
        assert!(reader.next_packet().unwrap().is_none());

        // Generic code can still use the CaptureReader trait.
        let mut reader = PcapSliceReader::new(&buffer).unwrap();
        assert_eq!(CaptureReader::interfaces(&reader).len(), 1);
        assert!(CaptureReader::next_packet(&mut reader).unwrap().is_some());

        // Truncated captures are reported as errors.
        let mut reader = PcapSliceReader::new(&buffer[..buffer.len() - 1]).unwrap();
        reader.next_packet().unwrap();
        assert!(reader.next_packet().is_err());
    }

    /// A nanosecond-precision capture holding two packets.
    fn two_packet_capture() -> Vec<u8> {
        let mut buffer = Vec::new();
        {
            let mut writer =
                PcapWriter::new(&mut buffer, false, true, 65535, LinkType::Ethernet).unwrap();
            writer
                .write_packet_raw(
                    PcapPacketHeader {
                        ts_sec: 1,
                        ts_usec: 500,
                        incl_len: 4,
                        orig_len: 4,
                    },
                    [1, 2, 3, 4],
                )
                .unwrap();
            writer
                .write_packet_raw(
                    PcapPacketHeader {
                        ts_sec: 2,
                        ts_usec: 250_000_000,
                        incl_len: 2,
                        orig_len: 4,
                    },
                    [5, 6],
                )
                .unwrap();
        }
        buffer
    }

    #[test]
    fn pcap_slice_reader_matches_streaming_reader() {
        let buffer = two_packet_capture();

        let mut streaming = PcapReader::new(buffer.as_slice()).unwrap();
        let mut streamed = Vec::new();
        while let Some(record) = streaming.next_packet().unwrap() {
            streamed.push(record.to_owned());
        }

        let mut slice = PcapSliceReader::new(&buffer).unwrap();
        let mut sliced = Vec::new();
        while let Some(record) = slice.next_packet().unwrap() {
            sliced.push(record);
        }

        assert_eq!(streamed, sliced);
    }

    #[test]
    fn pcap_slice_reader_survives_truncation() {
        let buffer = two_packet_capture();

        // Every prefix must yield either clean results or an error, never a
        // panic.
        for len in 0..=buffer.len() {
            if let Ok(mut reader) = PcapSliceReader::new(&buffer[..len]) {
                while let Ok(Some(_)) = reader.next_packet() {}
            }
        }
    }
}
