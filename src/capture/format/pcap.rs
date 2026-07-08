//! Classic PCAP format

use std::io::{BufReader, BufWriter, Read, Write};

use log::debug;

use crate::capture::{
    CaptureError, CaptureReader, interface::Interface, link_type::LinkType, packet::PacketRecord,
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
    /// Return the link-layer type stored in the lower 16 bits of the header.
    pub fn link_type(&self) -> LinkType {
        ((self.additional_info_link_type & 0xFFFF) as u16).into()
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

        let mut magic_bytes = [0u8; 4];
        reader.read_exact(&mut magic_bytes)?;
        let magic_number = u32::from_be_bytes(magic_bytes);

        let (big_endian, nanosecond) = match magic_number {
            magic::BE_USEC => (true, false),
            magic::BE_NSEC => (true, true),
            magic::LE_USEC => (false, false),
            magic::LE_NSEC => (false, true),
            _ => return Err(CaptureError::InvalidMagicNumber(magic_number)),
        };

        let mut buffer = [0u8; 20];
        reader.read_exact(&mut buffer)?;

        let header = if big_endian {
            PcapHeader {
                magic_number,
                major_version: u16::from_be_bytes([buffer[0], buffer[1]]),
                minor_version: u16::from_be_bytes([buffer[2], buffer[3]]),
                reserved_1: u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                reserved_2: u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                snap_len: u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
                additional_info_link_type: u32::from_be_bytes([
                    buffer[16], buffer[17], buffer[18], buffer[19],
                ]),
            }
        } else {
            PcapHeader {
                magic_number,
                major_version: u16::from_le_bytes([buffer[0], buffer[1]]),
                minor_version: u16::from_le_bytes([buffer[2], buffer[3]]),
                reserved_1: u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                reserved_2: u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                snap_len: u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
                additional_info_link_type: u32::from_le_bytes([
                    buffer[16], buffer[17], buffer[18], buffer[19],
                ]),
            }
        };

        Ok(Self {
            header,
            big_endian,
            nanosecond,
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
        let mut buffer = [0u8; 16];
        match self.reader.read_exact(&mut buffer) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let header = if self.big_endian {
            PcapPacketHeader {
                ts_sec: u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
                ts_usec: u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                incl_len: u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                orig_len: u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
            }
        } else {
            PcapPacketHeader {
                ts_sec: u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
                ts_usec: u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                incl_len: u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
                orig_len: u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
            }
        };

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
        vec![Interface {
            link_type: self.header.link_type(),
            snap_len: self.header.snap_len,
            resolution: if self.nanosecond {
                crate::capture::interface::Resolution::PowerOfTen(9)
            } else {
                crate::capture::interface::Resolution::PowerOfTen(6)
            },
        }]
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
}
