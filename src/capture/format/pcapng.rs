//! PCAPNG format.

use std::{
    borrow::Cow,
    io::{BufReader, Read},
    net::{Ipv4Addr, Ipv6Addr},
    ops::Deref,
};

use log::{debug, error, trace};
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::{
    capture::{
        CaptureError, CaptureReader,
        endian::Endian,
        interface::{self, Interface},
        link_type::LinkType,
        packet::PacketRecord,
    },
    packet::layer::eth::EthAddr,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[repr(u32)]
/// PCAPNG block type codes.
///
/// These values identify the top-level block following each block type field.
/// Unknown values are preserved as [`Unknown`](BlockType::Unknown) so callers can keep
/// or inspect unsupported blocks.
pub enum BlockType {
    /// Section Header Block (`SHB`), which starts a section and defines byte order.
    SectionHeader = 0x0A0D0D0A,

    /// Interface Description Block (`IDB`), which describes one capture interface.
    InterfaceDescription = 0x00000001,

    /// Simple Packet Block (`SPB`), which stores packet data for interface 0.
    SimplePacket = 0x00000003,

    /// Name Resolution Block (`NRB`), which stores address/name mappings.
    NameResolution = 0x00000004,

    /// Interface Statistics Block (`ISB`), which stores per-interface counters.
    InterfaceStatistics = 0x00000005,

    /// Enhanced Packet Block (`EPB`), the normal timestamped packet record.
    EnhancedPacket = 0x00000006,

    /// Decryption Secrets Block (`DSB`), used by tools to store TLS or similar secrets.
    DecryptionSecrets = 0x0000000A,

    /// Custom Block whose contents may be copied by tools that do not understand it.
    CustomCopyable = 0x00000BAD,

    /// Custom Block whose contents should not be copied by unaware tools.
    CustomNonCopyable = 0x40000BAD,

    /// Unsupported or vendor-specific block type code.
    #[num_enum(catch_all)]
    Unknown(u32),
}

/// PCAPNG option code constants grouped by block family.
///
/// Options use a common type/length/value encoding, but each block family
/// defines its own option number space. These constants keep parsing logic
/// readable without exposing a large enum for every option family.
pub mod option_type {
    /// Delimits the end of the optional fields.
    pub const END_OF_OPT: u16 = 0;

    /// A UTF-8 string containing human-readable comment text.
    pub const COMMENT: u16 = 1;

    /* ===== SHB ===== */

    /// A UTF-8 string containing the description of the hardware used to create this section.
    pub const SHB_HARDWARE: u16 = 2;

    /// A UTF-8 string containing the name of the operating system used to create this section.
    pub const SHB_OS: u16 = 3;

    /// A UTF-8 string containing the name of the application used to create this section.
    pub const SHB_USER_APPL: u16 = 4;

    /* ===== IDB ===== */

    /// A UTF-8 string containing the name of the device used to capture data.
    pub const IF_NAME: u16 = 2;

    /// A UTF-8 string containing a description of the device used to capture data.
    pub const IF_DESCRIPTION: u16 = 3;

    /// Interface IPv4 address and netmask (`if_IPv4addr`).
    pub const IF_IPV4_ADDR: u16 = 4;

    /// Interface IPv6 address and prefix length (`if_IPv6addr`).
    pub const IF_IPV6_ADDR: u16 = 5;

    /// Interface IEEE 802 MAC address (`if_MACaddr`).
    pub const IF_MAC_ADDR: u16 = 6;

    /// Interface EUI address (`if_EUIaddr`).
    pub const IF_EUI_ADDR: u16 = 7;

    /// Interface speed in bits per second (`if_speed`).
    pub const IF_SPEED: u16 = 8;

    /// Interface timestamp resolution (`if_tsresol`).
    pub const IF_TSRESOL: u16 = 9;

    /// Deprecated interface time zone option (`if_tzone`).
    pub const IF_TZONE: u16 = 10;

    /// Capture filter expression associated with the interface (`if_filter`).
    pub const IF_FILTER: u16 = 11;

    /// Operating system of the machine hosting the interface (`if_os`).
    pub const IF_OS: u16 = 12;

    /// Link-layer frame check sequence length in bits (`if_fcslen`).
    pub const IF_FCSLEN: u16 = 13;

    /// Timestamp offset from UTC in seconds (`if_tsoffset`).
    pub const IF_TSOFFSET: u16 = 14;

    /// Interface hardware description (`if_hardware`).
    pub const IF_HARDWARE: u16 = 15;

    /// Interface transmit speed in bits per second (`if_txspeed`).
    pub const IF_TXSPEED: u16 = 16;

    /// Interface receive speed in bits per second (`if_rxspeed`).
    pub const IF_RXSPEED: u16 = 17;

    /// IANA time zone name for timestamps on this interface (`if_iana_tzname`).
    pub const IF_IANA_TZNAME: u16 = 18;

    /* ===== EPB ===== */

    /// Enhanced Packet Block packet flags (`epb_flags`).
    pub const EPB_FLAGS: u16 = 2;

    /// Enhanced Packet Block packet hash (`epb_hash`).
    pub const EPB_HASH: u16 = 3;

    /// Enhanced Packet Block drop count (`epb_dropcount`).
    pub const EPB_DROPCOUNT: u16 = 4;

    /// Enhanced Packet Block packet identifier (`epb_packetid`).
    pub const EPB_PACKET_ID: u16 = 5;

    /// Enhanced Packet Block queue identifier (`epb_queue`).
    pub const EPB_QUEUE: u16 = 6;

    /// Enhanced Packet Block packet verdict (`epb_verdict`).
    pub const EPB_VERDICT: u16 = 7;

    /// Enhanced Packet Block process and thread identifiers.
    pub const EPB_PROCESSID_THREADID: u16 = 8;

    /* ===== NS ===== */

    /// Name Resolution Block DNS name record.
    pub const NS_DNS_NAME: u16 = 2;

    /// Name Resolution Block IPv4 address record.
    pub const NS_DNS_IPV4_ADDR: u16 = 3;

    /// Name Resolution Block IPv6 address record.
    pub const NS_DNS_IPV6_ADDR: u16 = 4;

    /* ===== ISB ===== */

    /// Interface Statistics Block start time.
    pub const ISB_START_TIME: u16 = 2;

    /// Interface Statistics Block end time.
    pub const ISB_END_TIME: u16 = 3;

    /// Number of packets received from the interface.
    pub const ISB_IF_RECEIVE: u16 = 4;

    /// Number of packets dropped by the interface.
    pub const ISB_IF_DROP: u16 = 5;

    /// Number of packets accepted by the capture filter.
    pub const ISB_FILTER_ACCEPT: u16 = 6;

    /// Number of packets dropped by the operating system.
    pub const ISB_OS_DROP: u16 = 7;

    /// Number of packets delivered to the user-space capture application.
    pub const ISB_USR_DELIVER: u16 = 8;
}

/// # Section Header Block (SHB)
#[derive(Debug, Default, Clone)]
pub struct SectionHeader {
    /// Determines the byte order from the magic number.
    pub endian: Endian,

    /// Major version.
    pub major_version: u16,

    /// Minor version.
    pub minor_version: u16,

    /// Section length, or -1 if unspecified.
    pub section_length: i64,

    /// Optional hardware description from the `shb_hardware` option.
    pub hardware: Option<String>,

    /// Optional operating system description from the `shb_os` option.
    pub os: Option<String>,

    /// Optional application name from the `shb_userappl` option.
    pub user_appl: Option<String>,
}

/// # Interface Description Block (IDB)
#[derive(Debug, Default, Clone)]
pub struct InterfaceDescription {
    /// Link-layer type for packets captured on this interface.
    pub link_type: LinkType,

    /// Maximum number of octets captured from each packet on this interface.
    pub snap_len: u32,

    /// Optional capture device name.
    pub name: Option<String>,

    /// Optional human-readable interface description.
    pub description: Option<String>,

    /// IPv4 addresses and netmasks assigned to this interface.
    pub ipv4_addr: Vec<(Ipv4Addr, Ipv4Addr)>,

    /// IPv6 addresses and prefix lengths assigned to this interface.
    pub ipv6_addr: Vec<(Ipv6Addr, u8)>,

    /// Optional IEEE 802 MAC address for this interface.
    pub mac_addr: Option<EthAddr>,

    /// Optional EUI-64 style address for this interface.
    pub eui_addr: Option<[u8; 8]>,

    /// Optional interface speed in bits per second.
    pub speed: Option<u64>,

    /// Optional timestamp resolution byte as stored by PCAPNG.
    pub tsresol: Option<u8>,

    /// Should not be used.
    pub tzone: Option<i32>,

    /// Raw capture filter option bytes.
    pub filter: Vec<u8>,

    /// Optional operating system description for this interface.
    pub os: Option<String>,

    /// Optional frame check sequence length in bits.
    pub fcs_len: Option<u8>,

    /// Optional timestamp offset from UTC in seconds.
    pub tsoffset: Option<i64>,

    /// Optional interface hardware description.
    pub hardware: Option<String>,

    /// Optional transmit speed in bits per second.
    pub txspeed: Option<u64>,

    /// Optional receive speed in bits per second.
    pub rxspeed: Option<u64>,

    /// Optional IANA time zone name associated with interface timestamps.
    pub iana_tzname: Option<String>,
}

impl InterfaceDescription {
    /// Create an interface description with the required link type and snapshot length.
    pub fn new(link_type: LinkType, snap_len: u32) -> Self {
        Self {
            link_type,
            snap_len,
            ..Default::default()
        }
    }

    fn to_interface(&self) -> Interface {
        Interface {
            link_type: self.link_type,
            snap_len: self.snap_len,
            resolution: match self.tsresol.unwrap_or(6) {
                res @ 0..128 => interface::Resolution::PowerOfTen(res),
                res => interface::Resolution::PowerOfTwo(res ^ 0x80),
            },
        }
    }
}

#[derive(Debug, Clone)]
/// Header fields from a Simple Packet Block.
pub struct SimplePacketHeader {
    /// Original packet length before capture truncation.
    pub original_len: u32,
}

impl SimplePacketHeader {
    /// Convert this header and packet bytes into a common packet record.
    ///
    /// Simple Packet Blocks do not carry timestamps and are defined relative to
    /// the first interface in the PCAPNG section, so the returned timestamp is
    /// zero and the link type comes from `interface`.
    pub fn into_packet_record<'a>(
        self,
        interface: &InterfaceDescription,
        data: &'a [u8],
    ) -> PacketRecord<'a> {
        PacketRecord {
            timestamp: 0,
            original_length: self.original_len,
            data: Cow::Borrowed(data),
            link_type: interface.link_type,
        }
    }
}

/// # Simple Packet Block (SPB)
///
/// As draft-ietf-opsawg-pcapng describes, SPB should always be related to the
/// first interface in the file.
///
/// ## Block layout
///
/// ```text
///                         1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |                    Block Type = 0x00000003                    |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                    Original Packet Length                     |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 /                                                               /
///    /                          Packet Data                          /
///    /              variable length, padded to 32 bits               /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct SimplePacket<'a> {
    /// Parsed Simple Packet Block header.
    pub header: SimplePacketHeader,

    /// Captured packet bytes stored in the block.
    pub packet_data: Cow<'a, [u8]>,
}

impl Deref for SimplePacket<'_> {
    type Target = SimplePacketHeader;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

#[derive(Debug, Default, Clone)]
/// Header fields and parsed options from an Enhanced Packet Block.
pub struct EnhancedPacketHeaderOptions {
    /// Interface index this packet was captured on.
    pub interface_id: u32,

    /// Upper 32 bits of the raw timestamp counter.
    pub timestamp_high: u32,

    /// Lower 32 bits of the raw timestamp counter.
    pub timestamp_low: u32,

    /// Number of packet octets stored in this block.
    pub captured_len: u32,

    /// Original packet length before capture truncation.
    pub original_len: u32,

    /// Optional packet flags value.
    pub flags: Option<u32>,

    /// Optional packet hash values.
    pub hash: Vec<Vec<u8>>,

    /// Optional cumulative drop count before this packet.
    pub drop_count: Option<u64>,

    /// Optional packet identifier.
    pub packet_id: Option<u64>,

    /// Optional receive queue identifier.
    pub queue: Option<u32>,

    /// Optional packet verdict values.
    pub verdict: Vec<Vec<u8>>,

    /// Optional process and thread identifiers associated with the packet.
    pub processid_threadid: Option<(u32, u32)>,
}

/// # Enhanced Packet Block (EPB)
///
/// ## Block layout
///
/// ```text
///                         1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |                    Block Type = 0x00000006                    |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                         Interface ID                          |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |                       (Upper 32 bits)                         |
///    + - - - - - - - - - - - -  Timestamp  - - - - - - - - - - - - - +
/// 16 |                       (Lower 32 bits)                         |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 20 |                    Captured Packet Length                     |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 24 |                    Original Packet Length                     |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 28 /                                                               /
///    /                          Packet Data                          /
///    /              variable length, padded to 32 bits               /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    /                                                               /
///    /                      Options (variable)                       /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Default, Clone)]
pub struct EnhancedPacket<'a> {
    /// Parsed Enhanced Packet Block header fields and options.
    pub header_options: EnhancedPacketHeaderOptions,

    /// Captured packet bytes stored in the block.
    pub packet_data: Cow<'a, [u8]>,
}

impl Deref for EnhancedPacket<'_> {
    type Target = EnhancedPacketHeaderOptions;

    fn deref(&self) -> &Self::Target {
        &self.header_options
    }
}

impl EnhancedPacketHeaderOptions {
    fn calc_timestamp(raw: u64, tsresol: u8, tsoffset: i64) -> i64 {
        let timestamp = match tsresol {
            power_of_10 @ 0..=127 => {
                // The unit is 10^-power_of_10 seconds.
                let power_of_10 = power_of_10 as u32;
                if power_of_10 <= 9 {
                    (raw as i64).checked_mul(10_i64.pow(9 - power_of_10))
                } else {
                    (raw as i64).checked_div(10_i64.pow(power_of_10 - 9))
                }
            }
            power_of_2 => {
                // The unit is 2^-power_of_2 seconds.
                // We assume 2^10 ~ 10^3, so nanosecond ~ 2^-30 seconds.
                let power_of_2 = (power_of_2 ^ 0x80) as u32;
                if power_of_2 <= 30 {
                    (raw as i64).checked_mul(2_i64.pow(30 - power_of_2))
                } else {
                    (raw as i64).checked_div(2_i64.pow(power_of_2 - 30))
                }
            }
        };

        // TODO: Handle overflow
        timestamp
            .expect("timestamp calculation overflowed")
            .checked_add(tsoffset * 1_000_000_000)
            .expect("timestamp calculation overflowed")
    }

    /// Convert the raw split timestamp into nanoseconds since the Unix epoch.
    ///
    /// The conversion uses the timestamp resolution and timestamp offset from
    /// the referenced interface description.
    pub fn packet_timestamp(&self, interface: &InterfaceDescription) -> i64 {
        let raw = ((self.timestamp_high as u64) << 32) | (self.timestamp_low as u64);

        // The typical tsresol value is 6, means microsecond resolution.
        let tsresol = interface.tsresol.unwrap_or(6);
        let tsoffset = interface.tsoffset.unwrap_or(0);

        Self::calc_timestamp(raw, tsresol, tsoffset)
    }

    /// Convert this EPB header and packet bytes into a common packet record.
    pub fn into_packet_record<'a>(
        self,
        interface: &InterfaceDescription,
        data: &'a [u8],
    ) -> PacketRecord<'a> {
        PacketRecord {
            timestamp: self.packet_timestamp(interface),
            original_length: self.original_len,
            data: Cow::Borrowed(data),
            link_type: interface.link_type,
        }
    }
}

/// # Pcapng Block
#[derive(Debug, Clone)]
pub enum PcapngBlock<'a> {
    /// Parsed Section Header Block.
    SectionHeader(SectionHeader),

    /// Parsed Interface Description Block.
    InterfaceDescription(InterfaceDescription),

    /// Parsed Simple Packet Block.
    SimplePacket(SimplePacket<'a>),

    /// Parsed Enhanced Packet Block.
    EnhancedPacket(EnhancedPacket<'a>),

    /// Unsupported block preserved as raw bytes.
    Raw {
        /// Block type code that was not parsed into a typed variant.
        block_type: BlockType,
        /// Raw block body bytes.
        data: Cow<'a, [u8]>,
    },
}

#[derive(Debug)]
/// Streaming reader for PCAPNG files.
///
/// The reader tracks the current section and all interface descriptions because
/// later packet blocks refer to interfaces by numeric index.
pub struct PcapngReader<R: Read> {
    /// The latest section header
    pub section: Option<SectionHeader>,

    /// The interfaces
    pub interfaces: Vec<InterfaceDescription>,

    /// The underlying reader
    reader: BufReader<R>,

    /// The internal buffer for reading packets
    buffer: Vec<u8>,
}

impl<R: Read> PcapngReader<R> {
    /// Creates a new PcapngReader from a reader.
    ///
    /// Note: This does not read from the reader yet.
    pub fn new(reader: R) -> Result<Self, CaptureError> {
        Ok(Self {
            section: None,
            interfaces: Vec::new(),
            reader: BufReader::new(reader),
            buffer: Vec::new(),
        })
    }

    /// Return the most recently parsed section header, if any.
    pub fn section(&self) -> Option<&SectionHeader> {
        self.section.as_ref()
    }

    /// Return all interface descriptions parsed in the current reader state.
    pub fn interface_descriptions(&self) -> &[InterfaceDescription] {
        &self.interfaces
    }

    /// Read the next pcapng block.
    pub fn next_block(&mut self) -> Result<Option<PcapngBlock<'_>>, CaptureError> {
        let block_type = match self.next_block_type()? {
            Some(block_type) => block_type,
            None => return Ok(None),
        };

        match block_type {
            BlockType::SectionHeader => self
                .read_section_header()
                .map(PcapngBlock::SectionHeader)
                .map(Some),

            BlockType::InterfaceDescription => self
                .read_interface_description()
                .map(PcapngBlock::InterfaceDescription)
                .map(Some),

            BlockType::SimplePacket => self
                .read_simple_packet()
                .map(|spb| {
                    PcapngBlock::SimplePacket(SimplePacket {
                        header: spb,
                        packet_data: Cow::Borrowed(&self.buffer),
                    })
                })
                .map(Some),

            BlockType::EnhancedPacket => self
                .read_enhanced_packet()
                .map(|epb| {
                    PcapngBlock::EnhancedPacket(EnhancedPacket {
                        header_options: epb,
                        packet_data: Cow::Borrowed(&self.buffer),
                    })
                })
                .map(Some),

            _ => self.read_unsupported_block().map(Some),
        }
    }

    fn next_block_type(&mut self) -> Result<Option<BlockType>, CaptureError> {
        let mut block_type_bytes = [0u8; 4];

        match self.reader.read_exact(&mut block_type_bytes) {
            Ok(()) => {
                // let block_type_be = u32::from_be_bytes(block_type_bytes);
                // let block_type = BlockType::from(u32::from_be_bytes(block_type_bytes));

                if block_type_bytes == [0x0A, 0x0D, 0x0D, 0x0A] {
                    // A new section header
                    Ok(Some(BlockType::SectionHeader))
                } else {
                    // Not a section header, we need to use the current section header to determine the endianness
                    if let Some(section) = self.section() {
                        Ok(Some(BlockType::from(
                            section.endian.read_u32(&block_type_bytes),
                        )))
                    } else {
                        // No section header + not a section header block type
                        Err(CaptureError::InvalidMagicNumber(u32::from_be_bytes(
                            block_type_bytes,
                        )))
                    }
                }
            }

            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),

            Err(e) => Err(e.into()),
        }
    }

    fn read_option<'a>(
        buffer: &'a [u8],
        endian: Endian,
        offset: &mut usize,
    ) -> Result<(u16, u16, &'a [u8]), CaptureError> {
        // debug!(
        //     "Reading option at offset {} {:?}",
        //     offset,
        //     &buffer[*offset..]
        // );

        let option_type = endian.read_u16(&buffer[*offset..*offset + 2]);

        debug!("Option type: {}", option_type);

        let option_length = endian.read_u16(&buffer[*offset + 2..*offset + 4]);

        debug!("Option length: {}", option_length);

        if option_type == option_type::END_OF_OPT {
            *offset += 4;
            return Ok((option_type, option_length, &[]));
        }

        let option_value = &buffer[*offset + 4..*offset + 4 + option_length as usize];

        // The offset is padded to 32 bits, so we need to round up to the next multiple of 4
        *offset += 4 + option_length.next_multiple_of(4) as usize;

        Ok((option_type, option_length, option_value))
    }

    fn read_section_header(&mut self) -> Result<SectionHeader, CaptureError> {
        let mut block_total_length_bytes = [0u8; 4];
        let mut byte_order_bytes = [0u8; 4];

        self.reader.read_exact(&mut block_total_length_bytes)?;
        self.reader.read_exact(&mut byte_order_bytes)?;

        let mut section_header = SectionHeader {
            endian: if byte_order_bytes == [0x1A, 0x2B, 0x3C, 0x4D] {
                Endian::Big
            } else {
                Endian::Little
            },
            ..Default::default()
        };

        let block_total_length = section_header.endian.read_u32(&block_total_length_bytes);

        // Read the rest of the section header block, excluding the first 12 bytes (block type, block total length, and byte order magic)
        let mut buffer: Vec<u8> = vec![0u8; (block_total_length - 12) as usize];
        self.reader.read_exact(&mut buffer)?;

        section_header.major_version = section_header.endian.read_u16(&buffer[0..2]);
        section_header.minor_version = section_header.endian.read_u16(&buffer[2..4]);
        section_header.section_length = section_header.endian.read_i64(&buffer[4..12]);

        let mut position = 12;

        while position < buffer.len() - 4 {
            let (option_type, _option_length, option_value) =
                Self::read_option(&buffer, section_header.endian, &mut position)?;

            match option_type {
                option_type::END_OF_OPT => {
                    break;
                }

                option_type::SHB_HARDWARE => {
                    section_header.hardware = Some(String::from_utf8(option_value.to_vec())?)
                }

                option_type::SHB_OS => {
                    section_header.os = Some(String::from_utf8(option_value.to_vec())?)
                }

                option_type::SHB_USER_APPL => {
                    section_header.user_appl = Some(String::from_utf8(option_value.to_vec())?)
                }

                _ => {
                    // Skip unknown / unsupported option types
                }
            }
        }

        self.section = Some(section_header.clone());

        // Read the trailing block total length from the last 4 bytes of the buffer
        let trailing_block_total_length_bytes: [u8; 4] = buffer[buffer.len() - 4..].try_into()?;

        // Check that the trailing block total length matches the initial block total length
        let trailing_block_total_length = section_header
            .endian
            .read_u32(&trailing_block_total_length_bytes);

        if block_total_length != trailing_block_total_length {
            error!(
                "Section header block total length mismatch: {} != {}",
                block_total_length, trailing_block_total_length
            );
        }

        Ok(section_header)
    }

    fn read_interface_description(&mut self) -> Result<InterfaceDescription, CaptureError> {
        let mut interface = InterfaceDescription::default();
        let endian = self
            .section
            .as_ref()
            .expect("No section header found")
            .endian;

        let mut block_total_length_bytes = [0u8; 4];
        self.reader.read_exact(&mut block_total_length_bytes)?;
        let block_total_length = endian.read_u32(&block_total_length_bytes);

        // Read the rest of the interface description block, excluding the first 8 bytes (block type and block total length)
        let mut buffer: Vec<u8> = vec![0u8; (block_total_length - 8) as usize];
        self.reader.read_exact(&mut buffer)?;

        interface.link_type = LinkType::from(endian.read_u16(&buffer[0..2]));
        interface.snap_len = endian.read_u32(&buffer[4..8]);

        let mut position = 8;

        while position < buffer.len() - 4 {
            let (option_type, _option_length, option_value) =
                Self::read_option(&buffer, endian, &mut position)?;

            match option_type {
                option_type::END_OF_OPT => {
                    break;
                }

                option_type::IF_NAME => {
                    interface.name = Some(String::from_utf8(option_value.to_vec())?)
                }

                option_type::IF_DESCRIPTION => {
                    interface.description = Some(String::from_utf8(option_value.to_vec())?)
                }

                option_type::IF_IPV4_ADDR => interface.ipv4_addr.push((
                    Ipv4Addr::new(
                        option_value[0],
                        option_value[1],
                        option_value[2],
                        option_value[3],
                    ),
                    Ipv4Addr::new(
                        option_value[4],
                        option_value[5],
                        option_value[6],
                        option_value[7],
                    ),
                )),

                option_type::IF_IPV6_ADDR => {
                    let addr = Ipv6Addr::from_octets(option_value[0..16].try_into()?);
                    let prefix_len = option_value[16];
                    interface.ipv6_addr.push((addr, prefix_len));
                }

                option_type::IF_MAC_ADDR => {
                    interface.mac_addr = Some(EthAddr::from_slice(option_value));
                }

                option_type::IF_EUI_ADDR => {
                    interface.eui_addr = Some(option_value.try_into()?);
                }

                option_type::IF_SPEED => {
                    interface.speed = Some(endian.read_u64(option_value));
                }

                option_type::IF_TSRESOL => {
                    interface.tsresol = Some(option_value[0]);
                }

                option_type::IF_TZONE => {
                    interface.tzone = Some(endian.read_i32(option_value));
                }

                option_type::IF_FILTER => {
                    interface.filter = option_value.to_vec();
                }

                option_type::IF_OS => {
                    interface.os = Some(String::from_utf8(option_value.to_vec())?)
                }

                option_type::IF_FCSLEN => {
                    interface.fcs_len = Some(option_value[0]);
                }

                option_type::IF_TSOFFSET => {
                    interface.tsoffset = Some(endian.read_i64(option_value));
                }

                option_type::IF_HARDWARE => {
                    interface.hardware = Some(String::from_utf8(option_value.to_vec())?)
                }

                option_type::IF_TXSPEED => {
                    interface.txspeed = Some(endian.read_u64(option_value));
                }

                option_type::IF_RXSPEED => {
                    interface.rxspeed = Some(endian.read_u64(option_value));
                }

                option_type::IF_IANA_TZNAME => {
                    interface.iana_tzname = Some(String::from_utf8(option_value.to_vec())?)
                }

                _ => {
                    // Skip unknown / unsupported option types
                }
            }
        }

        self.interfaces.push(interface.clone());

        // Read the trailing block total length from the last 4 bytes of the buffer
        let trailing_block_total_length_bytes: [u8; 4] = buffer[buffer.len() - 4..].try_into()?;

        // Check that the trailing block total length matches the initial block total length
        let trailing_block_total_length = endian.read_u32(&trailing_block_total_length_bytes);

        if block_total_length != trailing_block_total_length {
            error!(
                "Interface description block total length mismatch: {} != {}",
                block_total_length, trailing_block_total_length
            );
        }

        Ok(interface)
    }

    fn read_simple_packet(&mut self) -> Result<SimplePacketHeader, CaptureError> {
        let endian = self
            .section
            .as_ref()
            .expect("No section header found")
            .endian;

        let mut block_total_length_bytes = [0u8; 4];
        self.reader.read_exact(&mut block_total_length_bytes)?;

        let block_total_length = endian.read_u32(&block_total_length_bytes);

        // Read the original packet length
        let mut original_len_bytes = [0u8; 4];
        self.reader.read_exact(&mut original_len_bytes)?;
        let original_len = endian.read_u32(&original_len_bytes);

        // Read the packet data into the internal buffer
        self.buffer.resize((block_total_length - 16) as usize, 0);
        self.reader.read_exact(&mut self.buffer)?;

        // Read the trailing block total length from the last 4 bytes of the buffer
        let trailing_block_total_length_bytes: [u8; 4] =
            self.buffer[self.buffer.len() - 4..].try_into()?;

        // Check that the trailing block total length matches the initial block total length
        let trailing_block_total_length = endian.read_u32(&trailing_block_total_length_bytes);

        if block_total_length != trailing_block_total_length {
            error!(
                "Simple packet block total length mismatch: {} != {}",
                block_total_length, trailing_block_total_length
            );
        }

        Ok(SimplePacketHeader { original_len })
    }

    fn read_enhanced_packet(&mut self) -> Result<EnhancedPacketHeaderOptions, CaptureError> {
        let mut enhanced_packet = EnhancedPacketHeaderOptions::default();
        let endian = self
            .section
            .as_ref()
            .expect("No section header found")
            .endian;

        let mut block_total_length_bytes = [0u8; 4];
        self.reader.read_exact(&mut block_total_length_bytes)?;
        let block_total_length = endian.read_u32(&block_total_length_bytes);

        let mut header_bytes = [0u8; 20];
        self.reader.read_exact(&mut header_bytes)?;

        enhanced_packet.interface_id = endian.read_u32(&header_bytes[0..4]);
        enhanced_packet.timestamp_high = endian.read_u32(&header_bytes[4..8]);
        enhanced_packet.timestamp_low = endian.read_u32(&header_bytes[8..12]);
        enhanced_packet.captured_len = endian.read_u32(&header_bytes[12..16]);
        enhanced_packet.original_len = endian.read_u32(&header_bytes[16..20]);

        // The packet data is padded to 32 bits, so we need to skip the padding bytes
        let padded_length = enhanced_packet.captured_len.next_multiple_of(4);

        // Read the packet data into the internal buffer
        self.buffer.resize(padded_length as usize, 0);
        self.reader.read_exact(&mut self.buffer)?;

        // Resize the buffer to the actual captured length
        self.buffer.resize(enhanced_packet.captured_len as usize, 0);

        // Read the options, if any
        let mut buffer = vec![0u8; (block_total_length - 32 - padded_length) as usize];
        self.reader.read_exact(&mut buffer)?;

        let mut position = 0;
        while position < buffer.len() {
            let (option_type, _option_length, option_value) =
                Self::read_option(&buffer, endian, &mut position)?;

            match option_type {
                option_type::END_OF_OPT => {
                    break;
                }

                option_type::EPB_FLAGS => {
                    enhanced_packet.flags = Some(endian.read_u32(option_value));
                }

                option_type::EPB_HASH => {
                    enhanced_packet.hash.push(option_value.to_vec());
                }

                option_type::EPB_DROPCOUNT => {
                    enhanced_packet.drop_count = Some(endian.read_u64(option_value));
                }

                option_type::EPB_PACKET_ID => {
                    enhanced_packet.packet_id = Some(endian.read_u64(option_value));
                }

                option_type::EPB_QUEUE => {
                    enhanced_packet.queue = Some(endian.read_u32(option_value));
                }

                option_type::EPB_VERDICT => {
                    enhanced_packet.verdict.push(option_value.to_vec());
                }

                option_type::EPB_PROCESSID_THREADID => {
                    let process_id = endian.read_u32(&option_value[0..4]);
                    let thread_id = endian.read_u32(&option_value[4..8]);
                    enhanced_packet.processid_threadid = Some((process_id, thread_id));
                }

                _ => {
                    // Skip unknown / unsupported option types
                }
            }
        }

        // Read the trailing block total length from the reader
        let mut trailing_block_total_length_bytes = [0u8; 4];
        self.reader
            .read_exact(&mut trailing_block_total_length_bytes)?;

        // Check that the trailing block total length matches the initial block total length
        let trailing_block_total_length = endian.read_u32(&trailing_block_total_length_bytes);

        if block_total_length != trailing_block_total_length {
            error!(
                "Enhanced packet block total length mismatch: {} != {}",
                block_total_length, trailing_block_total_length
            );
        }

        Ok(enhanced_packet)
    }

    fn read_unsupported_block(&mut self) -> Result<PcapngBlock<'_>, CaptureError> {
        let endian = self
            .section
            .as_ref()
            .expect("No section header found")
            .endian;

        let mut block_total_length_bytes = [0u8; 4];
        self.reader.read_exact(&mut block_total_length_bytes)?;
        let block_total_length = endian.read_u32(&block_total_length_bytes);

        self.buffer.resize((block_total_length - 8) as usize, 0);
        self.reader.read_exact(&mut self.buffer)?;

        Ok(PcapngBlock::Raw {
            block_type: BlockType::Unknown(u32::from_be_bytes(block_total_length_bytes)),
            data: Cow::Borrowed(&self.buffer),
        })
    }

    /// Read blocks until the next packet record is found.
    ///
    /// Non-packet blocks are consumed to update reader state or skipped when
    /// unsupported. Returns `Ok(None)` at end of file.
    pub fn next_packet(&mut self) -> Result<Option<PacketRecord<'_>>, CaptureError> {
        loop {
            let block_type = match self.next_block_type()? {
                Some(block_type) => block_type,
                None => return Ok(None),
            };

            trace!("Next block type: {:?}", block_type);

            match block_type {
                BlockType::SectionHeader => {
                    self.read_section_header()?;
                }

                BlockType::InterfaceDescription => {
                    self.read_interface_description()?;
                }

                BlockType::SimplePacket => {
                    error!("Simple Packet Block");

                    let spb = self.read_simple_packet()?;
                    if let Some(interface) = self.interface_descriptions().first() {
                        return Ok(Some(
                            spb.into_packet_record(interface, self.buffer.as_slice()),
                        ));
                    } else {
                        return Err(CaptureError::MissingPcapngInterfaceDescriptionBlock);
                    }
                }

                BlockType::EnhancedPacket => {
                    let epb = self.read_enhanced_packet()?;

                    if let Some(interface) =
                        self.interface_descriptions().get(epb.interface_id as usize)
                    {
                        return Ok(Some(
                            epb.into_packet_record(interface, self.buffer.as_slice()),
                        ));
                    } else {
                        return Err(CaptureError::InvalidPcapngPacketInterfaceId(
                            epb.interface_id,
                        ));
                    }
                }

                _ => {
                    // Skip other blocks
                    trace!("Skipping unsupported block type: {:?}", block_type);
                    self.read_unsupported_block()?;
                }
            }
        }
    }
}

impl<R: Read> CaptureReader for PcapngReader<R> {
    fn interfaces(&self) -> Vec<interface::Interface> {
        self.interfaces
            .iter()
            .map(|idb| idb.to_interface())
            .collect()
    }

    fn next_packet(
        &mut self,
    ) -> Result<Option<crate::capture::packet::PacketRecord<'_>>, CaptureError> {
        self.next_packet()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    #[test]
    fn epb_calc_timestamp() {
        // 2001-02-03 04:05:06.789012
        let raw = 981144306789012 as u64;
        let tsresol = 6;
        let tsoffset = 0;

        let timestamp = EnhancedPacketHeaderOptions::calc_timestamp(raw, tsresol, tsoffset);
        assert_eq!(timestamp, 981144306789012000);
    }

    #[test]
    fn read_section_header() {
        let bytes: [u8; 28] = [
            0x0A, 0x0D, 0x0D, 0x0A, // Block Type: Section Header
            0x00, 0x00, 0x00, 0x1C, // Block Total Length: 28
            0x1A, 0x2B, 0x3C, 0x4D, // Byte-Order Magic: 0x1A2B3C4D
            0x00, 0x01, // Major Version: 1
            0x00, 0x00, // Minor Version: 0
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, // Section Length: -1 (unspecified)
            0x00, 0x00, 0x00, 0x1C, // Block Total Length: 28
        ];

        let mut reader = PcapngReader::new(Cursor::new(&bytes)).unwrap();

        let section_header = reader.next_block().unwrap().unwrap();

        if let PcapngBlock::SectionHeader(shb) = section_header {
            assert_eq!(shb.endian, Endian::Big);
            assert_eq!(shb.major_version, 1);
            assert_eq!(shb.minor_version, 0);
            assert_eq!(shb.section_length, -1);
        } else {
            panic!("Expected SectionHeader block");
        }

        let bytes: [u8; _] = [
            0x0A, 0x0D, 0x0D, 0x0A, // Block Type: Section Header
            0x00, 0x00, 0x00, 0x24, // Block Total Length: 36
            0x1A, 0x2B, 0x3C, 0x4D, // Byte-Order Magic: 0x1A2B3C4D
            0x00, 0x01, // Major Version: 1
            0x00, 0x00, // Minor Version: 0
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, // Section Length: -1 (unspecified)
            0x00, 0x02, 0x00, 0x04, // Option Type: SHB_HARDWARE, Option Length: 4
            0x74, 0x65, 0x73, 0x74, // Option Value: "test"
            0x00, 0x00, 0x00, 0x24, // Block Total Length: 36
        ];

        let mut reader = PcapngReader::new(Cursor::new(&bytes)).unwrap();

        let section_header = reader.next_block().unwrap().unwrap();

        if let PcapngBlock::SectionHeader(shb) = section_header {
            assert_eq!(shb.endian, Endian::Big);
            assert_eq!(shb.major_version, 1);
            assert_eq!(shb.minor_version, 0);
            assert_eq!(shb.section_length, -1);
            assert_eq!(shb.hardware.as_deref(), Some("test"));
        } else {
            panic!("Expected SectionHeader block");
        }
    }

    #[test]
    fn pcapng_reader() {
        let data: [u8; _] = [
            /* SHB */
            0x0A, 0x0D, 0x0D, 0x0A, // Block Type: Section Header
            0x00, 0x00, 0x00, 0x1C, // Block Total Length: 28
            0x1A, 0x2B, 0x3C, 0x4D, // Byte-Order Magic: 0x1A2B3C4D
            0x00, 0x01, // Major Version: 1
            0x00, 0x00, // Minor Version: 0
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, // Section Length: -1 (unspecified)
            0x00, 0x00, 0x00, 0x1C, // Block Total Length: 28
            /* IDB */
            0x00, 0x00, 0x00, 0x01, // Block Type: Interface Description
            0x00, 0x00, 0x00, 0x14, // Block Total Length: 20
            0x00, 0x01, // LinkType: Ethernet (1)
            0x00, 0x00, // Reserved
            0x00, 0x00, 0x04, 0x00, // SnapLen: 1024
            0x00, 0x00, 0x00, 0x14, // Block Total Length: 20
            /* EPB: A Eth / Ipv4 / Udp / Payload */
            0x00, 0x00, 0x00, 0x06, // Block Type: Enhanced Packet
            0x00, 0x00, 0x00, 0x50, // Block Total Length: 78
            0x00, 0x00, 0x00, 0x00, // Interface ID: 0
            0x00, 0x03, 0x7C, 0x58, // Timestamp (High)
            0x75, 0xE1, 0x2A, 0x94, // Timestamp (Low)
            0x00, 0x00, 0x00, 0x2E, // Captured Len: 20
            0x00, 0x00, 0x00, 0x2E, // Original Len: 20
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Dst MAC: 00:01:02:03:04:05
            0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, // Src MAC: 06:07:08:09:0A:0B
            0x08, 0x00, // Ethertype: IPv4 (0x0800)
            0x45, // Version + IHL
            0x00, // DSCP + ECN
            0x00, 0x20, // Total Length (20 + 8 + 4 = 32)
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment Offset
            0x40, // TTL (64)
            0x11, // Protocol (UDP)
            0x00, 0x00, // Header Checksum (TODO: Calculate this)
            10, 0, 1, 1, // Source IP
            10, 0, 1, 2, // Destination IP
            0x04, 0xd2, 0x04, 0xd3, // Source Port (1234), Destination Port (1235)
            0x00, 0x0c, // Length (8 + 4 = 12)
            0x00, 0x00, // Checksum (TODO: Calculate this)
            0x01, 0x02, 0x03, 0x04, // Payload
            0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x50, // Block Total Length: 78
        ];

        let mut reader = PcapngReader::new(Cursor::new(&data)).unwrap();

        let packet_record = reader.next_packet().unwrap().unwrap();

        assert_eq!(packet_record.timestamp, 981144306789012000);
        assert_eq!(packet_record.link_type, LinkType::Ethernet);
        assert_eq!(packet_record.original_length, 46);

        let mut packet = Packet::new(packet_record.data);
        packet.parse::<Eth>(Default::default());

        let eth = packet.layer_viewer(Eth).unwrap();
        assert_eq!(eth.dst(), EthAddr::new(0, 1, 2, 3, 4, 5));
        assert_eq!(eth.src(), EthAddr::new(6, 7, 8, 9, 10, 11));
        assert_eq!(eth.eth_type().raw(), 0x0800);

        let ipv4 = packet
            .layer_viewer(crate::packet::layer::ip::v4::Ipv4)
            .unwrap();
        assert_eq!(ipv4.src(), Ipv4Addr::new(10, 0, 1, 1));
        assert_eq!(ipv4.dst(), Ipv4Addr::new(10, 0, 1, 2));
        assert_eq!(ipv4.protocol().raw(), 17);

        let udp = packet.layer_viewer(crate::packet::layer::udp::Udp).unwrap();
        assert_eq!(udp.src_port(), 1234);
        assert_eq!(udp.dst_port(), 1235);
    }
}
