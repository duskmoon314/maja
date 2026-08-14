//! PCAPNG format.

use std::{
    borrow::Cow,
    io::{BufReader, Read},
    net::{Ipv4Addr, Ipv6Addr},
    ops::Deref,
};

use log::{debug, trace};
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::{
    capture::{
        CaptureError, CaptureReader,
        endian::Endian,
        interface::{self, Interface},
        link_type::LinkType,
        packet::{LocatedPacketRecord, PacketRecord},
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

/// Read one option at `offset` from `buffer`, advancing `offset` past it.
///
/// Returns the option type, value length, and value bytes. Options are padded
/// to 32 bits; the padding is consumed but not returned.
fn read_option<'a>(
    buffer: &'a [u8],
    endian: Endian,
    offset: &mut usize,
) -> Result<(u16, u16, &'a [u8]), CaptureError> {
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

/// Check that the trailing block total length matches the leading one.
///
/// A mismatch means the block is corrupt, so a
/// [`PcapngBlockTotalLengthMismatch`](CaptureError::PcapngBlockTotalLengthMismatch)
/// error is returned. Callers may still resume parsing with the next block if they
/// choose to: block boundaries are derived from the leading length alone,
/// which both readers consume before this check runs.
fn check_block_total_length(
    block: &[u8],
    endian: Endian,
    what: &'static str,
) -> Result<(), CaptureError> {
    let leading = endian.read_u32(&block[4..8]);
    let trailing = endian.read_u32(&block[block.len() - 4..]);
    if leading != trailing {
        return Err(CaptureError::PcapngBlockTotalLengthMismatch(
            what, leading, trailing,
        ));
    }
    Ok(())
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

impl SectionHeader {
    /// Parse a Section Header Block from its complete bytes, from the block
    /// type field through the trailing block total length.
    pub fn parse(block: &[u8]) -> Result<Self, CaptureError> {
        if block.len() < 28 {
            return Err(CaptureError::TruncatedCapture(
                "pcapng section header block",
            ));
        }

        let mut section_header = SectionHeader {
            endian: if block[8..12] == [0x1A, 0x2B, 0x3C, 0x4D] {
                Endian::Big
            } else {
                Endian::Little
            },
            ..Default::default()
        };
        let endian = section_header.endian;

        section_header.major_version = endian.read_u16(&block[12..14]);
        section_header.minor_version = endian.read_u16(&block[14..16]);
        section_header.section_length = endian.read_i64(&block[16..24]);

        let mut position = 24;
        while position < block.len() - 4 {
            let (option_type, _option_length, option_value) =
                read_option(block, endian, &mut position)?;

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

        check_block_total_length(block, endian, "Section header")?;

        Ok(section_header)
    }
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

    /// Parse an Interface Description Block from its complete bytes, from the
    /// block type field through the trailing block total length, using the
    /// current section's byte order.
    pub fn parse(block: &[u8], endian: Endian) -> Result<Self, CaptureError> {
        if block.len() < 20 {
            return Err(CaptureError::TruncatedCapture(
                "pcapng interface description block",
            ));
        }

        let mut interface = InterfaceDescription {
            link_type: LinkType::from(endian.read_u16(&block[8..10])),
            snap_len: endian.read_u32(&block[12..16]),
            ..Default::default()
        };

        let mut position = 16;
        while position < block.len() - 4 {
            let (option_type, _option_length, option_value) =
                read_option(block, endian, &mut position)?;

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

        check_block_total_length(block, endian, "Interface description")?;

        Ok(interface)
    }

    /// Build the generic interface metadata for this description.
    pub fn to_interface(&self) -> Interface {
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
    /// Parse a Simple Packet Block from its complete bytes, from the block
    /// type field through the trailing block total length, using the current
    /// section's byte order.
    ///
    /// Returns the header and the packet data bytes. The data slice may
    /// include 32-bit padding bytes, matching the streaming reader's
    /// behavior.
    pub fn parse(block: &[u8], endian: Endian) -> Result<(Self, &[u8]), CaptureError> {
        if block.len() < 16 {
            return Err(CaptureError::TruncatedCapture("pcapng simple packet block"));
        }

        check_block_total_length(block, endian, "Simple packet")?;

        let header = Self {
            original_len: endian.read_u32(&block[8..12]),
        };
        let data = &block[12..block.len() - 4];

        Ok((header, data))
    }

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
    /// Parse an Enhanced Packet Block from its complete bytes, from the block
    /// type field through the trailing block total length, using the current
    /// section's byte order.
    ///
    /// Returns the parsed header fields and options, plus the packet data
    /// bytes (32-bit padding excluded).
    pub fn parse(block: &[u8], endian: Endian) -> Result<(Self, &[u8]), CaptureError> {
        if block.len() < 32 {
            return Err(CaptureError::TruncatedCapture(
                "pcapng enhanced packet block",
            ));
        }

        let mut enhanced_packet = Self {
            interface_id: endian.read_u32(&block[8..12]),
            timestamp_high: endian.read_u32(&block[12..16]),
            timestamp_low: endian.read_u32(&block[16..20]),
            captured_len: endian.read_u32(&block[20..24]),
            original_len: endian.read_u32(&block[24..28]),
            ..Default::default()
        };

        // The packet data is padded to 32 bits, so the options start after
        // the padded data.
        let padded_length = enhanced_packet.captured_len.next_multiple_of(4) as usize;
        let options_start = 28 + padded_length;
        if block.len() < options_start + 4 {
            return Err(CaptureError::TruncatedCapture(
                "pcapng enhanced packet block",
            ));
        }
        let data = &block[28..28 + enhanced_packet.captured_len as usize];

        let mut position = options_start;
        while position < block.len() - 4 {
            let (option_type, _option_length, option_value) =
                read_option(block, endian, &mut position)?;

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

        check_block_total_length(block, endian, "Enhanced packet")?;

        Ok((enhanced_packet, data))
    }

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
        let block_type = match self.read_next_block()? {
            Some(block_type) => block_type,
            None => return Ok(None),
        };

        let block = self.buffer.as_slice();

        match block_type {
            BlockType::SectionHeader => {
                let section_header = SectionHeader::parse(block)?;
                self.section = Some(section_header.clone());
                Ok(Some(PcapngBlock::SectionHeader(section_header)))
            }

            BlockType::InterfaceDescription => {
                let endian = self
                    .section
                    .as_ref()
                    .expect("No section header found")
                    .endian;
                let interface = InterfaceDescription::parse(block, endian)?;
                self.interfaces.push(interface.clone());
                Ok(Some(PcapngBlock::InterfaceDescription(interface)))
            }

            BlockType::SimplePacket => {
                let endian = self
                    .section
                    .as_ref()
                    .expect("No section header found")
                    .endian;
                let (header, data) = SimplePacketHeader::parse(block, endian)?;
                Ok(Some(PcapngBlock::SimplePacket(SimplePacket {
                    header,
                    packet_data: Cow::Borrowed(data),
                })))
            }

            BlockType::EnhancedPacket => {
                let endian = self
                    .section
                    .as_ref()
                    .expect("No section header found")
                    .endian;
                let (header_options, data) = EnhancedPacketHeaderOptions::parse(block, endian)?;
                Ok(Some(PcapngBlock::EnhancedPacket(EnhancedPacket {
                    header_options,
                    packet_data: Cow::Borrowed(data),
                })))
            }

            _ => Ok(Some(PcapngBlock::Raw {
                block_type,
                data: Cow::Borrowed(&block[8..]),
            })),
        }
    }

    /// Read the next complete block into the internal buffer and return its
    /// type.
    ///
    /// On return the buffer holds the complete block, from the block type
    /// field through the trailing block total length. Returns `Ok(None)` at
    /// end of input.
    fn read_next_block(&mut self) -> Result<Option<BlockType>, CaptureError> {
        let mut block_type_bytes = [0u8; 4];
        match self.reader.read_exact(&mut block_type_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        self.buffer.clear();
        self.buffer.extend_from_slice(&block_type_bytes);

        let mut length_bytes = [0u8; 4];
        self.reader.read_exact(&mut length_bytes)?;
        self.buffer.extend_from_slice(&length_bytes);

        let (block_type, endian) = if block_type_bytes == [0x0A, 0x0D, 0x0D, 0x0A] {
            // A section header carries its own byte-order magic right after
            // the length field.
            let mut byte_order_bytes = [0u8; 4];
            self.reader.read_exact(&mut byte_order_bytes)?;
            self.buffer.extend_from_slice(&byte_order_bytes);
            let endian = if byte_order_bytes == [0x1A, 0x2B, 0x3C, 0x4D] {
                Endian::Big
            } else {
                Endian::Little
            };
            (BlockType::SectionHeader, endian)
        } else {
            // Not a section header, we need to use the current section header
            // to determine the endianness
            let section = self
                .section
                .as_ref()
                .ok_or(CaptureError::InvalidMagicNumber(u32::from_be_bytes(
                    block_type_bytes,
                )))?;
            (
                BlockType::from(section.endian.read_u32(&block_type_bytes)),
                section.endian,
            )
        };

        let block_total_length = endian.read_u32(&length_bytes) as usize;
        if block_total_length < self.buffer.len() {
            return Err(CaptureError::InvalidPcapngBlockTotalLength(
                block_total_length as u32,
            ));
        }

        let position = self.buffer.len();
        self.buffer.resize(block_total_length, 0);
        self.reader.read_exact(&mut self.buffer[position..])?;

        Ok(Some(block_type))
    }

    /// Read blocks until the next packet record is found.
    ///
    /// Non-packet blocks are consumed to update reader state or skipped when
    /// unsupported. Returns `Ok(None)` at end of file.
    pub fn next_packet(&mut self) -> Result<Option<PacketRecord<'_>>, CaptureError> {
        loop {
            let block_type = match self.read_next_block()? {
                Some(block_type) => block_type,
                None => return Ok(None),
            };

            trace!("Next block type: {:?}", block_type);

            match block_type {
                BlockType::SectionHeader => {
                    self.section = Some(SectionHeader::parse(&self.buffer)?);
                }

                BlockType::InterfaceDescription => {
                    let endian = self
                        .section
                        .as_ref()
                        .expect("No section header found")
                        .endian;
                    let interface = InterfaceDescription::parse(&self.buffer, endian)?;
                    self.interfaces.push(interface);
                }

                BlockType::SimplePacket => {
                    let endian = self
                        .section
                        .as_ref()
                        .expect("No section header found")
                        .endian;
                    let (spb, data) = SimplePacketHeader::parse(&self.buffer, endian)?;
                    if let Some(interface) = self.interface_descriptions().first() {
                        return Ok(Some(spb.into_packet_record(interface, data)));
                    } else {
                        return Err(CaptureError::MissingPcapngInterfaceDescriptionBlock);
                    }
                }

                BlockType::EnhancedPacket => {
                    let endian = self
                        .section
                        .as_ref()
                        .expect("No section header found")
                        .endian;
                    let (epb, data) = EnhancedPacketHeaderOptions::parse(&self.buffer, endian)?;
                    if let Some(interface) =
                        self.interface_descriptions().get(epb.interface_id as usize)
                    {
                        return Ok(Some(epb.into_packet_record(interface, data)));
                    } else {
                        return Err(CaptureError::InvalidPcapngPacketInterfaceId(
                            epb.interface_id,
                        ));
                    }
                }

                _ => {
                    // Skip other blocks
                    trace!("Skipping unsupported block type: {:?}", block_type);
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

/// A pcapng block read from a slice: its byte offset, complete raw bytes, and
/// parsed content.
#[derive(Debug)]
pub struct PcapngBlockRecord<'a> {
    /// Byte offset of the block in the input slice
    pub offset: usize,

    /// Complete raw block bytes, from the block type field through the
    /// trailing block total length
    pub raw: &'a [u8],

    /// Parsed block content borrowing from `raw`
    pub block: PcapngBlock<'a>,
}

/// # Zero-copy PCAPNG reader over a byte slice
///
/// `PcapngSliceReader` parses a PCAPNG capture held entirely in memory —
/// typically an `mmap`-backed slice — without copying packet bytes. Blocks
/// and records borrow from the input slice with lifetime `'a` rather than
/// from the reader itself, so they can be held across subsequent reads.
///
/// Every block is returned with its byte offset and complete raw bytes,
/// enabling index-then-copy workflows such as reordering packet blocks by
/// timestamp while copying them verbatim.
#[derive(Debug)]
pub struct PcapngSliceReader<'a> {
    /// The latest section header
    pub section: Option<SectionHeader>,

    /// The interfaces
    pub interfaces: Vec<InterfaceDescription>,

    /// The underlying capture bytes
    data: &'a [u8],

    /// Offset of the next block
    pos: usize,
}

impl<'a> PcapngSliceReader<'a> {
    /// Create a reader over a complete in-memory PCAPNG capture.
    ///
    /// Parsing is lazy: section and interface state is built up as blocks are
    /// read.
    pub fn new(data: &'a [u8]) -> Result<Self, CaptureError> {
        Ok(Self {
            section: None,
            interfaces: Vec::new(),
            data,
            pos: 0,
        })
    }

    /// Return the byte offset at which the next block starts.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Return the most recently parsed section header, if any.
    pub fn section(&self) -> Option<&SectionHeader> {
        self.section.as_ref()
    }

    /// Return all interface descriptions parsed in the current reader state.
    pub fn interface_descriptions(&self) -> &[InterfaceDescription] {
        &self.interfaces
    }

    /// Read the next pcapng block, borrowing directly from the input slice.
    ///
    /// Returns `Ok(None)` when the slice is exhausted.
    pub fn next_block(&mut self) -> Result<Option<PcapngBlockRecord<'a>>, CaptureError> {
        let remaining: &'a [u8] = &self.data[self.pos..];
        if remaining.is_empty() {
            return Ok(None);
        }
        if remaining.len() < 12 {
            return Err(CaptureError::TruncatedCapture("pcapng block"));
        }

        let block_type_bytes: [u8; 4] = remaining[0..4].try_into().unwrap();
        let (block_type, endian) = if block_type_bytes == [0x0A, 0x0D, 0x0D, 0x0A] {
            // A section header carries its own byte-order magic right after
            // the length field.
            let endian = if remaining[8..12] == [0x1A, 0x2B, 0x3C, 0x4D] {
                Endian::Big
            } else {
                Endian::Little
            };
            (BlockType::SectionHeader, endian)
        } else {
            // Not a section header, we need to use the current section header
            // to determine the endianness
            let section = self
                .section
                .as_ref()
                .ok_or(CaptureError::InvalidMagicNumber(u32::from_be_bytes(
                    block_type_bytes,
                )))?;
            (
                BlockType::from(section.endian.read_u32(&block_type_bytes)),
                section.endian,
            )
        };

        let block_total_length = endian.read_u32(&remaining[4..8]) as usize;
        if block_total_length < 12 || remaining.len() < block_total_length {
            return Err(CaptureError::TruncatedCapture("pcapng block"));
        }

        let offset = self.pos;
        let raw = &remaining[..block_total_length];
        self.pos += block_total_length;

        let block = match block_type {
            BlockType::SectionHeader => {
                let section_header = SectionHeader::parse(raw)?;
                self.section = Some(section_header.clone());
                PcapngBlock::SectionHeader(section_header)
            }

            BlockType::InterfaceDescription => {
                let interface = InterfaceDescription::parse(raw, endian)?;
                self.interfaces.push(interface.clone());
                PcapngBlock::InterfaceDescription(interface)
            }

            BlockType::SimplePacket => {
                let (header, data) = SimplePacketHeader::parse(raw, endian)?;
                PcapngBlock::SimplePacket(SimplePacket {
                    header,
                    packet_data: Cow::Borrowed(data),
                })
            }

            BlockType::EnhancedPacket => {
                let (header_options, data) = EnhancedPacketHeaderOptions::parse(raw, endian)?;
                PcapngBlock::EnhancedPacket(EnhancedPacket {
                    header_options,
                    packet_data: Cow::Borrowed(data),
                })
            }

            _ => PcapngBlock::Raw {
                block_type,
                data: Cow::Borrowed(&raw[8..]),
            },
        };

        Ok(Some(PcapngBlockRecord { offset, raw, block }))
    }

    /// Read blocks until the next packet record is found, borrowing directly
    /// from the input slice.
    ///
    /// Unlike the [`CaptureReader`] implementation, records returned by this
    /// inherent method are tied to the input slice's lifetime `'a` rather
    /// than to the borrow of the reader, so they may be held across later
    /// reads.
    pub fn next_packet(&mut self) -> Result<Option<PacketRecord<'a>>, CaptureError> {
        match self.next_packet_with_offset()? {
            Some(located) => Ok(Some(located.packet)),
            None => Ok(None),
        }
    }

    /// Read blocks until the next packet record is found, returning it along
    /// with the offset and raw bytes of its source block.
    pub fn next_packet_with_offset(
        &mut self,
    ) -> Result<Option<LocatedPacketRecord<'a>>, CaptureError> {
        loop {
            let Some(record) = self.next_block()? else {
                return Ok(None);
            };

            match record.block {
                PcapngBlock::SimplePacket(sp) => {
                    let data = match sp.packet_data {
                        Cow::Borrowed(data) => data,
                        Cow::Owned(_) => unreachable!("slice reader never owns packet data"),
                    };
                    if let Some(interface) = self.interfaces.first() {
                        return Ok(Some(LocatedPacketRecord {
                            offset: record.offset,
                            raw: record.raw,
                            packet: sp.header.into_packet_record(interface, data),
                        }));
                    } else {
                        return Err(CaptureError::MissingPcapngInterfaceDescriptionBlock);
                    }
                }

                PcapngBlock::EnhancedPacket(ep) => {
                    let data = match ep.packet_data {
                        Cow::Borrowed(data) => data,
                        Cow::Owned(_) => unreachable!("slice reader never owns packet data"),
                    };
                    if let Some(interface) =
                        self.interfaces.get(ep.header_options.interface_id as usize)
                    {
                        return Ok(Some(LocatedPacketRecord {
                            offset: record.offset,
                            raw: record.raw,
                            packet: ep.header_options.into_packet_record(interface, data),
                        }));
                    } else {
                        return Err(CaptureError::InvalidPcapngPacketInterfaceId(
                            ep.header_options.interface_id,
                        ));
                    }
                }

                _ => {
                    // Skip non-packet blocks
                }
            }
        }
    }
}

impl<'a> CaptureReader for PcapngSliceReader<'a> {
    fn interfaces(&self) -> Vec<interface::Interface> {
        self.interfaces
            .iter()
            .map(|idb| idb.to_interface())
            .collect()
    }

    fn next_packet(&mut self) -> Result<Option<PacketRecord<'_>>, CaptureError> {
        self.next_packet()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

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

    /// SHB + IDB + two EPBs, the second one microsecond later.
    fn slice_test_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&SHB);
        data.extend_from_slice(&IDB);
        data.extend_from_slice(&EPB);
        let mut epb2 = EPB;
        epb2[19] += 1; // Timestamp (Low) + 1 microsecond
        data.extend_from_slice(&epb2);
        data
    }

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

    #[test]
    fn pcapng_slice_reader() {
        let data = slice_test_data();

        // Block-level access carries offsets and complete raw bytes.
        let mut reader = PcapngSliceReader::new(&data).unwrap();
        let shb = reader.next_block().unwrap().unwrap();
        assert_eq!(shb.offset, 0);
        assert_eq!(shb.raw, SHB);
        assert!(matches!(shb.block, PcapngBlock::SectionHeader(_)));
        let idb = reader.next_block().unwrap().unwrap();
        assert_eq!(idb.offset, 28);
        assert!(matches!(idb.block, PcapngBlock::InterfaceDescription(_)));
        let epb = reader.next_block().unwrap().unwrap();
        assert_eq!(epb.offset, 48);
        assert_eq!(epb.raw.len(), 80);

        // Packet records borrow from the slice and can be held across reads.
        let mut reader = PcapngSliceReader::new(&data).unwrap();
        let first = reader.next_packet_with_offset().unwrap().unwrap();
        let second = reader.next_packet_with_offset().unwrap().unwrap();
        assert_eq!(first.offset, 48);
        assert_eq!(first.raw.len(), 80);
        assert!(matches!(first.packet.data, Cow::Borrowed(_)));
        assert_eq!(first.packet.timestamp, 981144306789012000);
        assert_eq!(first.packet.link_type, LinkType::Ethernet);
        assert_eq!(first.packet.original_length, 46);
        assert_eq!(second.offset, 48 + 80);
        assert_eq!(second.packet.timestamp, 981144306789013000);
        assert!(reader.next_packet().unwrap().is_none());

        // Generic code can still use the CaptureReader trait.
        let mut reader = PcapngSliceReader::new(&data).unwrap();
        assert!(CaptureReader::next_packet(&mut reader).unwrap().is_some());
        assert_eq!(CaptureReader::interfaces(&reader).len(), 1);

        // Truncated captures are reported as errors.
        let mut reader = PcapngSliceReader::new(&data[..data.len() - 1]).unwrap();
        reader.next_packet().unwrap();
        assert!(reader.next_packet().is_err());
    }

    #[test]
    fn pcapng_block_total_length_mismatch() {
        // SHB with a corrupted trailing block total length.
        let data: [u8; 28] = [
            0x0A, 0x0D, 0x0D, 0x0A, // Block Type: Section Header
            0x00, 0x00, 0x00, 0x1C, // Block Total Length: 28
            0x1A, 0x2B, 0x3C, 0x4D, // Byte-Order Magic: big-endian
            0x00, 0x01, // Major Version: 1
            0x00, 0x00, // Minor Version: 0
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Section Length: -1
            0x00, 0x00, 0x00, 0x1D, // Block Total Length: 29 (mismatch)
        ];

        let mut slice_reader = PcapngSliceReader::new(&data).unwrap();
        assert!(slice_reader.next_block().is_err());

        let mut stream_reader = PcapngReader::new(Cursor::new(&data)).unwrap();
        assert!(stream_reader.next_block().is_err());
    }

    #[test]
    fn pcapng_slice_reader_matches_streaming_reader() {
        let data = slice_test_data();

        let mut streaming = PcapngReader::new(Cursor::new(&data)).unwrap();
        let mut streamed = Vec::new();
        while let Some(record) = streaming.next_packet().unwrap() {
            streamed.push(record.to_owned());
        }

        let mut slice = PcapngSliceReader::new(&data).unwrap();
        let mut sliced = Vec::new();
        while let Some(record) = slice.next_packet().unwrap() {
            sliced.push(record);
        }

        assert_eq!(streamed, sliced);
    }

    #[test]
    fn pcapng_slice_reader_survives_truncation() {
        let data = slice_test_data();

        // Every prefix must yield either clean results or an error, never a
        // panic.
        for len in 0..=data.len() {
            if let Ok(mut reader) = PcapngSliceReader::new(&data[..len]) {
                while let Ok(Some(_)) = reader.next_block() {}
            }
        }
    }
}
