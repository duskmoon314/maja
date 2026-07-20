//! Link-layer header types.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    // num_enum
    FromPrimitive,
    IntoPrimitive,
    // strum
    AsRefStr,
    Display,
    EnumString,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[repr(u16)]
#[non_exhaustive]
/// Link-layer header type values used by PCAP and PCAPNG.
///
/// Values follow the tcpdump.org `LINKTYPE_*` registry. The enum includes the
/// link types currently parsed by maja and preserves unsupported values through
/// [`Unknown`](LinkType::Unknown).
pub enum LinkType {
    /// BSD loopback encapsulation (LINKTYPE_NULL)
    #[strum(serialize = "NULL")]
    Null = 0,

    /// IEEE 802.3 Ethernet (LINKTYPE_ETHERNET)
    #[strum(serialize = "Ethernet", serialize = "EN10MB")]
    Ethernet = 1,

    /// Experimental Ethernet (3Mb) (LINKTYPE_EXP_ETHERNET)
    #[strum(serialize = "EN3MB")]
    ExpEthernet = 2,

    /// AX.25 packet (LINKTYPE_AX25)
    #[strum(serialize = "AX25")]
    Ax25 = 3,

    /// IEEE 802.5 Token Ring (LINKTYPE_TOKEN_RING)
    #[strum(serialize = "IEEE802")]
    TokenRing = 6,

    /// ARCNET Data Packets (LINKTYPE_ARCNET)
    #[strum(serialize = "ARCNET_BSD")]
    Arcnet = 7,

    /// SLIP (LINKTYPE_SLIP)
    #[strum(serialize = "SLIP")]
    Slip = 8,

    /// PPP (LINKTYPE_PPP)
    #[strum(serialize = "PPP")]
    Ppp = 9,

    /// FDDI (LINKTYPE_FDDI)
    #[strum(serialize = "FDDI")]
    Fddi = 10,

    /// Raw IP packets (LINKTYPE_RAW)
    #[strum(serialize = "RAW")]
    Raw = 101,

    /// IEEE 802.11 wireless LAN (LINKTYPE_IEEE802_11)
    #[strum(serialize = "IEEE802_11")]
    Ieee80211 = 105,

    /// Linux cooked capture v1 (LINKTYPE_LINUX_SLL)
    #[strum(serialize = "LINUX_SLL")]
    LinuxSll = 113,

    /// Prism monitor mode (LINKTYPE_PRISM_HEADER)
    #[strum(serialize = "PRISM_HEADER")]
    PrismHeader = 119,

    /// Aironet header (LINKTYPE_AIRONET_HEADER)
    #[strum(serialize = "AIRONET_HEADER")]
    AironetHeader = 120,

    /// Radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)
    #[strum(serialize = "IEEE802_11_RADIOTAP")]
    Ieee80211Radiotap = 127,

    /// IPv4 packets with no link-layer header (LINKTYPE_IPV4)
    #[strum(serialize = "IPV4")]
    Ipv4 = 228,

    /// IPv6 packets with no link-layer header (LINKTYPE_IPV6)
    #[strum(serialize = "IPV6")]
    Ipv6 = 229,

    /// Linux cooked capture v2 (LINKTYPE_LINUX_SLL2)
    #[strum(serialize = "LINUX_SLL2")]
    LinuxSll2 = 276,

    /// Unknown or unsupported link type with raw value.
    #[num_enum(catch_all)]
    Unknown(u16),
}

#[allow(clippy::derivable_impls)]
impl Default for LinkType {
    fn default() -> Self {
        LinkType::Ethernet
    }
}
