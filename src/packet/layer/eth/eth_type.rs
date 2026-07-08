use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// EthType (IEEE 802 Numbers)
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    // num_enum traits
    FromPrimitive,
    IntoPrimitive,
    // strum traits
    AsRefStr,
    Display,
    EnumString,
)]
#[repr(u16)]
#[non_exhaustive]
pub enum EthType {
    /// Internet Protocol version 4 (IPv4)
    Ipv4 = 0x0800,

    /// Address Resolution Protocol (ARP)
    Arp = 0x0806,

    /// Frame Relay ARP
    FrameRelayArp = 0x0808,

    /// Customer VLAN Tag Type
    Vlan = 0x8100,

    /// Novell, Inc
    Novell8137 = 0x8137,
    /// Novell, Inc
    Novell8138 = 0x8138,

    /// Internet Protocol version 6 (IPv6)
    Ipv6 = 0x86DD,

    /// MPLS unicast.
    MplsUnicast = 0x8847,

    /// MPLS multicast.
    MplsMulticast = 0x8848,

    /// Represents any other EthType
    #[num_enum(catch_all)]
    Reserverd(u16),
}

impl_target!(frominto, EthType, u16);

impl From<EthType> for u64 {
    fn from(value: EthType) -> Self {
        u16::from(value).into()
    }
}
