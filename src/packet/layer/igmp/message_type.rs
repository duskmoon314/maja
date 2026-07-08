//! IGMP message type registry values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// IGMP message type values.
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
#[repr(u8)]
#[non_exhaustive]
pub enum IgmpType {
    /// Membership query.
    MembershipQuery = 0x11,
    /// IGMPv1 membership report.
    V1MembershipReport = 0x12,
    /// DVMRP.
    Dvmrp = 0x13,
    /// PIM version 1.
    PimV1 = 0x14,
    /// Cisco trace.
    CiscoTrace = 0x15,
    /// IGMPv2 membership report.
    V2MembershipReport = 0x16,
    /// IGMPv2 leave group.
    LeaveGroup = 0x17,
    /// Multicast traceroute response.
    MulticastTracerouteResponse = 0x1e,
    /// Multicast traceroute.
    MulticastTraceroute = 0x1f,
    /// IGMPv3 membership report.
    V3MembershipReport = 0x22,
    /// Multicast router advertisement.
    MulticastRouterAdvertisement = 0x30,
    /// Multicast router solicitation.
    MulticastRouterSolicitation = 0x31,
    /// Multicast router termination.
    MulticastRouterTermination = 0x32,
    /// Unknown message type.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, IgmpType, u8);
