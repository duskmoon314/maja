//! ICMPv6 message type registry values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// ICMPv6 message type values.
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
pub enum Icmpv6Type {
    /// Destination unreachable.
    DestinationUnreachable = 1,
    /// Packet too big.
    PacketTooBig = 2,
    /// Time exceeded.
    TimeExceeded = 3,
    /// Parameter problem.
    ParameterProblem = 4,
    /// Echo request.
    EchoRequest = 128,
    /// Echo reply.
    EchoReply = 129,
    /// Multicast listener query.
    MulticastListenerQuery = 130,
    /// Multicast listener report.
    MulticastListenerReport = 131,
    /// Multicast listener done.
    MulticastListenerDone = 132,
    /// Router solicitation.
    RouterSolicitation = 133,
    /// Router advertisement.
    RouterAdvertisement = 134,
    /// Neighbor solicitation.
    NeighborSolicitation = 135,
    /// Neighbor advertisement.
    NeighborAdvertisement = 136,
    /// Redirect.
    Redirect = 137,
    /// Router renumbering.
    RouterRenumbering = 138,
    /// Node information query.
    NodeInformationQuery = 139,
    /// Node information response.
    NodeInformationResponse = 140,
    /// Inverse neighbor discovery solicitation.
    InverseNeighborDiscoverySolicitation = 141,
    /// Inverse neighbor discovery advertisement.
    InverseNeighborDiscoveryAdvertisement = 142,
    /// Multicast listener report v2.
    MulticastListenerReportV2 = 143,
    /// Home agent address discovery request.
    HomeAgentAddressDiscoveryRequest = 144,
    /// Home agent address discovery reply.
    HomeAgentAddressDiscoveryReply = 145,
    /// Mobile prefix solicitation.
    MobilePrefixSolicitation = 146,
    /// Mobile prefix advertisement.
    MobilePrefixAdvertisement = 147,
    /// Certification path solicitation.
    CertificationPathSolicitation = 148,
    /// Certification path advertisement.
    CertificationPathAdvertisement = 149,
    /// Unknown message type.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, Icmpv6Type, u8);
