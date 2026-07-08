//! ICMPv4 message type registry values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// ICMPv4 message type values.
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
pub enum IcmpType {
    /// Echo reply.
    EchoReply = 0,
    /// Destination unreachable.
    DestinationUnreachable = 3,
    /// Source quench.
    SourceQuench = 4,
    /// Redirect.
    Redirect = 5,
    /// Echo request.
    EchoRequest = 8,
    /// Router advertisement.
    RouterAdvertisement = 9,
    /// Router solicitation.
    RouterSolicitation = 10,
    /// Time exceeded.
    TimeExceeded = 11,
    /// Parameter problem.
    ParameterProblem = 12,
    /// Timestamp request.
    TimestampRequest = 13,
    /// Timestamp reply.
    TimestampReply = 14,
    /// Information request.
    InformationRequest = 15,
    /// Information reply.
    InformationReply = 16,
    /// Address mask request.
    AddressMaskRequest = 17,
    /// Address mask reply.
    AddressMaskReply = 18,
    /// Traceroute.
    Traceroute = 30,
    /// Datagram conversion error.
    DatagramConversionError = 31,
    /// Mobile host redirect.
    MobileHostRedirect = 32,
    /// IPv6 Where-Are-You.
    Ipv6WhereAreYou = 33,
    /// IPv6 I-Am-Here.
    Ipv6IAmHere = 34,
    /// Mobile registration request.
    MobileRegistrationRequest = 35,
    /// Mobile registration reply.
    MobileRegistrationReply = 36,
    /// Domain name request.
    DomainNameRequest = 37,
    /// Domain name reply.
    DomainNameReply = 38,
    /// SKIP.
    Skip = 39,
    /// Photuris.
    Photuris = 40,
    /// Extended echo request.
    ExtendedEchoRequest = 42,
    /// Extended echo reply.
    ExtendedEchoReply = 43,
    /// Unknown message type.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, IcmpType, u8);
