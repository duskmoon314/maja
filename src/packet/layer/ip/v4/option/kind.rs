//! IPv4 option kind registry values.
//!
//! The option kind is the full on-wire option type byte. That byte includes
//! the copied flag, option class, and option number from the IPv4 option
//! format, so values such as `Security = 130` and `RouterAlert = 148` are
//! represented directly rather than decomposed here.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// IPv4 option kind values.
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
pub enum Ipv4OptionKind {
    /// End of options list.
    EndOfOptions = 0,
    /// No operation.
    NoOperation = 1,
    /// Security.
    Security = 130,
    /// Loose source and record route.
    LooseSourceRoute = 131,
    /// Internet timestamp.
    Timestamp = 68,
    /// Extended security.
    ExtendedSecurity = 133,
    /// Commercial security.
    CommercialSecurity = 134,
    /// Record route.
    RecordRoute = 7,
    /// Stream identifier.
    StreamId = 136,
    /// Strict source and record route.
    StrictSourceRoute = 137,
    /// Experimental measurement.
    ExperimentalMeasurement = 10,
    /// MTU probe.
    MtuProbe = 11,
    /// MTU reply.
    MtuReply = 12,
    /// Experimental flow control.
    ExperimentalFlowControl = 205,
    /// Experimental access control.
    Visa = 142,
    /// ENCODE.
    Encode = 15,
    /// IMI traffic descriptor.
    ImiTrafficDescriptor = 144,
    /// Extended Internet Protocol.
    ExtendedInternetProtocol = 145,
    /// Traceroute.
    Traceroute = 82,
    /// Address extension.
    AddressExtension = 147,
    /// Router alert.
    RouterAlert = 148,
    /// Selective directed broadcast.
    SelectiveDirectedBroadcast = 149,
    /// Released value 150.
    Released150 = 150,
    /// Dynamic packet state.
    DynamicPacketState = 151,
    /// Upstream multicast packet.
    UpstreamMulticastPacket = 152,
    /// Quick-Start.
    QuickStart = 25,
    /// RFC 3692-style experiment, value 30.
    Rfc3692Experiment30 = 30,
    /// RFC 3692-style experiment, value 94.
    Rfc3692Experiment94 = 94,
    /// RFC 3692-style experiment, value 158.
    Rfc3692Experiment158 = 158,
    /// RFC 3692-style experiment, value 222.
    Rfc3692Experiment222 = 222,
    /// Unknown option kind.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, Ipv4OptionKind, u8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_option_kind_values_use_wire_type() {
        assert_eq!(u8::from(Ipv4OptionKind::Security), 130);
        assert_eq!(u8::from(Ipv4OptionKind::LooseSourceRoute), 131);
        assert_eq!(u8::from(Ipv4OptionKind::Timestamp), 68);
        assert_eq!(u8::from(Ipv4OptionKind::StrictSourceRoute), 137);
        assert_eq!(u8::from(Ipv4OptionKind::Traceroute), 82);
        assert_eq!(u8::from(Ipv4OptionKind::RouterAlert), 148);
    }
}
