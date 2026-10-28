//! IPv6 option type registry values.
//!
//! The option type is the full on-wire type byte of the Destination Options and
//! Hop-by-Hop Options headers.
//! [RFC 8200 section 4.2](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.2) gives
//! the high-order three bits a meaning (two action bits and one changeable bit) and
//! leaves the remaining five bits to complete the registered type value, so values
//! such as `JumboPayload = 194` and `HomeAddress = 201` are represented directly
//! rather than decomposed here.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// IPv6 option type values.
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
pub enum Ipv6OptionKind {
    /// Pad1.
    Pad1 = 0,
    /// PadN.
    PadN = 1,
    /// Tunnel Encapsulation Limit.
    TunnelEncapsulationLimit = 4,
    /// Router Alert.
    RouterAlert = 5,
    /// CALIPSO.
    Calipso = 7,
    /// SMF_DPD.
    SmfDpd = 8,
    /// Performance and Diagnostic Metrics.
    PerformanceDiagnosticMetrics = 15,
    /// AltMark.
    AltMark = 18,
    /// RPL Option.
    Rpl = 35,
    /// Quick-Start.
    QuickStart = 38,
    /// Minimum Path MTU Hop-by-Hop Option.
    MinimumPathMtu = 48,
    /// MPL Option.
    Mpl = 109,
    /// Endpoint Identification.
    EndpointIdentification = 138,
    /// ILNP Nonce.
    IlnpNonce = 139,
    /// Line-Identification Option.
    LineIdentification = 140,
    /// Jumbo Payload.
    JumboPayload = 194,
    /// Home Address.
    HomeAddress = 201,
    /// IP_DFF.
    IpDff = 238,
    /// Unknown option type.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, Ipv6OptionKind, u8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_option_kind_values_use_wire_type() {
        assert_eq!(u8::from(Ipv6OptionKind::Pad1), 0);
        assert_eq!(u8::from(Ipv6OptionKind::PadN), 1);
        assert_eq!(u8::from(Ipv6OptionKind::TunnelEncapsulationLimit), 4);
        assert_eq!(u8::from(Ipv6OptionKind::RouterAlert), 5);
        assert_eq!(u8::from(Ipv6OptionKind::Rpl), 35);
        assert_eq!(u8::from(Ipv6OptionKind::JumboPayload), 194);
        assert_eq!(u8::from(Ipv6OptionKind::HomeAddress), 201);
        assert_eq!(u8::from(Ipv6OptionKind::Unknown(0xff)), 0xff);
    }
}
