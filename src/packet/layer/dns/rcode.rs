//! DNS response code registry values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// DNS response code values from the low 4-bit DNS header field.
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
pub enum DnsRcode {
    /// No error.
    NoError = 0,
    /// Format error.
    FormErr = 1,
    /// Server failure.
    ServFail = 2,
    /// Name error.
    NxDomain = 3,
    /// Not implemented.
    NotImp = 4,
    /// Refused.
    Refused = 5,
    /// Unknown response code.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, DnsRcode, u8);
