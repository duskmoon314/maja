//! DNS opcode registry values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// DNS operation code values.
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
pub enum DnsOpcode {
    /// Standard query.
    Query = 0,
    /// Inverse query.
    InverseQuery = 1,
    /// Server status request.
    Status = 2,
    /// Notify.
    Notify = 4,
    /// Dynamic update.
    Update = 5,
    /// DNS Stateful Operations.
    Dso = 6,
    /// Unknown opcode.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, DnsOpcode, u8);
