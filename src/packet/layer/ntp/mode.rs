//! NTP mode values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// NTP mode values from the first octet of an NTP message.
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
pub enum NtpMode {
    /// Reserved.
    Reserved = 0,
    /// Symmetric active.
    SymmetricActive = 1,
    /// Symmetric passive.
    SymmetricPassive = 2,
    /// Client.
    Client = 3,
    /// Server.
    Server = 4,
    /// Broadcast.
    Broadcast = 5,
    /// NTP control message.
    NtpControlMessage = 6,
    /// Private use.
    PrivateUse = 7,
    /// Unknown mode value.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, NtpMode, u8);
