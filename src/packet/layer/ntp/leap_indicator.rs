//! NTP leap indicator values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// NTP leap indicator values from the first octet of an NTP message.
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
pub enum NtpLeapIndicator {
    /// No warning.
    NoWarning = 0,
    /// Last minute has 61 seconds.
    LastMinute61Seconds = 1,
    /// Last minute has 59 seconds.
    LastMinute59Seconds = 2,
    /// Clock is unsynchronized.
    Alarm = 3,
    /// Unknown leap indicator value.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, NtpLeapIndicator, u8);
