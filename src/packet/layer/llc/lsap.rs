use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// LSAP (Link Service Access Point)
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
pub enum Lsap {
    /// SNAP Extension
    Snap = 0xAA,

    /// Unsupported yet
    #[num_enum(catch_all)]
    Unsupported(u8),
}

impl_target!(frominto, Lsap, u8);
