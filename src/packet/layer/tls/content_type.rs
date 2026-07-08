//! TLS content type values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// TLS record content type values.
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
pub enum TlsContentType {
    /// Change cipher spec.
    ChangeCipherSpec = 20,
    /// Alert.
    Alert = 21,
    /// Handshake.
    Handshake = 22,
    /// Application data.
    ApplicationData = 23,
    /// Heartbeat.
    Heartbeat = 24,
    /// Unknown content type.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, TlsContentType, u8);
