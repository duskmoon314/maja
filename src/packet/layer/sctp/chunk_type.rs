//! SCTP chunk type registry values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// SCTP chunk type values.
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
pub enum SctpChunkType {
    /// Payload data.
    Data = 0,
    /// Initiation.
    Init = 1,
    /// Initiation acknowledgement.
    InitAck = 2,
    /// Selective acknowledgement.
    Sack = 3,
    /// Heartbeat request.
    Heartbeat = 4,
    /// Heartbeat acknowledgement.
    HeartbeatAck = 5,
    /// Abort.
    Abort = 6,
    /// Shutdown.
    Shutdown = 7,
    /// Shutdown acknowledgement.
    ShutdownAck = 8,
    /// Operation error.
    Error = 9,
    /// State cookie.
    CookieEcho = 10,
    /// Cookie acknowledgement.
    CookieAck = 11,
    /// Explicit congestion notification echo.
    Ecne = 12,
    /// Congestion window reduced.
    Cwr = 13,
    /// Shutdown complete.
    ShutdownComplete = 14,
    /// Address configuration change.
    AddressConfigurationChange = 0xc1,
    /// Padding.
    Padding = 0x84,
    /// Forward TSN.
    ForwardTsn = 0xc0,
    /// Authentication.
    Authentication = 15,
    /// Unknown chunk type.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, SctpChunkType, u8);
