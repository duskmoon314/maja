//! SLL packet type field

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// The packet type field of the SLL header.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    // num_enum
    FromPrimitive,
    IntoPrimitive,
    // strum
    AsRefStr,
    Display,
    EnumString,
)]
#[repr(u16)]
#[non_exhaustive]
pub enum PacketType {
    /// The packet was specifically sent to us.
    SentToUs = 0,
    /// The packet was broadcast by somebody else.
    Broadcast = 1,
    /// The packet was multicast but not broadcast.
    Multicast = 2,
    /// The packet was sent to somebody else by somebody else.
    OtherHost = 3,
    /// The packet was sent by us.
    SentByUs = 4,

    /// Unknown packet type.
    #[num_enum(catch_all)]
    Unknown(u16),
}

impl_target!(frominto, PacketType, u16);
