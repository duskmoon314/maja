//! DHCP operation codes.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// DHCP/BOOTP operation codes.
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
pub enum DhcpOp {
    /// Request from client to server.
    BootRequest = 1,
    /// Reply from server to client.
    BootReply = 2,
    /// Unknown operation.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, DhcpOp, u8);
