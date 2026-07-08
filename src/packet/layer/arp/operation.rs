//! ARP operation code registry values.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// ARP operation codes from the IANA ARP Parameters registry.
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
#[repr(u16)]
#[non_exhaustive]
pub enum ArpOperation {
    /// Reserved.
    Reserved = 0,
    /// ARP request.
    Request = 1,
    /// ARP reply.
    Reply = 2,
    /// Reverse ARP request.
    RequestReverse = 3,
    /// Reverse ARP reply.
    ReplyReverse = 4,
    /// DRARP request.
    DrarpRequest = 5,
    /// DRARP reply.
    DrarpReply = 6,
    /// DRARP error.
    DrarpError = 7,
    /// InARP request.
    InArpRequest = 8,
    /// InARP reply.
    InArpReply = 9,
    /// ARP NAK.
    ArpNak = 10,
    /// MARS request.
    MarsRequest = 11,
    /// MARS multi.
    MarsMulti = 12,
    /// MARS MServ.
    MarsMServ = 13,
    /// MARS join.
    MarsJoin = 14,
    /// MARS leave.
    MarsLeave = 15,
    /// MARS NAK.
    MarsNak = 16,
    /// MARS unserv.
    MarsUnserv = 17,
    /// MARS SJoin.
    MarsSJoin = 18,
    /// MARS SLeave.
    MarsSLeave = 19,
    /// MARS grouplist request.
    MarsGrouplistRequest = 20,
    /// MARS grouplist reply.
    MarsGrouplistReply = 21,
    /// MARS redirect map.
    MarsRedirectMap = 22,
    /// MAPOS UNARP.
    MaposUnarp = 23,
    /// Experimental operation code 1.
    OpExp1 = 24,
    /// Experimental operation code 2.
    OpExp2 = 25,
    /// Unassigned operation code.
    #[num_enum(catch_all)]
    Unassigned(u16),
}

impl_target!(frominto, ArpOperation, u16);
