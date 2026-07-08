//! Typed payload for the IPv4 Traceroute option.
//!
//! The traceroute option has a fixed ten-byte payload after the kind and
//! length bytes: identifier, outbound hop count, return hop count, and the
//! originator IPv4 address.

use core::net::Ipv4Addr;

/// Decoded IPv4 traceroute option payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4TracerouteOption {
    /// Traceroute identifier.
    pub id: u16,
    /// Outbound hop count.
    pub outbound_hop_count: u16,
    /// Return hop count.
    pub return_hop_count: u16,
    /// Originator IPv4 address.
    pub originator_addr: Ipv4Addr,
}

impl Ipv4TracerouteOption {
    pub(crate) fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != 10 {
            return None;
        }

        Some(Self {
            id: u16::from_be_bytes([data[0], data[1]]),
            outbound_hop_count: u16::from_be_bytes([data[2], data[3]]),
            return_hop_count: u16::from_be_bytes([data[4], data[5]]),
            originator_addr: Ipv4Addr::new(data[6], data[7], data[8], data[9]),
        })
    }
}
