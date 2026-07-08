//! Typed payloads for IPv4 route-style options.
//!
//! Record Route, Loose Source and Record Route, and Strict Source and Record
//! Route share the same option payload shape: one pointer byte followed by a
//! sequence of IPv4 addresses. This module keeps that common decoder separate
//! from the raw option iterator.

use core::net::Ipv4Addr;

/// Decoded route-style IPv4 option payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4RouteOption<'a> {
    /// Pointer byte from the option payload.
    pub pointer: u8,
    addrs: &'a [u8],
}

impl<'a> Ipv4RouteOption<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        Some(Self {
            pointer: data[0],
            addrs: &data[1..],
        })
    }

    /// Iterate over complete IPv4 addresses carried by this option.
    pub fn addrs(&self) -> Ipv4RouteAddrs<'a> {
        Ipv4RouteAddrs {
            bytes: self.addrs,
            offset: 0,
        }
    }

    /// Return trailing bytes that do not form a complete IPv4 address.
    pub fn trailing_bytes(&self) -> &'a [u8] {
        let remainder = self.addrs.len() % 4;
        if remainder == 0 {
            &self.addrs[0..0]
        } else {
            &self.addrs[self.addrs.len() - remainder..]
        }
    }
}

/// Iterator over IPv4 addresses in route-style options.
#[derive(Debug, Clone)]
pub struct Ipv4RouteAddrs<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for Ipv4RouteAddrs<'_> {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        let addr = self.bytes.get(self.offset..self.offset + 4)?;
        self.offset += 4;
        Some(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
    }
}
