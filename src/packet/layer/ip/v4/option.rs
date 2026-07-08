//! IPv4 option parsing.
//!
//! IPv4 options are carried after the fixed IPv4 header when IHL is greater
//! than five 32-bit words. Each option starts with a one-byte kind. Kinds `0`
//! and `1` are single-byte End-of-Options and No-Operation markers; every other
//! option uses a kind byte, a total-length byte, and length-specific payload
//! bytes.
//!
//! This module keeps the raw option iterator in one place and delegates
//! registry values and typed option payloads to submodules:
//!
//! - [`kind`] contains on-wire option kind values.
//! - [`route`] decodes RR, LSRR, and SSRR payloads.
//! - [`timestamp`] decodes the Internet Timestamp payload header.
//! - [`traceroute`] decodes the fixed Traceroute payload.

pub mod kind;
pub mod route;
pub mod timestamp;
pub mod traceroute;

pub use kind::Ipv4OptionKind;
pub use route::{Ipv4RouteAddrs, Ipv4RouteOption};
pub use timestamp::Ipv4TimestampOption;
pub use traceroute::Ipv4TracerouteOption;

/// Parsed IPv4 option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4Option<'a> {
    /// End of options list.
    EndOfOptions,
    /// No operation.
    NoOperation,
    /// Option with a kind, length byte, and data bytes after the length.
    Option {
        /// Option kind.
        kind: Ipv4OptionKind,
        /// Full option length, including kind and length bytes.
        len: u8,
        /// Option data after kind and length bytes.
        data: &'a [u8],
    },
    /// Malformed option bytes.
    Malformed {
        /// Raw option kind.
        kind: u8,
        /// Remaining bytes from the malformed option.
        bytes: &'a [u8],
    },
}

impl<'a> Ipv4Option<'a> {
    /// Return the option kind, if the option has one.
    pub fn kind(&self) -> Option<Ipv4OptionKind> {
        match self {
            Self::EndOfOptions => Some(Ipv4OptionKind::EndOfOptions),
            Self::NoOperation => Some(Ipv4OptionKind::NoOperation),
            Self::Option { kind, .. } => Some(*kind),
            Self::Malformed { kind, .. } => Some(Ipv4OptionKind::from(*kind)),
        }
    }

    /// Return the full option length, including kind and length bytes.
    pub fn len(&self) -> Option<u8> {
        match self {
            Self::EndOfOptions | Self::NoOperation => Some(1),
            Self::Option { len, .. } => Some(*len),
            Self::Malformed { .. } => None,
        }
    }

    /// Return whether this option carries no bytes.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::EndOfOptions | Self::NoOperation => true,
            Self::Option { data, .. } => data.is_empty(),
            Self::Malformed { bytes, .. } => bytes.is_empty(),
        }
    }

    /// Return option data bytes after kind and length bytes.
    pub fn data(&self) -> Option<&'a [u8]> {
        match self {
            Self::Option { data, .. } => Some(*data),
            _ => None,
        }
    }

    /// Return a route-style option view for RR, LSRR, or SSRR options.
    pub fn route(&self) -> Option<Ipv4RouteOption<'a>> {
        let Self::Option { kind, data, .. } = self else {
            return None;
        };

        if !matches!(
            kind,
            Ipv4OptionKind::RecordRoute
                | Ipv4OptionKind::LooseSourceRoute
                | Ipv4OptionKind::StrictSourceRoute
        ) {
            return None;
        }

        Ipv4RouteOption::parse(data)
    }

    /// Return an IPv4 timestamp option view.
    pub fn timestamp(&self) -> Option<Ipv4TimestampOption<'a>> {
        let Self::Option { kind, data, .. } = self else {
            return None;
        };

        if *kind != Ipv4OptionKind::Timestamp {
            return None;
        }

        Ipv4TimestampOption::parse(data)
    }

    /// Return the 16-bit router alert value.
    pub fn router_alert(&self) -> Option<u16> {
        self.fixed_u16(Ipv4OptionKind::RouterAlert)
    }

    /// Return the stream identifier value.
    pub fn stream_id(&self) -> Option<u16> {
        self.fixed_u16(Ipv4OptionKind::StreamId)
    }

    /// Return the MTU probe value.
    pub fn mtu_probe(&self) -> Option<u16> {
        self.fixed_u16(Ipv4OptionKind::MtuProbe)
    }

    /// Return the MTU reply value.
    pub fn mtu_reply(&self) -> Option<u16> {
        self.fixed_u16(Ipv4OptionKind::MtuReply)
    }

    /// Return a traceroute option view.
    pub fn traceroute(&self) -> Option<Ipv4TracerouteOption> {
        let Self::Option { kind, data, .. } = self else {
            return None;
        };

        if *kind != Ipv4OptionKind::Traceroute {
            return None;
        }

        Ipv4TracerouteOption::parse(data)
    }

    fn fixed_u16(&self, expected_kind: Ipv4OptionKind) -> Option<u16> {
        let Self::Option { kind, data, .. } = self else {
            return None;
        };

        if *kind == expected_kind && data.len() == 2 {
            Some(u16::from_be_bytes([data[0], data[1]]))
        } else {
            None
        }
    }
}

/// Iterator over IPv4 options.
#[derive(Debug, Clone)]
pub struct Ipv4Options<'a> {
    bytes: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> Ipv4Options<'a> {
    /// Create a new option iterator.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for Ipv4Options<'a> {
    type Item = Ipv4Option<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.bytes.len() {
            return None;
        }

        let start = self.offset;
        let kind = self.bytes[start];

        match kind {
            0 => {
                self.offset += 1;
                self.done = true;
                Some(Ipv4Option::EndOfOptions)
            }
            1 => {
                self.offset += 1;
                Some(Ipv4Option::NoOperation)
            }
            _ => {
                let Some(&len) = self.bytes.get(start + 1) else {
                    self.done = true;
                    return Some(Ipv4Option::Malformed {
                        kind,
                        bytes: &self.bytes[start..],
                    });
                };

                let len = len as usize;
                if len < 2 || start + len > self.bytes.len() {
                    self.done = true;
                    return Some(Ipv4Option::Malformed {
                        kind,
                        bytes: &self.bytes[start..],
                    });
                }

                self.offset += len;
                Some(Ipv4Option::Option {
                    kind: Ipv4OptionKind::from(kind),
                    len: len as u8,
                    data: &self.bytes[start + 2..start + len],
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use super::*;

    #[test]
    fn ipv4_option_typed_helpers() {
        let bytes = [
            0x94, 0x04, 0x00, 0x00, // Router Alert
            0x07, 0x07, 0x04, 192, 0, 2, 1, // Record Route
            0x44, 0x0c, 0x05, 0x00, 0, 0, 0, 1, 0, 0, 0, 2, // Timestamp
            0x52, 0x0c, 0x12, 0x34, 0x00, 0x02, 0x00, 0x01, 198, 51, 100, 9,
            // Traceroute
            0x00, // EOL
        ];

        let options: Vec<_> = Ipv4Options::new(&bytes).collect();

        assert_eq!(options[0].router_alert(), Some(0));

        let route = options[1].route().expect("route option");
        assert_eq!(route.pointer, 4);
        assert_eq!(
            route.addrs().collect::<Vec<_>>(),
            vec![Ipv4Addr::new(192, 0, 2, 1)]
        );
        assert_eq!(route.trailing_bytes(), &[]);

        let timestamp = options[2].timestamp().expect("timestamp option");
        assert_eq!(timestamp.pointer, 5);
        assert_eq!(timestamp.overflow, 0);
        assert_eq!(timestamp.flags, 0);
        assert_eq!(timestamp.entry_width(), Some(4));
        assert_eq!(timestamp.entries, &[0, 0, 0, 1, 0, 0, 0, 2]);

        let traceroute = options[3].traceroute().expect("traceroute option");
        assert_eq!(traceroute.id, 0x1234);
        assert_eq!(traceroute.outbound_hop_count, 2);
        assert_eq!(traceroute.return_hop_count, 1);
        assert_eq!(traceroute.originator_addr, Ipv4Addr::new(198, 51, 100, 9));
    }
}
