//! TCP option parsing.
//!
//! TCP options appear after the fixed TCP header when the data offset is
//! greater than five 32-bit words. Kinds `0` and `1` are single-byte
//! End-of-Options and No-Operation markers. Other options use a kind byte, a
//! total-length byte, and option-specific payload bytes.
//!
//! This module owns raw option iteration and generic accessors. Supporting
//! submodules hold registry values and typed payload decoders:
//!
//! - [`kind`] contains on-wire option kind values.
//! - [`sack`] decodes SACK block payloads.
//! - [`timestamp`] decodes timestamp option payloads.
//! - [`user_timeout`] decodes the user timeout option payload.

pub mod kind;
pub mod sack;
pub mod timestamp;
pub mod user_timeout;

pub use kind::TcpOptionKind;
pub use sack::{TcpSackBlock, TcpSackBlocks};
pub use timestamp::TcpTimestamp;
pub use user_timeout::TcpUserTimeout;

/// Parsed TCP option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOption<'a> {
    /// End of options list.
    EndOfOptions,
    /// No operation.
    NoOperation,
    /// Option with a kind, length byte, and data bytes after the length.
    Option {
        /// Option kind.
        kind: TcpOptionKind,
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

impl<'a> TcpOption<'a> {
    /// Return the option kind, if the option has one.
    pub fn kind(&self) -> Option<TcpOptionKind> {
        match self {
            Self::EndOfOptions => Some(TcpOptionKind::EndOfOptions),
            Self::NoOperation => Some(TcpOptionKind::NoOperation),
            Self::Option { kind, .. } => Some(*kind),
            Self::Malformed { kind, .. } => Some(TcpOptionKind::from(*kind)),
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

    /// Return the TCP maximum segment size value.
    pub fn maximum_segment_size(&self) -> Option<u16> {
        self.fixed_u16(TcpOptionKind::MaximumSegmentSize)
    }

    /// Return the TCP window scale shift count.
    pub fn window_scale(&self) -> Option<u8> {
        let Self::Option { kind, data, .. } = self else {
            return None;
        };

        if *kind == TcpOptionKind::WindowScale && data.len() == 1 {
            Some(data[0])
        } else {
            None
        }
    }

    /// Return whether this is a valid SACK-permitted option.
    pub fn sack_permitted(&self) -> bool {
        matches!(
            self,
            Self::Option {
                kind: TcpOptionKind::SackPermitted,
                data: [],
                ..
            }
        )
    }

    /// Iterate over SACK blocks carried by a SACK option.
    pub fn sack_blocks(&self) -> Option<TcpSackBlocks<'a>> {
        let Self::Option { kind, data, .. } = self else {
            return None;
        };

        if *kind != TcpOptionKind::Sack {
            return None;
        }

        TcpSackBlocks::parse(data)
    }

    /// Return TCP timestamp option values.
    pub fn timestamp(&self) -> Option<TcpTimestamp> {
        let Self::Option { kind, data, .. } = self else {
            return None;
        };

        if *kind != TcpOptionKind::Timestamp {
            return None;
        }

        TcpTimestamp::parse(data)
    }

    /// Return TCP user timeout option values.
    pub fn user_timeout(&self) -> Option<TcpUserTimeout> {
        let Self::Option { kind, data, .. } = self else {
            return None;
        };

        if *kind != TcpOptionKind::UserTimeout {
            return None;
        }

        TcpUserTimeout::parse(data)
    }

    /// Return raw TCP authentication option bytes.
    pub fn authentication(&self) -> Option<&'a [u8]> {
        self.raw_for_kind(TcpOptionKind::Authentication)
    }

    /// Return raw Multipath TCP option bytes.
    pub fn multipath_tcp(&self) -> Option<&'a [u8]> {
        self.raw_for_kind(TcpOptionKind::MultipathTcp)
    }

    /// Return raw TCP Fast Open cookie bytes.
    pub fn fast_open_cookie(&self) -> Option<&'a [u8]> {
        self.raw_for_kind(TcpOptionKind::FastOpenCookie)
    }

    fn fixed_u16(&self, expected_kind: TcpOptionKind) -> Option<u16> {
        let Self::Option { kind, data, .. } = self else {
            return None;
        };

        if *kind == expected_kind && data.len() == 2 {
            Some(u16::from_be_bytes([data[0], data[1]]))
        } else {
            None
        }
    }

    fn raw_for_kind(&self, expected_kind: TcpOptionKind) -> Option<&'a [u8]> {
        let Self::Option { kind, data, .. } = self else {
            return None;
        };

        if *kind == expected_kind {
            Some(*data)
        } else {
            None
        }
    }
}

/// Iterator over TCP options.
#[derive(Debug, Clone)]
pub struct TcpOptions<'a> {
    bytes: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> TcpOptions<'a> {
    /// Create a new option iterator.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for TcpOptions<'a> {
    type Item = TcpOption<'a>;

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
                Some(TcpOption::EndOfOptions)
            }
            1 => {
                self.offset += 1;
                Some(TcpOption::NoOperation)
            }
            _ => {
                let Some(&len) = self.bytes.get(start + 1) else {
                    self.done = true;
                    return Some(TcpOption::Malformed {
                        kind,
                        bytes: &self.bytes[start..],
                    });
                };

                let len = len as usize;
                if len < 2 || start + len > self.bytes.len() {
                    self.done = true;
                    return Some(TcpOption::Malformed {
                        kind,
                        bytes: &self.bytes[start..],
                    });
                }

                self.offset += len;
                Some(TcpOption::Option {
                    kind: TcpOptionKind::from(kind),
                    len: len as u8,
                    data: &self.bytes[start + 2..start + len],
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_option_typed_helpers() {
        let bytes = [
            0x02, 0x04, 0x05, 0xb4, // MSS
            0x03, 0x03, 0x07, // window scale
            0x04, 0x02, // SACK permitted
            0x05, 0x12, // SACK
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
            0x00, 0x40, 0x08, 0x0a, // timestamp
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x1c, 0x04, 0x80,
            0x2a, // user timeout
            0x22, 0x04, 0xde, 0xad, // fast open cookie
            0x00, // EOL
        ];

        let options: Vec<_> = TcpOptions::new(&bytes).collect();

        assert_eq!(options[0].maximum_segment_size(), Some(1460));
        assert_eq!(options[1].window_scale(), Some(7));
        assert!(options[2].sack_permitted());
        assert_eq!(
            options[3]
                .sack_blocks()
                .expect("sack blocks")
                .collect::<Vec<_>>(),
            vec![
                TcpSackBlock {
                    left_edge: 0x10,
                    right_edge: 0x20,
                },
                TcpSackBlock {
                    left_edge: 0x30,
                    right_edge: 0x40,
                },
            ]
        );
        assert_eq!(
            options[4].timestamp(),
            Some(TcpTimestamp { tsval: 1, tsecr: 2 })
        );
        assert_eq!(
            options[5].user_timeout(),
            Some(TcpUserTimeout {
                granularity: true,
                value: 42
            })
        );
        assert_eq!(options[6].fast_open_cookie(), Some(&[0xde, 0xad][..]));
    }
}
