//! IPv6 option parsing
//! ([RFC 8200 section 4.2](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.2)).
//!
//! The Hop-by-Hop Options and Destination Options headers carry type-length-value
//! options behind their fixed two-octet prefix. Pad1 is a single zero octet; every
//! other option is a type octet, a length octet counting the option data, and that
//! many data octets.
//!
//! The two high-order bits of the type give the action for an unknown option, the
//! third bit says whether the data may change en route. [`kind`] holds the
//! registered type values.
//!
//! ```text
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
//! |  Option Type  |  Opt Data Len |  Option Data
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
//! ```

pub mod kind;

pub use kind::Ipv6OptionKind;

/// Parsed IPv6 option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Option<'a> {
    /// Pad1: a single zero octet.
    Pad1,
    /// Option with a type and a data part of zero or more octets.
    Option {
        /// Option type.
        kind: Ipv6OptionKind,
        /// Option data; its wire length is the option length field.
        data: &'a [u8],
    },
    /// Option whose declared length runs past the option area.
    Malformed {
        /// Raw option type.
        kind: u8,
        /// Remaining bytes from the malformed option.
        bytes: &'a [u8],
    },
}

impl<'a> Ipv6Option<'a> {
    /// Get the kind of this option.
    #[inline]
    pub fn kind(&self) -> Ipv6OptionKind {
        match self {
            Self::Pad1 => Ipv6OptionKind::Pad1,
            Self::Option { kind, .. } => *kind,
            Self::Malformed { kind, .. } => Ipv6OptionKind::from(*kind),
        }
    }

    /// Return the option data octets, `None` for Pad1 and a truncated option.
    #[inline]
    pub fn data(&self) -> Option<&'a [u8]> {
        match self {
            Self::Option { data, .. } => Some(data),
            _ => None,
        }
    }
}

/// Iterator over IPv6 options.
#[derive(Debug, Clone)]
pub struct Ipv6Options<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Ipv6Options<'a> {
    /// Create a new option iterator.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl<'a> Iterator for Ipv6Options<'a> {
    type Item = Ipv6Option<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        let start = self.offset;
        let kind = self.bytes[start];

        // Pad1 is a single octet.
        if kind == 0 {
            self.offset += 1;
            return Some(Ipv6Option::Pad1);
        }

        let Some(&len) = self.bytes.get(start + 1) else {
            self.offset = self.bytes.len(); // stop after this malformed option
            return Some(Ipv6Option::Malformed {
                kind,
                bytes: &self.bytes[start..],
            });
        };

        let end = start + 2 + len as usize;
        if end > self.bytes.len() {
            self.offset = self.bytes.len(); // stop after this malformed option
            return Some(Ipv6Option::Malformed {
                kind,
                bytes: &self.bytes[start..],
            });
        }

        self.offset = end;

        Some(Ipv6Option::Option {
            kind: Ipv6OptionKind::from(kind),
            data: &self.bytes[start + 2..end],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_options_report_malformed_bytes() {
        // A length byte that runs past the end of the option area, and an
        // option that ends before its length byte.
        let bytes = [0x05, 0x04, 0x00, 0x05];
        let options: Vec<_> = Ipv6Options::new(&bytes).collect();

        assert_eq!(options.len(), 1);
        assert_eq!(options[0].kind(), Ipv6OptionKind::RouterAlert);
        assert_eq!(options[0].data(), None);
        assert_eq!(
            options[0],
            Ipv6Option::Malformed {
                kind: 5,
                bytes: &[0x05, 0x04, 0x00, 0x05],
            }
        );

        let options: Vec<_> = Ipv6Options::new(&[0x05]).collect();
        assert_eq!(options.len(), 1);
        assert_eq!(
            options[0],
            Ipv6Option::Malformed {
                kind: 5,
                bytes: &[0x05],
            }
        );
    }
}
