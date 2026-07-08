//! Typed payload for the IPv4 Internet Timestamp option.
//!
//! The timestamp option starts with a pointer byte and a combined
//! overflow/flags byte. Entry parsing depends on the flags and can include
//! timestamp-only or address-plus-timestamp records, so this module currently
//! exposes the raw entry bytes plus the computed entry width when known.

/// Decoded IPv4 timestamp option payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4TimestampOption<'a> {
    /// Pointer byte from the option payload.
    pub pointer: u8,
    /// Timestamp overflow count.
    pub overflow: u8,
    /// Timestamp flags.
    pub flags: u8,
    /// Raw timestamp entry bytes.
    pub entries: &'a [u8],
}

impl<'a> Ipv4TimestampOption<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }

        Some(Self {
            pointer: data[0],
            overflow: data[1] >> 4,
            flags: data[1] & 0x0f,
            entries: &data[2..],
        })
    }

    /// Return the expected entry width for the timestamp flags when known.
    pub fn entry_width(&self) -> Option<usize> {
        match self.flags {
            0 => Some(4),
            1 | 3 => Some(8),
            _ => None,
        }
    }
}
