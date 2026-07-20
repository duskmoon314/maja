//! Capture interface metadata.
//!
//! Interfaces describe the link type, capture truncation length, and timestamp
//! precision used by packets read from a capture file.

use std::fmt::Display;

use crate::capture::link_type::LinkType;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
/// Link-layer and timestamp metadata for a capture interface.
pub struct Interface {
    /// Link-layer type used by packets captured on this interface.
    pub link_type: LinkType,
    /// Maximum captured packet length in octets.
    pub snap_len: u32,
    /// Timestamp resolution used by packets on this interface.
    pub resolution: Resolution,
}

/// # Resolution of the timestamp
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Resolution {
    /// Timestamp units are `2^-n` seconds.
    PowerOfTwo(u8),
    /// Timestamp units are `10^-n` seconds.
    PowerOfTen(u8),
}

impl Display for Resolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Resolution::PowerOfTwo(exp) => write!(f, "2^-{}s", exp),
            Resolution::PowerOfTen(6) => write!(f, "10^-6s (microseconds)"),
            Resolution::PowerOfTen(9) => write!(f, "10^-9s (nanoseconds)"),
            Resolution::PowerOfTen(exp) => write!(f, "10^-{}s", exp),
        }
    }
}
