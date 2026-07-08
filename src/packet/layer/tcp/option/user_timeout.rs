//! Typed payload for the TCP User Timeout option.
//!
//! The user timeout payload is a 16-bit value. The most significant bit is the
//! granularity flag and the remaining bits carry the timeout value.

/// TCP user timeout option values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpUserTimeout {
    /// User timeout granularity flag.
    pub granularity: bool,
    /// User timeout value.
    pub value: u16,
}

impl TcpUserTimeout {
    pub(crate) fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != 2 {
            return None;
        }

        let raw = u16::from_be_bytes([data[0], data[1]]);
        Some(Self {
            granularity: raw & 0x8000 != 0,
            value: raw & 0x7fff,
        })
    }
}
