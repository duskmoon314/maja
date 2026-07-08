//! Typed payload for the TCP Timestamp option.
//!
//! The timestamp option has an eight-byte payload containing TSval and TSecr,
//! both encoded as big-endian 32-bit values.

/// TCP timestamp option values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpTimestamp {
    /// Timestamp value.
    pub tsval: u32,
    /// Timestamp echo reply.
    pub tsecr: u32,
}

impl TcpTimestamp {
    pub(crate) fn parse(data: &[u8]) -> Option<Self> {
        if data.len() != 8 {
            return None;
        }

        Some(Self {
            tsval: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            tsecr: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}
