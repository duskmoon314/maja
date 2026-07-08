//! Universal packet representation for all supported capture formats.

use std::borrow::Cow;

use crate::capture::link_type::LinkType;

/// Packet bytes plus capture metadata.
///
/// This is the common record type returned by capture file readers. It does
/// not parse protocol layers by itself; pass `data` and `link_type` to
/// [`parse_with_link_type`](crate::packet::Packet::parse_with_link_type) when protocol metadata is
/// needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketRecord<'a> {
    /// Timestamp in nanoseconds since the Unix epoch.
    pub timestamp: i64,

    /// Original length of the packet in bytes.
    pub original_length: u32,

    /// Captured packet data.
    pub data: Cow<'a, [u8]>,

    /// Link type of the packet.
    pub link_type: LinkType,
}

impl<'a> PacketRecord<'a> {
    /// Creates a new packet with the given timestamp, original length, data, and link type.
    pub fn new<T: Into<Cow<'a, [u8]>>>(
        timestamp: i64,
        original_length: u32,
        data: T,
        link_type: LinkType,
    ) -> Self {
        Self {
            timestamp,
            original_length,
            data: data.into(),
            link_type,
        }
    }

    /// Get the captured length
    pub fn captured_length(&self) -> usize {
        self.data.len()
    }

    /// Check if the packet is truncated (captured length is less than original length).
    pub fn is_truncated(&self) -> bool {
        self.captured_length() < self.original_length as usize
    }

    /// Get timestamp in seconds
    pub fn timestamp_seconds(&self) -> f64 {
        self.timestamp as f64 / 1_000_000_000.0
    }

    /// Clone packet bytes into an owned `'static` record.
    pub fn to_owned(&self) -> PacketRecord<'static> {
        PacketRecord {
            data: Cow::Owned(self.data.to_vec()),
            ..*self
        }
    }
}

impl PartialOrd for PacketRecord<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PacketRecord<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}
