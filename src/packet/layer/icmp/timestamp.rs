//! ICMPv4 timestamp request/reply body viewer.

use crate::{
    field_spec,
    packet::utils::field::{FieldMut, FieldRef},
};

field_spec!(IdentifierSpec, u16, u16);
field_spec!(SequenceSpec, u16, u16);
field_spec!(TimestampSpec, u32, u32);

/// Timestamp body length after the common ICMP header.
pub(super) const MIN_LEN: usize = 16;

/// ICMPv4 timestamp request/reply body.
pub struct IcmpTimestampViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpTimestampViewer<T>
where
    T: AsRef<[u8]>,
{
    const FIELD_IDENTIFIER: core::ops::Range<usize> = 0..2;
    const FIELD_SEQUENCE: core::ops::Range<usize> = 2..4;
    const FIELD_ORIGINATE: core::ops::Range<usize> = 4..8;
    const FIELD_RECEIVE: core::ops::Range<usize> = 8..12;
    const FIELD_TRANSMIT: core::ops::Range<usize> = 12..16;

    /// Create a new ICMP timestamp body viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the identifier.
    #[inline]
    pub fn identifier(&self) -> FieldRef<'_, IdentifierSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_IDENTIFIER])
    }

    /// Get the sequence number.
    #[inline]
    pub fn sequence(&self) -> FieldRef<'_, SequenceSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SEQUENCE])
    }

    /// Get the originate timestamp.
    #[inline]
    pub fn originate_timestamp(&self) -> FieldRef<'_, TimestampSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ORIGINATE])
    }

    /// Get the receive timestamp.
    #[inline]
    pub fn receive_timestamp(&self) -> FieldRef<'_, TimestampSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RECEIVE])
    }

    /// Get the transmit timestamp.
    #[inline]
    pub fn transmit_timestamp(&self) -> FieldRef<'_, TimestampSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TRANSMIT])
    }
}

impl<T> IcmpTimestampViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable originate timestamp.
    #[inline]
    pub fn originate_timestamp_mut(&mut self) -> FieldMut<'_, TimestampSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ORIGINATE])
    }
}

impl<T> core::fmt::Debug for IcmpTimestampViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IcmpTimestamp")
            .field("identifier", &self.identifier().get())
            .field("sequence", &self.sequence().get())
            .field("originate_timestamp", &self.originate_timestamp().get())
            .field("receive_timestamp", &self.receive_timestamp().get())
            .field("transmit_timestamp", &self.transmit_timestamp().get())
            .finish()
    }
}
