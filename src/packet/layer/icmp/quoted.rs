//! ICMPv4 error body viewer with quoted packet bytes.

use crate::{
    field_spec,
    packet::utils::field::{FieldMut, FieldRef},
};

field_spec!(RestOfHeaderSpec, u32, u32);
field_spec!(NextHopMtuSpec, u16, u16);
field_spec!(PointerSpec, u8, u8);

/// Minimum quoted-packet body length after the common ICMP header.
pub(super) const MIN_LEN: usize = 4;

/// ICMPv4 error body with the quoted invoking packet.
pub struct IcmpQuotedPacketViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpQuotedPacketViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of rest-of-header: 0..4
    const FIELD_REST_OF_HEADER: core::ops::Range<usize> = 0..4;
    /// Field range of next-hop MTU for destination-unreachable fragmentation-needed: 2..4
    const FIELD_NEXT_HOP_MTU: core::ops::Range<usize> = 2..4;
    /// Field range of parameter-problem pointer: 0..1
    const FIELD_POINTER: core::ops::Range<usize> = 0..1;

    /// Create a new quoted-packet body viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the 32-bit message-specific field before the quoted packet.
    #[inline]
    pub fn rest_of_header(&self) -> FieldRef<'_, RestOfHeaderSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_REST_OF_HEADER])
    }

    /// Get the next-hop MTU field used by fragmentation-needed messages.
    #[inline]
    pub fn next_hop_mtu(&self) -> FieldRef<'_, NextHopMtuSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_NEXT_HOP_MTU])
    }

    /// Get the parameter-problem pointer byte.
    #[inline]
    pub fn pointer(&self) -> FieldRef<'_, PointerSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_POINTER])
    }

    /// Get the quoted invoking packet bytes.
    #[inline]
    pub fn quoted_packet(&self) -> &[u8] {
        if self.data.as_ref().len() <= MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[MIN_LEN..]
        }
    }
}

impl<T> IcmpQuotedPacketViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable 32-bit message-specific field before the quoted packet.
    #[inline]
    pub fn rest_of_header_mut(&mut self) -> FieldMut<'_, RestOfHeaderSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_REST_OF_HEADER])
    }

    /// Get mutable quoted invoking packet bytes.
    #[inline]
    pub fn quoted_packet_mut(&mut self) -> &mut [u8] {
        let data = self.data.as_mut();
        if data.len() <= MIN_LEN {
            &mut data[0..0]
        } else {
            &mut data[MIN_LEN..]
        }
    }
}

impl<T> core::fmt::Debug for IcmpQuotedPacketViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IcmpQuotedPacket")
            .field("rest_of_header", &self.rest_of_header().get())
            .field("quoted_packet", &self.quoted_packet())
            .finish()
    }
}
