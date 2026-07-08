//! ICMPv6 error body viewer with quoted packet bytes.

use crate::{
    field_spec,
    packet::utils::field::{FieldMut, FieldRef},
};

field_spec!(U32Spec, u32, u32);

/// Minimum quoted-packet body length after the common ICMPv6 header.
pub(super) const MIN_LEN: usize = 4;

/// ICMPv6 error body with the quoted invoking packet.
pub struct Icmpv6QuotedPacketViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6QuotedPacketViewer<T>
where
    T: AsRef<[u8]>,
{
    const FIELD_MESSAGE_SPECIFIC: core::ops::Range<usize> = 0..4;

    /// Create a new ICMPv6 quoted-packet body viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the message-specific 32-bit field.
    #[inline]
    pub fn message_specific(&self) -> FieldRef<'_, U32Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_MESSAGE_SPECIFIC])
    }

    /// Get the MTU field for Packet Too Big messages.
    #[inline]
    pub fn mtu(&self) -> FieldRef<'_, U32Spec> {
        self.message_specific()
    }

    /// Get the pointer field for Parameter Problem messages.
    #[inline]
    pub fn pointer(&self) -> FieldRef<'_, U32Spec> {
        self.message_specific()
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

impl<T> Icmpv6QuotedPacketViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable message-specific 32-bit field.
    #[inline]
    pub fn message_specific_mut(&mut self) -> FieldMut<'_, U32Spec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_MESSAGE_SPECIFIC])
    }
}

impl<T> core::fmt::Debug for Icmpv6QuotedPacketViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Icmpv6QuotedPacket")
            .field("message_specific", &self.message_specific().get())
            .field("quoted_packet", &self.quoted_packet())
            .finish()
    }
}
