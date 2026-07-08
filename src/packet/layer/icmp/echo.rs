//! ICMPv4 echo request/reply body viewer.

use crate::{
    field_spec,
    packet::utils::field::{FieldMut, FieldRef},
};

pub mod craft;

pub use craft::IcmpEchoBuilder;

field_spec!(IdentifierSpec, u16, u16);
field_spec!(SequenceSpec, u16, u16);

/// Minimum ICMP echo body length after the common ICMP header.
pub(super) const MIN_LEN: usize = 4;

/// ICMPv4 echo request/reply body.
pub struct IcmpEchoViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpEchoViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the identifier: 0..2
    const FIELD_IDENTIFIER: core::ops::Range<usize> = 0..2;
    /// Field range of the sequence number: 2..4
    const FIELD_SEQUENCE: core::ops::Range<usize> = 2..4;

    /// Create a new ICMP echo body viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the echo identifier.
    #[inline]
    pub fn identifier(&self) -> FieldRef<'_, IdentifierSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_IDENTIFIER])
    }

    /// Get the echo sequence number.
    #[inline]
    pub fn sequence(&self) -> FieldRef<'_, SequenceSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SEQUENCE])
    }

    /// Get echo payload bytes.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        if self.data.as_ref().len() <= MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[MIN_LEN..]
        }
    }
}

impl<T> IcmpEchoViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable echo identifier.
    #[inline]
    pub fn identifier_mut(&mut self) -> FieldMut<'_, IdentifierSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_IDENTIFIER])
    }

    /// Get the mutable echo sequence number.
    #[inline]
    pub fn sequence_mut(&mut self) -> FieldMut<'_, SequenceSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SEQUENCE])
    }

    /// Get mutable echo payload bytes.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.data.as_mut();
        if data.len() <= MIN_LEN {
            &mut data[0..0]
        } else {
            &mut data[MIN_LEN..]
        }
    }
}

impl<T> core::fmt::Debug for IcmpEchoViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IcmpEcho")
            .field("identifier", &self.identifier().get())
            .field("sequence", &self.sequence().get())
            .field("payload", &self.payload())
            .finish()
    }
}
