//! ICMPv4 address mask request/reply body viewer.

use core::net::Ipv4Addr;

use crate::{field_spec, packet::utils::field::FieldRef};

field_spec!(IdentifierSpec, u16, u16);
field_spec!(SequenceSpec, u16, u16);
field_spec!(Ipv4AddrSpec, Ipv4Addr, u32);

/// Address-mask body length after the common ICMP header.
pub(super) const MIN_LEN: usize = 8;

/// ICMPv4 address mask request/reply body.
pub struct IcmpAddressMaskViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpAddressMaskViewer<T>
where
    T: AsRef<[u8]>,
{
    const FIELD_IDENTIFIER: core::ops::Range<usize> = 0..2;
    const FIELD_SEQUENCE: core::ops::Range<usize> = 2..4;
    const FIELD_ADDRESS_MASK: core::ops::Range<usize> = 4..8;

    /// Create a new ICMP address-mask body viewer with the given raw data.
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

    /// Get the address mask.
    #[inline]
    pub fn address_mask(&self) -> FieldRef<'_, Ipv4AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ADDRESS_MASK])
    }
}

impl<T> core::fmt::Debug for IcmpAddressMaskViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IcmpAddressMask")
            .field("identifier", &self.identifier().get())
            .field("sequence", &self.sequence().get())
            .field("address_mask", &self.address_mask().get())
            .finish()
    }
}
