//! VxLAN header flags.
//!
//! The rfc7348bis draft models the first 16 bits of the VxLAN header as a
//! flags field. The I flag remains in the same wire position as RFC 7348: bit
//! 3 of the first octet, represented as `0x0800` in a big-endian 16-bit word.

use bitflags::bitflags;

use crate::impl_target;

bitflags! {
    /// Flags from the first 16 bits of the VxLAN header.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VxlanFlags: u16 {
        /// VNI field is valid.
        const I = 0x0800;
    }
}

impl From<u16> for VxlanFlags {
    fn from(value: u16) -> Self {
        Self::from_bits_retain(value)
    }
}

impl From<VxlanFlags> for u16 {
    fn from(value: VxlanFlags) -> Self {
        value.bits()
    }
}

impl_target!(frominto, VxlanFlags, u16);

impl core::fmt::Display for VxlanFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.contains(Self::I) {
            write!(f, "I")
        } else {
            write!(f, "")
        }
    }
}
