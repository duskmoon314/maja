//! VxLAN Network Identifier.
//!
//! The VNI is a 24-bit identifier. It is represented as a newtype so setters
//! cannot accidentally write values outside the wire field width.

use crate::packet::utils::field::Target;

/// VxLAN Network Identifier (VNI).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VxlanVni(u32);

impl VxlanVni {
    /// Largest value representable in the 24-bit VNI field.
    pub const MAX: u32 = 0x00ff_ffff;

    /// Create a VNI when `value` fits in 24 bits.
    pub const fn new(value: u32) -> Option<Self> {
        if value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Return the numeric VNI value as `u32`.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<VxlanVni> for u32 {
    fn from(value: VxlanVni) -> Self {
        value.0
    }
}

impl TryFrom<u32> for VxlanVni {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(value)
    }
}

impl Target<[u8; 3]> for VxlanVni {
    fn from_underlay(x: [u8; 3]) -> Self {
        Self(u32::from_be_bytes([0, x[0], x[1], x[2]]))
    }

    fn into_underlay(self) -> [u8; 3] {
        let bytes = self.0.to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }
}

impl core::fmt::Display for VxlanVni {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
