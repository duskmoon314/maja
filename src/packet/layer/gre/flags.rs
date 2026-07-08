//! GRE flags.

use std::fmt::Display;

use bitflags::bitflags;

use crate::impl_target;

bitflags! {
    /// GRE flags from the first 16-bit GRE header word.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct GreFlags: u16 {
        /// Checksum field is present.
        const CHECKSUM = 0x8000;
        /// Key field is present.
        const KEY = 0x2000;
        /// Sequence number field is present.
        const SEQUENCE = 0x1000;
    }
}

impl From<u16> for GreFlags {
    fn from(value: u16) -> Self {
        Self::from_bits_retain(value)
    }
}

impl From<GreFlags> for u16 {
    fn from(value: GreFlags) -> Self {
        value.bits()
    }
}

impl_target!(frominto, GreFlags, u16);

impl Display for GreFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = Vec::new();
        if self.contains(GreFlags::CHECKSUM) {
            flags.push("CHECKSUM");
        }
        if self.contains(GreFlags::KEY) {
            flags.push("KEY");
        }
        if self.contains(GreFlags::SEQUENCE) {
            flags.push("SEQUENCE");
        }
        write!(f, "{}", flags.join("|"))
    }
}
