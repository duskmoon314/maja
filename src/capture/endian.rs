//! Endianness helpers for binary capture headers.

/// Byte order used to decode integer fields in capture headers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    /// Network/big-endian byte order.
    #[default]
    Big,
    /// Little-endian byte order.
    Little,
}

impl Endian {
    /// Return whether this value represents big-endian byte order.
    pub fn is_big(self) -> bool {
        self == Self::Big
    }

    /// Read a `u16` from the first two bytes using this byte order.
    pub fn read_u16(self, bytes: &[u8]) -> u16 {
        let bytes = [bytes[0], bytes[1]];
        match self {
            Self::Big => u16::from_be_bytes(bytes),
            Self::Little => u16::from_le_bytes(bytes),
        }
    }

    /// Read an `i32` from the first four bytes using this byte order.
    pub fn read_i32(self, bytes: &[u8]) -> i32 {
        let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Big => i32::from_be_bytes(bytes),
            Self::Little => i32::from_le_bytes(bytes),
        }
    }

    /// Read a `u32` from the first four bytes using this byte order.
    pub fn read_u32(self, bytes: &[u8]) -> u32 {
        let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Big => u32::from_be_bytes(bytes),
            Self::Little => u32::from_le_bytes(bytes),
        }
    }

    /// Read an `i64` from the first eight bytes using this byte order.
    pub fn read_i64(self, bytes: &[u8]) -> i64 {
        let bytes = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];
        match self {
            Self::Big => i64::from_be_bytes(bytes),
            Self::Little => i64::from_le_bytes(bytes),
        }
    }

    /// Read a `u64` from the first eight bytes using this byte order.
    pub fn read_u64(self, bytes: &[u8]) -> u64 {
        let bytes = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];
        match self {
            Self::Big => u64::from_be_bytes(bytes),
            Self::Little => u64::from_le_bytes(bytes),
        }
    }
}
