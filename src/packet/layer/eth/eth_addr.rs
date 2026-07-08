use std::{fmt::Display, str::FromStr};

use crate::impl_target;

/// Ethernet MAC address
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EthAddr {
    octets: [u8; 6],
}

impl EthAddr {
    /// Create a new `EthAddr` from octets
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self {
            octets: [a, b, c, d, e, f],
        }
    }

    /// Create a new `EthAddr` from a slice
    ///
    /// # Panics
    ///
    /// Panics if the slice is not 6 bytes long
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut octets = [0; 6];
        octets.copy_from_slice(slice);
        Self { octets }
    }
}

impl Display for EthAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5]
        )
    }
}

impl AsRef<[u8]> for EthAddr {
    fn as_ref(&self) -> &[u8] {
        &self.octets
    }
}

impl From<[u8; 6]> for EthAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self { octets }
    }
}

impl From<EthAddr> for [u8; 6] {
    fn from(addr: EthAddr) -> Self {
        addr.octets
    }
}

impl TryFrom<&[u8]> for EthAddr {
    type Error = EthAddrError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 6 {
            return Err(EthAddrError::InvalidLength(value.len()));
        }
        Ok(Self::from_slice(value))
    }
}

impl From<EthAddr> for u64 {
    fn from(addr: EthAddr) -> Self {
        u64::from_be_bytes([
            0,
            0,
            addr.octets[0],
            addr.octets[1],
            addr.octets[2],
            addr.octets[3],
            addr.octets[4],
            addr.octets[5],
        ])
    }
}

impl_target!(frominto, EthAddr, [u8; 6]);

/// `EthAddr` can be parsed from a string in the format "XX:XX:XX:XX:XX:XX"
impl FromStr for EthAddr {
    type Err = EthAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let octets = s
            .split(':')
            .map(|hex| u8::from_str_radix(hex, 16))
            .collect::<Result<Vec<_>, _>>()?;
        if octets.len() != 6 {
            return Err(EthAddrError::InvalidLength(octets.len()));
        }
        Ok(Self::new(
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        ))
    }
}

/// Create an `EthAddr` from a literal, expression, or octets
#[macro_export]
macro_rules! eth_addr {
    ($l: literal) => {
        $l.parse::<$crate::packet::layer::eth::EthAddr>().expect("Invalid EthAddr")
    };

    ($e:expr) => {
        $crate::packet::layer::eth::EthAddr::from($e)
    };

    ($($octet:expr),*) => {
        $crate::packet::layer::eth::EthAddr::new($($octet),*)
    };
}

/// Error type for `EthAddr`
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EthAddrError {
    /// Invalid length
    #[error("Invalide EthAddr length: Length must be 6, got {0}")]
    InvalidLength(usize),

    /// Invalid character
    #[error("Invalid EthAddr character: {0}")]
    ParseInt(#[from] core::num::ParseIntError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eth_addr() {
        assert_eq!(
            "01:23:45:67:89:AB".parse::<EthAddr>().unwrap(),
            EthAddr::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB)
        );

        assert_eq!(
            "01:23:45:67:89".parse::<EthAddr>(),
            Err(EthAddrError::InvalidLength(5))
        );

        assert_eq!(
            "01:23:45:67:89:AB:CD".parse::<EthAddr>(),
            Err(EthAddrError::InvalidLength(7))
        );
    }

    #[test]
    fn eth_addr_macro() {
        let addr = eth_addr!("01:23:45:67:89:AB");
        assert_eq!(addr, EthAddr::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));

        let addr = eth_addr!([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]);
        assert_eq!(addr, EthAddr::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));

        let addr = eth_addr!(1, 35, 69, 103, 137, 171);
        assert_eq!(addr, EthAddr::new(1, 35, 69, 103, 137, 171));
    }

    #[test]
    fn eth_addr_display() {
        let addr = EthAddr::new(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB);
        assert_eq!(addr.to_string(), "01:23:45:67:89:AB");
    }
}
