//! TCP flags (control bits)

use std::fmt::Display;

use bitflags::bitflags;

use crate::impl_target;

bitflags! {
    /// TCP flags (control bits)
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TcpFlags: u8 {
        /// Congestion Window Reduced.
        const CWR = 0b1000_0000;
        /// ECN-Echo.
        const ECE = 0b0100_0000;
        /// Urgent pointer field is significant.
        const URG = 0b0010_0000;
        /// Acknowledgment field is significant.
        const ACK = 0b0001_0000;
        /// Push function.
        const PSH = 0b0000_1000;
        /// Reset the connection.
        const RST = 0b0000_0100;
        /// Synchronize sequence numbers.
        const SYN = 0b0000_0010;
        /// No more data from sender.
        const FIN = 0b0000_0001;
    }
}

impl From<u8> for TcpFlags {
    fn from(value: u8) -> Self {
        Self::from_bits_retain(value)
    }
}

impl From<TcpFlags> for u8 {
    fn from(value: TcpFlags) -> Self {
        value.bits()
    }
}

impl_target!(frominto, TcpFlags, u8);

impl Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = Vec::new();
        if self.contains(TcpFlags::CWR) {
            flags.push("CWR");
        }
        if self.contains(TcpFlags::ECE) {
            flags.push("ECE");
        }
        if self.contains(TcpFlags::URG) {
            flags.push("URG");
        }
        if self.contains(TcpFlags::ACK) {
            flags.push("ACK");
        }
        if self.contains(TcpFlags::PSH) {
            flags.push("PSH");
        }
        if self.contains(TcpFlags::RST) {
            flags.push("RST");
        }
        if self.contains(TcpFlags::SYN) {
            flags.push("SYN");
        }
        if self.contains(TcpFlags::FIN) {
            flags.push("FIN");
        }
        write!(f, "{}", flags.join("|"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_flags() {
        let flags = TcpFlags::SYN | TcpFlags::ACK;
        assert_eq!(flags, TcpFlags::SYN | TcpFlags::ACK);
        assert_eq!(flags, TcpFlags::from_bits(0b0001_0010).unwrap());
        assert_eq!(flags.bits(), 0b0001_0010);
        assert_eq!(flags.contains(TcpFlags::SYN), true);
        assert_eq!(flags.contains(TcpFlags::ACK), true);
        assert_eq!(flags.contains(TcpFlags::FIN), false);
        assert_eq!(flags.contains(TcpFlags::RST), false);
        assert_eq!(flags.contains(TcpFlags::URG), false);
        assert_eq!(flags.contains(TcpFlags::ECE), false);
        assert_eq!(flags.contains(TcpFlags::CWR), false);
        assert_eq!(flags.contains(TcpFlags::PSH), false);
    }
}
