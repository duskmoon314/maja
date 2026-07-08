//! Internet checksum utilities.
//!
//! The Internet checksum is the one's-complement checksum used by IPv4,
//! ICMP, TCP, and UDP. This module only contains byte-oriented helpers; each
//! protocol viewer owns the protocol-specific rules for which bytes are
//! covered and which checksum field must be zeroed before calculation.

use std::{net::Ipv4Addr, ops::Range};

/// Calculate the Internet checksum over a byte slice.
///
/// The input is interpreted as big-endian 16-bit words. If `data` has an odd
/// number of bytes, the last byte is padded with a zero byte for calculation.
/// Callers that calculate a protocol checksum must pass bytes with that
/// protocol's checksum field already set to zero.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;

    add_words(&mut sum, data);

    fold_checksum(sum)
}

/// Calculate the Internet checksum while treating a byte range as zero.
///
/// This is useful for protocol checksum fields. It avoids cloning packet bytes
/// just to temporarily clear the checksum field before calculation.
pub fn internet_checksum_zeroing(data: &[u8], zeroed: Range<usize>) -> u16 {
    let mut sum = 0u32;

    add_words_zeroing(&mut sum, data, zeroed);

    fold_checksum(sum)
}

/// Add big-endian 16-bit words to an accumulated one's-complement sum.
fn add_words(sum: &mut u32, data: &[u8]) {
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        *sum += u32::from(word);
    }
}

/// Add big-endian words while replacing bytes in `zeroed` with zero.
fn add_words_zeroing(sum: &mut u32, data: &[u8], zeroed: Range<usize>) {
    for index in (0..data.len()).step_by(2) {
        let high = if zeroed.contains(&index) {
            0
        } else {
            data[index]
        };
        let low_index = index + 1;
        let low = if low_index < data.len() && !zeroed.contains(&low_index) {
            data[low_index]
        } else {
            0
        };
        *sum += u32::from(u16::from_be_bytes([high, low]));
    }
}

/// Fold an accumulated one's-complement sum into the final 16-bit checksum.
fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Calculate a TCP or UDP checksum using an IPv4 pseudo header.
///
/// `segment` must contain the complete TCP segment or UDP datagram exactly as
/// it will appear after the IPv4 header, with its checksum field set to zero.
/// The caller is responsible for ensuring `segment.len()` fits the IPv4
/// transport length field; packet builders validate this while measuring.
pub fn ipv4_transport_checksum(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, segment: &[u8]) -> u16 {
    let mut sum = 0u32;

    add_words(&mut sum, &src.octets());
    add_words(&mut sum, &dst.octets());
    sum += u32::from(protocol);
    sum += segment.len() as u32;
    add_words(&mut sum, segment);

    fold_checksum(sum)
}

/// Calculate an IPv4 transport checksum while treating a byte range as zero.
///
/// The `zeroed` range is relative to the start of `segment`. TCP and UDP use
/// this to calculate checksums over final packet bytes without allocating a
/// temporary segment copy.
pub fn ipv4_transport_checksum_zeroing(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    segment: &[u8],
    zeroed: Range<usize>,
) -> u16 {
    let mut sum = 0u32;

    add_words(&mut sum, &src.octets());
    add_words(&mut sum, &dst.octets());
    sum += u32::from(protocol);
    sum += segment.len() as u32;
    add_words_zeroing(&mut sum, segment, zeroed);

    fold_checksum(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internet_checksum_pads_odd_length_inputs() {
        assert_eq!(internet_checksum(&[0x12, 0x34, 0x56]), 0x97cb);
    }

    #[test]
    fn internet_checksum_zeroing_treats_range_as_zero() {
        let data = [0x12, 0x34, 0xff, 0xff, 0x56];
        assert_eq!(
            internet_checksum_zeroing(&data, 2..4),
            internet_checksum(&[0x12, 0x34, 0x00, 0x00, 0x56])
        );
    }

    #[test]
    fn ipv4_transport_checksum_includes_pseudo_header() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(192, 0, 2, 2);
        let segment = [
            0x30, 0x39, // source port
            0x00, 0x35, // destination port
            0x00, 0x0a, // UDP length
            0x00, 0x00, // checksum
            b'h', b'i',
        ];

        assert_eq!(ipv4_transport_checksum(src, dst, 17, &segment), 0xe2fe);
    }

    #[test]
    fn ipv4_transport_checksum_zeroing_treats_range_as_zero() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(192, 0, 2, 2);
        let segment = [
            0x30, 0x39, // source port
            0x00, 0x35, // destination port
            0x00, 0x0a, // UDP length
            0xff, 0xff, // checksum to zero
            b'h', b'i',
        ];

        assert_eq!(
            ipv4_transport_checksum_zeroing(src, dst, 17, &segment, 6..8),
            ipv4_transport_checksum(
                src,
                dst,
                17,
                &[0x30, 0x39, 0x00, 0x35, 0x00, 0x0a, 0x00, 0x00, b'h', b'i',]
            )
        );
    }
}
