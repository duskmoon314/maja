//! Typed payload helpers for TCP SACK options.
//!
//! A SACK option payload is a sequence of eight-byte blocks. Each block carries
//! the left and right edge sequence numbers for a selectively acknowledged byte
//! range.

/// TCP SACK block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSackBlock {
    /// Left edge sequence number.
    pub left_edge: u32,
    /// Right edge sequence number.
    pub right_edge: u32,
}

/// Iterator over TCP SACK blocks.
#[derive(Debug, Clone)]
pub struct TcpSackBlocks<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TcpSackBlocks<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        if !bytes.len().is_multiple_of(8) {
            return None;
        }

        Some(Self { bytes, offset: 0 })
    }
}

impl Iterator for TcpSackBlocks<'_> {
    type Item = TcpSackBlock;

    fn next(&mut self) -> Option<Self::Item> {
        let block = self.bytes.get(self.offset..self.offset + 8)?;
        self.offset += 8;
        Some(TcpSackBlock {
            left_edge: u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
            right_edge: u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
        })
    }
}
