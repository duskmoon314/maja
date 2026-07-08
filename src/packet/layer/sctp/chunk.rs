//! SCTP chunk parsing.

use super::SctpChunkType;

/// Parsed SCTP chunk header and value bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpChunk<'a> {
    /// SCTP chunk with type, flags, declared length, value bytes, and raw padding.
    Chunk {
        /// Chunk type.
        chunk_type: SctpChunkType,
        /// Chunk flags.
        flags: u8,
        /// Declared chunk length, including the 4-byte chunk header.
        len: u16,
        /// Chunk value bytes after the chunk header.
        value: &'a [u8],
        /// Padding bytes after the declared chunk length.
        padding: &'a [u8],
    },
    /// Malformed trailing chunk bytes.
    Malformed {
        /// Remaining malformed bytes.
        bytes: &'a [u8],
    },
}

/// Iterator over SCTP chunks.
#[derive(Debug, Clone)]
pub struct SctpChunks<'a> {
    bytes: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> SctpChunks<'a> {
    /// Create a new SCTP chunk iterator.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for SctpChunks<'a> {
    type Item = SctpChunk<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.bytes.len() {
            return None;
        }

        let start = self.offset;
        let Some(header) = self.bytes.get(start..start + 4) else {
            self.done = true;
            return Some(SctpChunk::Malformed {
                bytes: &self.bytes[start..],
            });
        };

        let chunk_type = SctpChunkType::from(header[0]);
        let flags = header[1];
        let len = u16::from_be_bytes([header[2], header[3]]) as usize;

        if len < 4 || start + len > self.bytes.len() {
            self.done = true;
            return Some(SctpChunk::Malformed {
                bytes: &self.bytes[start..],
            });
        }

        let padded_len = (len + 3) & !3;
        let end = start + len;
        let padded_end = (start + padded_len).min(self.bytes.len());
        self.offset = padded_end;

        Some(SctpChunk::Chunk {
            chunk_type,
            flags,
            len: len as u16,
            value: &self.bytes[start + 4..end],
            padding: &self.bytes[end..padded_end],
        })
    }
}
