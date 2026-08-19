use std::{
    cell::RefCell,
    io::{self, Read},
    rc::Rc,
};

use base16ct::lower::encode_string as to_hex;
use serde::Serialize;
use sha2::Digest;

/// Hex-encoded digests of a capture file, computed while it is being read.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Hashers driven in lockstep, shared between [`HashingReader`] and [`HashHandle`].
#[derive(Debug, Default)]
struct MultiHasher {
    md5: md5::Md5,
    sha1: sha1::Sha1,
    sha256: sha2::Sha256,
}

impl MultiHasher {
    fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        self.sha1.update(data);
        self.sha256.update(data);
    }

    fn finalize(self) -> FileHashes {
        FileHashes {
            md5: to_hex(&self.md5.finalize()),
            sha1: to_hex(&self.sha1.finalize()),
            sha256: to_hex(&self.sha256.finalize()),
        }
    }
}

/// A reader that feeds every byte it yields into the shared [`MultiHasher`].
#[derive(Debug)]
pub struct HashingReader<R> {
    inner: R,
    shared: Rc<RefCell<MultiHasher>>,
}

/// Handle used to retrieve the digests once the capture has been fully read.
pub struct HashHandle {
    shared: Rc<RefCell<MultiHasher>>,
}

impl<R: Read> HashingReader<R> {
    /// Wrap `inner` so that everything read from it is hashed with MD5, SHA-1 and SHA-256.
    ///
    /// Returns the reader together with the [`HashHandle`] used to retrieve the digests.
    pub fn new(inner: R) -> (Self, HashHandle) {
        let shared = Rc::new(RefCell::new(MultiHasher::default()));
        (
            Self {
                inner,
                shared: Rc::clone(&shared),
            },
            HashHandle { shared },
        )
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.shared.borrow_mut().update(&buf[..read]);
        Ok(read)
    }
}

impl HashHandle {
    /// Finalize the hashers and return the hex-encoded digests.
    pub fn finish(self) -> FileHashes {
        self.shared.replace(MultiHasher::default()).finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reader that never returns more than `chunk` bytes per call, to exercise
    /// partial reads through the hashing wrapper.
    struct Chunked<'a> {
        data: &'a [u8],
        chunk: usize,
    }

    impl Read for Chunked<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let amount = self.chunk.min(self.data.len()).min(buf.len());
            buf[..amount].copy_from_slice(&self.data[..amount]);
            self.data = &self.data[amount..];
            Ok(amount)
        }
    }

    fn hashes_of(data: &[u8], chunk: usize) -> FileHashes {
        let (mut reader, handle) = HashingReader::new(Chunked { data, chunk });
        let mut sink = Vec::new();
        reader.read_to_end(&mut sink).unwrap();
        assert_eq!(sink, data);
        handle.finish()
    }

    #[test]
    fn empty_input_matches_known_digests() {
        assert_eq!(
            hashes_of(b"", 4),
            FileHashes {
                md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
            }
        );
    }

    #[test]
    fn abc_matches_known_digests_regardless_of_chunking() {
        let expected = FileHashes {
            md5: "900150983cd24fb0d6963f7d28e17f72".to_string(),
            sha1: "a9993e364706816aba3e25717850c26c9cd0d89d".to_string(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
        };

        for chunk in [1, 2, 3, 16] {
            assert_eq!(hashes_of(b"abc", chunk), expected);
        }
    }
}
