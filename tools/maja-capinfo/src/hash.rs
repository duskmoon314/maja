use std::{
    cell::RefCell,
    io::{self, Read},
    rc::Rc,
    sync::{
        Arc,
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread::{self, JoinHandle},
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

/// One chunk of the capture, shared by the reader and every hasher.
type Chunk = Arc<[u8]>;

/// How many chunks a hasher may fall behind before the reader blocks.
///
/// A chunk is coalesced up to [`CHUNK_SIZE`], so 4 chunks cap the backlog at
/// 1 MiB per hasher.
const CHANNEL_DEPTH: usize = 4;

/// Bytes the reader gathers before handing a chunk to the hashers.
const CHUNK_SIZE: usize = 256 * 1024;

/// Hash `rx` with `D` on a thread of its own, returning the digest.
fn spawn<D>(name: &str, rx: Receiver<Chunk>) -> JoinHandle<Vec<u8>>
where
    D: Digest + Default,
{
    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let mut hasher = D::default();
            for chunk in rx {
                hasher.update(&chunk);
            }
            hasher.finalize().to_vec()
        })
        .expect("spawn hash worker")
}

/// A reader that feeds every chunk it yields to one hasher thread per algorithm.
#[derive(Debug)]
pub struct HashingReader<R> {
    inner: R,
    senders: Rc<RefCell<Vec<SyncSender<Chunk>>>>,
    staged: Vec<u8>,
}

/// Handle used to retrieve the digests once the capture has been fully read.
pub struct HashHandle {
    senders: Rc<RefCell<Vec<SyncSender<Chunk>>>>,
    workers: Vec<JoinHandle<Vec<u8>>>,
}

impl<R: Read> HashingReader<R> {
    /// Wrap `inner` so that everything read from it is hashed with MD5, SHA-1 and SHA-256.
    ///
    /// Returns the reader together with the [`HashHandle`] used to retrieve the digests.
    pub fn new(inner: R) -> (Self, HashHandle) {
        let mut senders = Vec::with_capacity(3);
        let mut workers = Vec::with_capacity(3);

        for name in ["hash-md5", "hash-sha1", "hash-sha256"] {
            let (tx, rx) = sync_channel(CHANNEL_DEPTH);
            senders.push(tx);
            workers.push(match name {
                "hash-md5" => spawn::<md5::Md5>(name, rx),
                "hash-sha1" => spawn::<sha1::Sha1>(name, rx),
                _ => spawn::<sha2::Sha256>(name, rx),
            });
        }

        let senders = Rc::new(RefCell::new(senders));
        (
            Self {
                inner,
                senders: Rc::clone(&senders),
                staged: Vec::with_capacity(CHUNK_SIZE),
            },
            HashHandle { senders, workers },
        )
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        if read == 0 {
            self.flush()?;
            return Ok(0);
        }

        self.staged.extend_from_slice(&buf[..read]);
        if self.staged.len() >= CHUNK_SIZE {
            self.flush()?;
        }
        Ok(read)
    }
}

impl<R> HashingReader<R> {
    /// Hand the staged bytes to the hashers.
    fn flush(&mut self) -> io::Result<()> {
        if self.staged.is_empty() {
            return Ok(());
        }

        let staged = std::mem::replace(&mut self.staged, Vec::with_capacity(CHUNK_SIZE));
        let chunk: Chunk = Arc::from(staged);
        for sender in self.senders.borrow().iter() {
            sender
                .send(Arc::clone(&chunk))
                .map_err(|_| io::Error::other("a hash worker stopped"))?;
        }
        Ok(())
    }
}

impl HashHandle {
    /// Finalize the hashers and return the hex-encoded digests.
    pub fn finish(self) -> FileHashes {
        // Closing the channels is what ends the hasher loops.
        self.senders.borrow_mut().clear();

        let mut digests = self
            .workers
            .into_iter()
            .map(|worker| worker.join().expect("hash worker panicked"));
        FileHashes {
            md5: to_hex(&digests.next().expect("md5 worker")),
            sha1: to_hex(&digests.next().expect("sha1 worker")),
            sha256: to_hex(&digests.next().expect("sha256 worker")),
        }
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
