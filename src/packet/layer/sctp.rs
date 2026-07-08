//! Stream Control Transmission Protocol (SCTP).
//!
//! SCTP starts with a 12-byte common header followed by one or more chunks.
//! Each chunk starts with a 4-byte chunk header: an 8-bit type, 8-bit
//! chunk-specific flags, and a 16-bit length. The chunk value begins after that
//! header. Chunk length includes the chunk header and value, but not the
//! zero padding used to align chunks to a 4-byte boundary. This parser records
//! the SCTP packet as one layer and exposes chunk iteration over the bytes after
//! the common header.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Source Port Number        |   Destination Port Number     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Verification Tag                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           Checksum                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Chunk Type   | Chunk Flags   |         Chunk Length          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Chunk Value                           |
//! ~                              ...                              ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  Padding (optional, 0-3 bytes)                |
//! ~                              ...                              ~
//! ```

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod chunk;
pub mod chunk_type;

pub use chunk::{SctpChunk, SctpChunks};
pub use chunk_type::SctpChunkType;

/// Stream Control Transmission Protocol (SCTP) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Sctp;

impl Sctp {
    /// SCTP common header length.
    const MIN_LEN: usize = 12;
}

impl Protocol for Sctp {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sctp = SctpViewer::new(bytes);

        write!(
            fmt,
            "[Sctp] {:<5} -> {:<5}",
            sctp.src_port().get(),
            sctp.dst_port().get()
        )
    }
}

impl ProtocolExt for Sctp {
    type Viewer<'a> = SctpViewer<&'a [u8]>;
    type ViewerMut<'a> = SctpViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        ctx.require(&Sctp, offset, Sctp::MIN_LEN)?;

        ctx.push_layer(&Sctp, offset, ctx.bytes.len() - offset);

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        SctpViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        SctpViewer::new(bytes)
    }
}

field_spec!(PortSpec, u16, u16);
field_spec!(VerificationTagSpec, u32, u32);
field_spec!(ChecksumSpec, u32, u32);

/// Stream Control Transmission Protocol (SCTP) common header viewer.
pub struct SctpViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> SctpViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the source port: 0..2
    const FIELD_SRC_PORT: core::ops::Range<usize> = 0..2;
    /// Field range of the destination port: 2..4
    const FIELD_DST_PORT: core::ops::Range<usize> = 2..4;
    /// Field range of the verification tag: 4..8
    const FIELD_VERIFICATION_TAG: core::ops::Range<usize> = 4..8;
    /// Field range of the checksum: 8..12
    const FIELD_CHECKSUM: core::ops::Range<usize> = 8..12;

    /// Create a new SCTP viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the source port.
    #[inline]
    pub fn src_port(&self) -> FieldRef<'_, PortSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SRC_PORT])
    }

    /// Get the accessor of the destination port.
    #[inline]
    pub fn dst_port(&self) -> FieldRef<'_, PortSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DST_PORT])
    }

    /// Get the accessor of the verification tag.
    #[inline]
    pub fn verification_tag(&self) -> FieldRef<'_, VerificationTagSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_VERIFICATION_TAG])
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, ChecksumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the raw chunk bytes after the SCTP common header.
    #[inline]
    pub fn chunks(&self) -> &[u8] {
        if self.data.as_ref().len() <= Sctp::MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[Sctp::MIN_LEN..]
        }
    }

    /// Iterate over SCTP chunks.
    #[inline]
    pub fn chunk_iter(&self) -> SctpChunks<'_> {
        SctpChunks::new(self.chunks())
    }
}

impl<T> SctpViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the source port.
    #[inline]
    pub fn src_port_mut(&mut self) -> FieldMut<'_, PortSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SRC_PORT])
    }

    /// Get the mutable accessor of the destination port.
    #[inline]
    pub fn dst_port_mut(&mut self) -> FieldMut<'_, PortSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_DST_PORT])
    }

    /// Get the mutable accessor of the verification tag.
    #[inline]
    pub fn verification_tag_mut(&mut self) -> FieldMut<'_, VerificationTagSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_VERIFICATION_TAG])
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, ChecksumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CHECKSUM])
    }

    /// Get the mutable raw chunk bytes after the SCTP common header.
    #[inline]
    pub fn chunks_mut(&mut self) -> &mut [u8] {
        let data = self.data.as_mut();
        if data.len() <= Sctp::MIN_LEN {
            &mut data[0..0]
        } else {
            &mut data[Sctp::MIN_LEN..]
        }
    }
}

impl<T> core::fmt::Debug for SctpViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sctp")
            .field("src_port", &self.src_port().get())
            .field("dst_port", &self.dst_port().get())
            .field("verification_tag", &self.verification_tag().get())
            .field("checksum", &self.checksum().get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    #[test]
    fn sctp_viewer() {
        let data: [u8; 36] = [
            0x13, 0x88, // source port 5000
            0x13, 0x89, // destination port 5001
            0x01, 0x02, 0x03, 0x04, // verification tag
            0xaa, 0xbb, 0xcc, 0xdd, // checksum
            0x00, // DATA chunk
            0x03, // flags
            0x00, 0x10, // length
            0x00, 0x00, 0x00, 0x01, // TSN
            0x00, 0x02, // stream id
            0x00, 0x03, // stream sequence number
            0x00, 0x00, 0x00, 0x04, // payload protocol identifier
            0x06, // ABORT chunk
            0x00, // flags
            0x00, 0x05, // length
            0xff, // value
            0x00, 0x00, 0x00, // padding
        ];

        let sctp = SctpViewer::new(&data);
        let chunks: Vec<_> = sctp.chunk_iter().collect();

        assert_eq!(sctp.src_port(), 5000);
        assert_eq!(sctp.dst_port(), 5001);
        assert_eq!(sctp.verification_tag(), 0x01020304);
        assert_eq!(sctp.checksum(), 0xaabbccdd);
        assert_eq!(
            chunks[0],
            SctpChunk::Chunk {
                chunk_type: SctpChunkType::Data,
                flags: 0x03,
                len: 16,
                value: &[
                    0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04
                ],
                padding: &[],
            }
        );
        assert_eq!(
            chunks[1],
            SctpChunk::Chunk {
                chunk_type: SctpChunkType::Abort,
                flags: 0,
                len: 5,
                value: &[0xff],
                padding: &[0x00, 0x00, 0x00],
            }
        );
    }

    #[test]
    fn sctp_viewer_mut() {
        let mut data: [u8; 12] = [0; 12];

        let mut sctp = SctpViewer::new(&mut data);
        sctp.src_port_mut().set(5000);
        sctp.dst_port_mut().set(5001);
        sctp.verification_tag_mut().set(0x01020304);
        sctp.checksum_mut().set(0xaabbccdd);

        assert_eq!(
            data,
            [
                0x13, 0x88, 0x13, 0x89, 0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd,
            ]
        );
    }

    #[test]
    fn parse_ethernet_ipv4_sctp_packet() {
        let data: [u8; 50] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // version + ihl
            0x00, // dscp + ecn
            0x00, 0x24, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x84, // protocol: SCTP
            0x00, 0x00, // checksum
            10, 0, 1, 1, // source IP
            10, 0, 1, 2, // destination IP
            0x13, 0x88, // source port 5000
            0x13, 0x89, // destination port 5001
            0x01, 0x02, 0x03, 0x04, // verification tag
            0xaa, 0xbb, 0xcc, 0xdd, // checksum
            0x01, // INIT chunk
            0x00, // flags
            0x00, 0x04, // length
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let sctp = packet.layer_viewer(Sctp).expect("SCTP layer not found");
        assert_eq!(sctp.src_port(), 5000);
        assert_eq!(sctp.dst_port(), 5001);
        assert_eq!(sctp.chunk_iter().count(), 1);
    }
}
