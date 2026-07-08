//! Multiprotocol Label Switching (MPLS).
//!
//! MPLS packets carry a stack of 32-bit label entries. Each entry contains the
//! label, traffic class, bottom-of-stack bit, and TTL. The parser records the
//! complete label stack as one layer, then guesses IPv4 or IPv6 payloads from
//! the first nibble after the bottom-of-stack entry.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                Label                  | TC  |S|      TTL      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            Additional label entries if S == 0                 |
//! ~                              ...                              ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Payload                            |
//! ~                              ...                              ~
//! ```

use crate::packet::{
    ParseContext,
    layer::{Protocol, ProtocolExt},
};

pub mod entry;

pub use entry::{MplsEntries, MplsEntry};

/// Multiprotocol Label Switching (MPLS) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Mpls;

impl Protocol for Mpls {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mpls = MplsViewer::new(bytes);

        if let Some(entry) = mpls.entries().next() {
            write!(fmt, "[Mpls] label {}", entry.label().get())
        } else {
            write!(fmt, "[Mpls]")
        }
    }
}

impl ProtocolExt for Mpls {
    type Viewer<'a> = MplsViewer<&'a [u8]>;
    type ViewerMut<'a> = MplsViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let mut len = 0;
        let mut next_offset = offset;

        loop {
            let bytes = ctx.require(&Mpls, next_offset, MplsEntry::<&[u8]>::LEN)?;

            let entry = MplsEntry::new(bytes);
            len += MplsEntry::<&[u8]>::LEN;
            next_offset += MplsEntry::<&[u8]>::LEN;

            if entry.bottom_of_stack().get() != 0 {
                break;
            }
        }

        ctx.push_layer(&Mpls, offset, len);

        let Some(&first_payload_byte) = ctx.bytes.get(next_offset) else {
            return Ok(());
        };

        match first_payload_byte >> 4 {
            4 => ctx.parse_child::<crate::packet::layer::ip::v4::Ipv4>(next_offset)?,
            6 => ctx.parse_child::<crate::packet::layer::ip::v6::Ipv6>(next_offset)?,
            _ => ctx.parse_raw(next_offset),
        }

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        MplsViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        MplsViewer::new(bytes)
    }
}

/// Multiprotocol Label Switching (MPLS) label stack.
pub struct MplsViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> MplsViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Create a new MPLS viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Iterate over MPLS label stack entries.
    #[inline]
    pub fn entries(&self) -> MplsEntries<'_> {
        MplsEntries::new(self.data.as_ref())
    }
}

impl<T> MplsViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<T> core::fmt::Debug for MplsViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries: Vec<_> = self.entries().collect();
        f.debug_struct("Mpls").field("entries", &entries).finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    #[test]
    fn mpls_viewer() {
        let data: [u8; 8] = [
            0x00, 0x10, 0x00, 0xff, // label 256, tc 0, bos 0, ttl 255
            0x00, 0x20, 0x01, 0x40, // label 512, tc 0, bos 1, ttl 64
        ];

        let mpls = MplsViewer::new(&data);
        let entries: Vec<_> = mpls.entries().collect();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].label(), 256);
        assert_eq!(entries[0].bottom_of_stack(), 0);
        assert_eq!(entries[0].ttl(), 255);
        assert_eq!(entries[1].label(), 512);
        assert_eq!(entries[1].bottom_of_stack(), 1);
        assert_eq!(entries[1].ttl(), 64);
    }

    #[test]
    fn mpls_entry_mut() {
        let mut data: [u8; 4] = [0; 4];

        let mut entry = MplsEntry::new(&mut data);
        entry.label_mut().set(100);
        entry.traffic_class_mut().set(5);
        entry.bottom_of_stack_mut().set(1);
        entry.ttl_mut().set(64);

        assert_eq!(data, [0x00, 0x06, 0x4b, 0x40]);
    }

    #[test]
    fn parse_ethernet_mpls_ipv4_packet() {
        let data: [u8; 38] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // source MAC
            0x88, 0x47, // EtherType: MPLS unicast
            0x00, 0x10, 0x01, 0x40, // label 256, bos 1, ttl 64
            0x45, // version + ihl
            0x00, // dscp + ecn
            0x00, 0x14, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x11, // protocol: UDP
            0x00, 0x00, // checksum
            10, 0, 1, 1, // source IP
            10, 0, 1, 2, // destination IP
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let mpls = packet.layer_viewer(Mpls).expect("MPLS layer not found");
        let entries: Vec<_> = mpls.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].label(), 256);
        assert!(
            packet
                .layer_viewer(crate::packet::layer::ip::v4::Ipv4)
                .is_some()
        );
    }
}
