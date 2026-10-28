//! Internet Protocol version 6 fragment extension header
//! ([RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)).

use super::super::NextHeaderSpec;
use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt, ip::v6::dispatch},
        utils::field::{FieldMut, FieldRef},
    },
};

/// Internet Protocol version 6 fragment extension header.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Identification                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// The second octet is `Reserved`: zero when sent and ignored on receipt
/// ([RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)).
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Frag;

impl Ipv6Frag {
    /// Fixed fragment header length.
    pub const MIN_LEN: usize = 8;
}

impl Protocol for Ipv6Frag {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let frag = Ipv6FragViewer::new(bytes);

        write!(
            fmt,
            "[Ipv6Frag] offset={} m={} id={:#x} next={}",
            frag.fragment_offset().get(),
            frag.m_flag().get(),
            frag.identification().get(),
            frag.next_header().get()
        )
    }
}

impl ProtocolExt for Ipv6Frag {
    type Viewer<'a> = Ipv6FragViewer<&'a [u8]>;
    type ViewerMut<'a> = Ipv6FragViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let header = ctx.require(&Ipv6Frag, offset, Self::MIN_LEN)?;
        let frag = Ipv6FragViewer::new(header);
        let next_header = frag.next_header().get();

        ctx.push_layer(&Ipv6Frag, offset, Self::MIN_LEN);

        // Only the first fragment carries the transport header; the body of the
        // later ones is a piece of the original payload, which would be parsed
        // as a transport header if it were dispatched.
        if frag.fragment_offset().get() != 0 {
            ctx.parse_raw(offset + Self::MIN_LEN);
            return Ok(());
        }

        dispatch::dispatch(ctx, offset + Self::MIN_LEN, next_header)
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        Ipv6FragViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        Ipv6FragViewer::new(bytes)
    }
}

field_spec!(FragOffsetSpec, u16, u16, 0xFFF8, 3);
field_spec!(FragMFlagSpec, bool, u8, 0x01);
field_spec!(FragReservedSpec, u8, u8, 0x06, 1);
field_spec!(FragIdentificationSpec, u32, u32);

/// Zero-copy viewer for the IPv6 fragment extension header.
pub struct Ipv6FragViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Ipv6FragViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the next header: 0..1
    const FIELD_NEXT_HEADER: core::ops::Range<usize> = 0..1;
    /// Field range of the fragment offset: 2..4
    const FIELD_FRAGMENT: core::ops::Range<usize> = 2..4;
    /// Field range of the more fragments flag: 3..4
    const FIELD_M_FLAG: core::ops::Range<usize> = 3..4;
    /// Field range of the reserved bits: 3..4
    const FIELD_RESERVED: core::ops::Range<usize> = 3..4;
    /// Field range of the identification: 4..8
    const FIELD_IDENTIFICATION: core::ops::Range<usize> = 4..8;

    /// Create a new IPv6 fragment header viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the next header.
    #[inline]
    pub fn next_header(&self) -> FieldRef<'_, NextHeaderSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_NEXT_HEADER])
    }

    /// Get the accessor of the fragment offset.
    #[inline]
    pub fn fragment_offset(&self) -> FieldRef<'_, FragOffsetSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FRAGMENT])
    }

    /// Get the accessor of the more fragments flag, true when more fragments
    /// follow.
    #[inline]
    pub fn m_flag(&self) -> FieldRef<'_, FragMFlagSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_M_FLAG])
    }

    /// Get the accessor of the reserved bits.
    #[inline]
    pub fn reserved(&self) -> FieldRef<'_, FragReservedSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RESERVED])
    }

    /// Get the accessor of the identification.
    #[inline]
    pub fn identification(&self) -> FieldRef<'_, FragIdentificationSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_IDENTIFICATION])
    }
}

impl<T> Ipv6FragViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the next header.
    #[inline]
    pub fn next_header_mut(&mut self) -> FieldMut<'_, NextHeaderSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_NEXT_HEADER])
    }
    /// Get the mutable accessor of the fragment offset.
    #[inline]
    pub fn fragment_offset_mut(&mut self) -> FieldMut<'_, FragOffsetSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FRAGMENT])
    }

    /// Get the mutable accessor of the more fragments flag, true when more fragments
    /// follow.
    #[inline]
    pub fn m_flag_mut(&mut self) -> FieldMut<'_, FragMFlagSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_M_FLAG])
    }

    /// Get the mutable accessor of the reserved bits.
    #[inline]
    pub fn reserved_mut(&mut self) -> FieldMut<'_, FragReservedSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_RESERVED])
    }

    /// Get the mutable accessor of the identification.
    #[inline]
    pub fn identification_mut(&mut self) -> FieldMut<'_, FragIdentificationSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_IDENTIFICATION])
    }
}

#[cfg(test)]
mod tests {

    use crate::packet::layer::ip::protocol::IpProtocol;
    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    /// Ethernet + IPv6 + a fragment extension header + `payload`.
    fn fragmented(payload: &[u8], fragment_field: u16, frag_next_header: u8) -> Vec<u8> {
        let mut header = vec![frag_next_header, 0x00]; // next header, reserved
        header.extend_from_slice(&fragment_field.to_be_bytes()); // offset, M flag
        header.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // identification
        header.extend_from_slice(payload);

        super::super::test_util::eth_ipv6_frame(44, &header)
    }

    /// Minimal 20 byte TCP header (data offset 5, SYN).
    #[test]
    fn parse_ipv6_first_fragment_packet() {
        let data = fragmented(&super::super::test_util::tcp_header(), 0x0001, 6);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        let frag = packet
            .layer_viewer(Ipv6Frag)
            .expect("fragment header layer");
        assert_eq!(frag.fragment_offset().get(), 0);
        assert!(frag.m_flag().get());
        assert_eq!(frag.identification().get(), 0x1122_3344);
        assert_eq!(frag.reserved().get(), 0);
        assert_eq!(frag.next_header().get(), IpProtocol::Tcp);

        // A first fragment still carries the transport header.
        assert!(
            packet
                .layer_viewer(crate::packet::layer::tcp::Tcp)
                .is_some()
        );
    }

    #[test]
    fn parse_ipv6_non_first_fragment_packet() {
        // offset = 1 (8 octets) and the more fragments flag clear.
        let data = fragmented(&[0x5a; 8], 0x0008, 6);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        let frag = packet
            .layer_viewer(Ipv6Frag)
            .expect("fragment header layer");
        assert_eq!(frag.fragment_offset().get(), 1);
        assert!(!frag.m_flag().get());
        assert_eq!(frag.identification().get(), 0x1122_3344);
        assert_eq!(frag.next_header().get(), IpProtocol::Tcp);

        // A non-first fragment has no transport header to parse.
        assert!(
            packet
                .layer_viewer(crate::packet::layer::tcp::Tcp)
                .is_none()
        );
    }

    #[test]
    fn ipv6_frag_viewer_mut() {
        let mut data = [17, 0, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44];
        let mut frag = Ipv6FragViewer::new(&mut data[..]);

        frag.next_header_mut().set(IpProtocol::Tcp);
        frag.fragment_offset_mut().set(1);
        frag.m_flag_mut().set(true);
        frag.reserved_mut().set(3);
        frag.identification_mut().set(0x5566_7788);

        assert_eq!(data, [6, 0, 0x00, 0x0f, 0x55, 0x66, 0x77, 0x88]);
    }
}
