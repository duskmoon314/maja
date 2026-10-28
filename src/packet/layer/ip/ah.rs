//! IP authentication header (AH), next header value 51
//! ([RFC 4302 section 2](https://www.rfc-editor.org/rfc/rfc4302.html#section-2)).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Next Header   |  Payload Len  |          RESERVED             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 Security Parameters Index (SPI)               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Sequence Number Field                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                Integrity Check Value-ICV (variable)           |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::{
    field_spec,
    packet::{
        ParseContext,
        error::ParseError,
        layer::{
            Protocol, ProtocolExt,
            ip::v6::{NextHeaderSpec, dispatch::dispatch},
        },
        utils::field::{FieldMut, FieldRef},
    },
};

/// IP authentication header.
#[derive(Debug, Clone, Copy)]
pub struct Ah;

impl Ah {
    /// Next header, payload length, reserved, SPI and sequence number.
    pub const MIN_LEN: usize = 12;

    /// Full header length in octets for a `Payload Len` value, `(len + 2) * 4`
    /// ([RFC 4302 section 2.2](https://www.rfc-editor.org/rfc/rfc4302.html#section-2.2)).
    ///
    /// A value of four gives a 24-octet header: the 12-octet fixed part plus a
    /// 12-octet ICV.
    #[inline]
    pub const fn header_len(payload_len: u8) -> usize {
        (payload_len as usize + 2) * 4
    }
}

impl Protocol for Ah {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ah = AhViewer::new(bytes);

        write!(
            fmt,
            "[Ah] spi={:#010x} seq={} next={}",
            ah.spi().get(),
            ah.sequence().get(),
            ah.next_header().get()
        )
    }
}

impl ProtocolExt for Ah {
    type Viewer<'a> = AhViewer<&'a [u8]>;
    type ViewerMut<'a> = AhViewer<&'a mut [u8]>;

    fn parse(ctx: &mut ParseContext, offset: usize) -> Result<(), ParseError> {
        let prefix = ctx.require(&Ah, offset, Ah::MIN_LEN)?;
        let declared = AhViewer::new(prefix).header_len();
        if declared < Ah::MIN_LEN {
            return Err(ParseError::Malformed {
                protocol: &Ah,
                field: "payload length",
                reason: "the declared header is shorter than the fixed part",
            });
        }

        // The declared length is trusted only as far as the enclosing payload or
        // the capture reaches: a header that declares more than that takes the
        // bytes that exist and ends the chain.
        let len = declared.min(ctx.rest(offset).len());
        let header = ctx.require(&Ah, offset, len)?;
        let next_header = AhViewer::new(header).next_header().get();

        ctx.push_layer(&Ah, offset, len);

        if ctx.rest(offset + len).is_empty() {
            ctx.parse_raw(offset + len);
            return Ok(());
        }

        dispatch(ctx, offset + len, next_header)
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        AhViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        AhViewer::new(bytes)
    }
}

field_spec!(AhPayloadLenSpec, u8, u8);
field_spec!(AhSpiSpec, u32, u32);
field_spec!(AhSequenceSpec, u32, u32);

/// Zero-copy viewer for the IP authentication header.
pub struct AhViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> AhViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the next header: 0..1
    const FIELD_NEXT_HEADER: core::ops::Range<usize> = 0..1;
    /// Field range of the payload length: 1..2
    const FIELD_PAYLOAD_LEN: core::ops::Range<usize> = 1..2;
    /// Field range of the security parameters index: 4..8
    const FIELD_SPI: core::ops::Range<usize> = 4..8;
    /// Field range of the sequence number: 8..12
    const FIELD_SEQUENCE: core::ops::Range<usize> = 8..12;

    /// Create a new authentication header viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the next header, i.e. the header that follows this one.
    #[inline]
    pub fn next_header(&self) -> FieldRef<'_, NextHeaderSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_NEXT_HEADER])
    }

    /// Get the accessor of the payload length, in 32-bit words not counting the
    /// first two.
    #[inline]
    pub fn payload_len(&self) -> FieldRef<'_, AhPayloadLenSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PAYLOAD_LEN])
    }

    /// Get the accessor of the security parameters index.
    #[inline]
    pub fn spi(&self) -> FieldRef<'_, AhSpiSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SPI])
    }

    /// Get the accessor of the sequence number.
    #[inline]
    pub fn sequence(&self) -> FieldRef<'_, AhSequenceSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SEQUENCE])
    }

    /// Return the full header length in octets.
    #[inline]
    pub fn header_len(&self) -> usize {
        Ah::header_len(self.data.as_ref()[Self::FIELD_PAYLOAD_LEN.start])
    }

    /// Get the integrity check value behind the fixed part.
    pub fn icv(&self) -> &[u8] {
        &self.data.as_ref()[Ah::MIN_LEN..]
    }
}

impl<T> AhViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the next header, i.e. the header that follows this one.
    #[inline]
    pub fn next_header_mut(&mut self) -> FieldMut<'_, NextHeaderSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_NEXT_HEADER])
    }

    /// Get the mutable accessor of the payload length, in 32-bit words not counting the
    /// first two.
    #[inline]
    pub fn payload_len_mut(&mut self) -> FieldMut<'_, AhPayloadLenSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PAYLOAD_LEN])
    }

    /// Get the mutable accessor of the security parameters index.
    #[inline]
    pub fn spi_mut(&mut self) -> FieldMut<'_, AhSpiSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SPI])
    }

    /// Get the mutable accessor of the sequence number.
    #[inline]
    pub fn sequence_mut(&mut self) -> FieldMut<'_, AhSequenceSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SEQUENCE])
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::{
        Packet,
        layer::{Protocol, eth::Eth, ip::v6::Ipv6, raw::Raw, tcp::Tcp},
    };

    use super::*;
    use crate::packet::layer::ip::protocol::IpProtocol;
    use crate::packet::layer::ip::v6::ext::test_util::tcp_header;
    use crate::packet::layer::ip::v6::ext::test_util::{eth_ipv6_frame, layers};

    /// An AH header that points at TCP, with `icv` behind the fixed part.
    fn ah_header(next_header: u8, icv: &[u8]) -> Vec<u8> {
        let header_len = Ah::MIN_LEN + icv.len();
        let mut header = vec![next_header, (header_len / 4 - 2) as u8, 0, 0];
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // spi
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // sequence
        header.extend_from_slice(icv);

        header
    }

    #[test]
    fn ah_viewer() {
        // A 24-octet header with the twelve-octet ICV of HMAC-SHA1-96, the shape
        // a real deployment sends; the values were cross-checked with `tshark -T
        // fields -e ah.next_header -e ah.length -e ah.spi -e ah.sequence -e ah.icv`.
        let icv = [
            0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
        ];
        let mut payload = ah_header(6, &icv);
        payload.extend_from_slice(&tcp_header());

        let data = eth_ipv6_frame(51, &payload);
        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(layers(&packet), [&Eth as &dyn Protocol, &Ipv6, &Ah, &Tcp]);

        let ah = packet.layer_viewer(Ah).expect("ah layer");
        assert_eq!(ah.next_header().get(), IpProtocol::Tcp);
        assert_eq!(ah.payload_len().get(), 4);
        assert_eq!(ah.header_len(), 24);
        assert_eq!(ah.spi().get(), 1);
        assert_eq!(ah.sequence().get(), 2);
        assert_eq!(ah.icv(), &icv);

        assert!(packet.layer_viewer(Tcp).is_some());
        assert_eq!(packet.layer(Ipv6).unwrap().range(), 14..54);
        assert_eq!(packet.layer(Ah).unwrap().range(), 54..78);
    }

    #[test]
    fn ah_shorter_than_its_declared_length_keeps_the_present_bytes() {
        // The header claims four more octets than the packet holds.
        let mut payload = ah_header(6, &[]);
        payload[1] = 2; // header length 16, but only 12 octets follow
        let data = eth_ipv6_frame(51, &payload);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(layers(&packet), [&Eth as &dyn Protocol, &Ipv6, &Ah]);

        let ah = packet.layer_viewer(Ah).expect("ah layer");
        assert_eq!(ah.header_len(), 16);
        assert_eq!(ah.inner().len(), 12);
        assert_eq!(ah.next_header().get(), IpProtocol::Tcp);

        // The chain ends at the declared payload length, so nothing is parsed
        // from inside the missing ICV.
        assert!(packet.layer_viewer(Tcp).is_none());
    }

    #[test]
    fn ah_zero_payload_length_is_malformed() {
        // The declared header would be shorter than the fixed part.
        let mut payload = ah_header(6, &[]);
        payload[1] = 0;
        let data = eth_ipv6_frame(51, &payload);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(layers(&packet), [&Eth as &dyn Protocol, &Ipv6, &Raw]);
        assert!(packet.layer_viewer(Ah).is_none());
        assert!(packet.layer_viewer(Raw).is_some());
    }

    #[test]
    fn ah_viewer_mut() {
        let mut data = [0u8; Ah::MIN_LEN];
        let mut ah = AhViewer::new(&mut data[..]);

        ah.next_header_mut().set(IpProtocol::Tcp);
        ah.payload_len_mut().set(1);
        ah.spi_mut().set(0x1234);
        ah.sequence_mut().set(7);

        assert_eq!(data, [6, 1, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 0, 7]);
    }
}
