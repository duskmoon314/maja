//! Internet Protocol version 6 (IPv6) parsing
//! ([RFC 8200 section 3](https://www.rfc-editor.org/rfc/rfc8200.html#section-3)).
//!
//! IPv6 has a fixed 40-byte base header. Extension headers between the base
//! header and the transport header are handled by the [`ext`] module, which also
//! owns the layers for them, and the options those headers carry are parsed by
//! the [`option`](ext::option) module.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Version| Traffic Class |           Flow Label                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Payload Length        |  Next Header  |   Hop Limit   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                         Source Address                        +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                      Destination Address                      +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |        Extension headers and/or upper-layer payload           |
//! ~                              ...                              ~
//! ```

use crate::{
    field_spec, impl_target,
    packet::{
        ParseContext,
        error::ParseError,
        layer::{Protocol, ProtocolExt, ip::protocol::IpProtocol},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod dispatch;
pub mod ext;

pub use ext::{
    HipPacketType, Ipv6DestOpts, Ipv6ExtHeaderViewer, Ipv6Frag, Ipv6FragViewer, Ipv6Hip,
    Ipv6Hopopt, Ipv6Mobility, Ipv6Option, Ipv6OptionKind, Ipv6Options, Ipv6Route, Ipv6RouteType,
    Ipv6RouteViewer, Ipv6Shim6, MobilityType, Shim6MessageType, parse_ext_header,
};

impl_target!(frominto, core::net::Ipv6Addr, u128);

/// Internet Protocol version 6 (IPv6) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6;

impl Ipv6 {
    /// IPv6 fixed header length.
    pub const MIN_LEN: usize = 40;
}

impl Protocol for Ipv6 {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ipv6 = Ipv6Viewer::new(bytes);

        write!(
            fmt,
            "[Ipv6] {:<39} -> {:<39} {:<5}",
            ipv6.src().get(),
            ipv6.dst().get(),
            ipv6.payload_length().get()
        )
    }
}

impl ProtocolExt for Ipv6 {
    type Viewer<'a> = Ipv6Viewer<&'a [u8]>;
    type ViewerMut<'a> = Ipv6Viewer<&'a mut [u8]>;

    fn parse(ctx: &mut ParseContext, offset: usize) -> Result<(), ParseError> {
        let header = ctx.require(&Ipv6, offset, Ipv6::MIN_LEN)?;
        let ipv6 = Ipv6Viewer::new(header);
        let next_header = ipv6.next_header().get();

        ctx.push_layer(&Ipv6, offset, Ipv6::MIN_LEN);

        let child_offset = offset + Ipv6::MIN_LEN;
        // A zero `Payload Length` means a jumbogram or an offloaded packet: no
        // header declares where the payload ends, so the capture is the bound.
        let end = match usize::from(ipv6.payload_length().get()) {
            0 => None,
            len => Some(child_offset.saturating_add(len)),
        };

        let outer_end = ctx.declared_end;
        ctx.declared_end = match (outer_end, end) {
            (Some(outer), Some(inner)) => Some(outer.min(inner)),
            (outer, None) => outer,
            (None, inner) => inner,
        };
        let result = dispatch::dispatch(ctx, child_offset, next_header);
        ctx.declared_end = outer_end;
        result?;

        // Bytes past the declared payload are padding or a trailer, not payload:
        // record them raw so the layer table still covers the frame.
        if let Some(end) = end {
            ctx.parse_raw(end);
        }

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        Ipv6Viewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        Ipv6Viewer::new(bytes)
    }
}

field_spec!(VersionSpec, u8, u8, 0xF0, 4);
field_spec!(TrafficClassSpec, u8, u16, 0x0FF0, 4);
field_spec!(FlowLabelSpec, u32, u32, 0x000F_FFFF);
field_spec!(PayloadLengthSpec, u16, u16);
field_spec!(NextHeaderSpec, IpProtocol, u8);
field_spec!(HopLimitSpec, u8, u8);
field_spec!(Ipv6AddrSpec, core::net::Ipv6Addr, u128);

/// Internet Protocol version 6 (IPv6).
pub struct Ipv6Viewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Ipv6Viewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the version: 0..1
    const FIELD_VERSION: core::ops::Range<usize> = 0..1;
    /// Field range of the traffic class: 0..2
    const FIELD_TRAFFIC_CLASS: core::ops::Range<usize> = 0..2;
    /// Field range of the flow label: 0..4
    const FIELD_FLOW_LABEL: core::ops::Range<usize> = 0..4;
    /// Field range of the payload length: 4..6
    const FIELD_PAYLOAD_LENGTH: core::ops::Range<usize> = 4..6;
    /// Field range of the next header: 6..7
    const FIELD_NEXT_HEADER: core::ops::Range<usize> = 6..7;
    /// Field range of the hop limit: 7..8
    const FIELD_HOP_LIMIT: core::ops::Range<usize> = 7..8;
    /// Field range of the source address: 8..24
    const FIELD_SRC: core::ops::Range<usize> = 8..24;
    /// Field range of the destination address: 24..40
    const FIELD_DST: core::ops::Range<usize> = 24..40;

    /// Create a new IPv6 viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the version.
    #[inline]
    pub fn version(&self) -> FieldRef<'_, VersionSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_VERSION])
    }

    /// Get the accessor of the traffic class.
    #[inline]
    pub fn traffic_class(&self) -> FieldRef<'_, TrafficClassSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TRAFFIC_CLASS])
    }

    /// Get the accessor of the flow label.
    #[inline]
    pub fn flow_label(&self) -> FieldRef<'_, FlowLabelSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLOW_LABEL])
    }

    /// Get the accessor of the payload length.
    #[inline]
    pub fn payload_length(&self) -> FieldRef<'_, PayloadLengthSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PAYLOAD_LENGTH])
    }

    /// Get the accessor of the next header.
    #[inline]
    pub fn next_header(&self) -> FieldRef<'_, NextHeaderSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_NEXT_HEADER])
    }

    /// Get the accessor of the hop limit.
    #[inline]
    pub fn hop_limit(&self) -> FieldRef<'_, HopLimitSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_HOP_LIMIT])
    }

    /// Get the accessor of the source address.
    #[inline]
    pub fn src(&self) -> FieldRef<'_, Ipv6AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SRC])
    }

    /// Get the accessor of the destination address.
    #[inline]
    pub fn dst(&self) -> FieldRef<'_, Ipv6AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DST])
    }
}

impl<T> Ipv6Viewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the version.
    #[inline]
    pub fn version_mut(&mut self) -> FieldMut<'_, VersionSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_VERSION])
    }

    /// Get the mutable accessor of the traffic class.
    #[inline]
    pub fn traffic_class_mut(&mut self) -> FieldMut<'_, TrafficClassSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TRAFFIC_CLASS])
    }

    /// Get the mutable accessor of the flow label.
    #[inline]
    pub fn flow_label_mut(&mut self) -> FieldMut<'_, FlowLabelSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLOW_LABEL])
    }

    /// Get the mutable accessor of the payload length.
    #[inline]
    pub fn payload_length_mut(&mut self) -> FieldMut<'_, PayloadLengthSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PAYLOAD_LENGTH])
    }

    /// Get the mutable accessor of the next header.
    #[inline]
    pub fn next_header_mut(&mut self) -> FieldMut<'_, NextHeaderSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_NEXT_HEADER])
    }

    /// Get the mutable accessor of the hop limit.
    #[inline]
    pub fn hop_limit_mut(&mut self) -> FieldMut<'_, HopLimitSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_HOP_LIMIT])
    }

    /// Get the mutable accessor of the source address.
    #[inline]
    pub fn src_mut(&mut self) -> FieldMut<'_, Ipv6AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SRC])
    }

    /// Get the mutable accessor of the destination address.
    #[inline]
    pub fn dst_mut(&mut self) -> FieldMut<'_, Ipv6AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_DST])
    }
}

impl<T> core::fmt::Debug for Ipv6Viewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv6")
            .field("version", &self.version().get())
            .field("traffic_class", &self.traffic_class().get())
            .field("flow_label", &self.flow_label().get())
            .field("payload_length", &self.payload_length().get())
            .field("next_header", &self.next_header().get())
            .field("hop_limit", &self.hop_limit().get())
            .field("src", &self.src().get())
            .field("dst", &self.dst().get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv6Addr;

    use crate::packet::{
        Packet, ParseOptions,
        error::ParseError,
        layer::{eth::Eth, icmpv6::Icmpv6, raw::Raw, udp::Udp},
        utils::checksum::ipv6_transport_checksum_zeroing,
    };

    use super::ext::test_util::{eth_ipv6_frame_with_plen, layers, tcp_header, udp_header};
    use super::*;

    #[test]
    fn ipv6_viewer() {
        let data: [u8; 40] = [
            0x60, 0x00, 0x00, 0x00, // version, traffic class, flow label
            0x00, 0x08, // payload length
            0x3a, // next header: ICMPv6
            0x40, // hop limit
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // src
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // dst
        ];

        let ipv6 = Ipv6Viewer::new(&data);

        assert_eq!(ipv6.version(), 6);
        assert_eq!(ipv6.traffic_class(), 0);
        assert_eq!(ipv6.flow_label(), 0);
        assert_eq!(ipv6.payload_length(), 8);
        assert_eq!(ipv6.next_header(), IpProtocol::Ipv6Icmp);
        assert_eq!(ipv6.hop_limit(), 64);
        assert_eq!(ipv6.src(), Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(ipv6.dst(), Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
    }

    #[test]
    fn parse_ethernet_ipv6_icmpv6_packet() {
        let data: [u8; 62] = [
            0x33, 0x33, 0x00, 0x00, 0x00, 0x02, // destination MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // source MAC
            0x86, 0xdd, // EtherType: IPv6
            0x60, 0x00, 0x00, 0x00, // version, traffic class, flow label
            0x00, 0x08, // payload length
            0x3a, // next header: ICMPv6
            0x40, // hop limit
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // src
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,    // dst
            0x80, // type: echo request
            0x00, // code
            0x00, 0x00, // checksum
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        assert!(packet.layer_viewer(Ipv6).is_some());
        let icmpv6 = packet
            .layer_viewer(crate::packet::layer::icmpv6::Icmpv6)
            .expect("ICMPv6 layer not found");
        assert_eq!(
            icmpv6.message_type(),
            crate::packet::layer::icmpv6::Icmpv6Type::EchoRequest
        );
    }

    /// The two addresses of every `eth_ipv6_frame` fixture.
    fn endpoints() -> (Ipv6Addr, Ipv6Addr) {
        (
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        )
    }

    #[test]
    fn payload_length_bounds_the_child_region() {
        // An eight-octet UDP header followed by two octets that the payload
        // length does not cover.
        let mut payload = udp_header();
        payload.extend_from_slice(&[0xaa, 0xaa]);
        let data = eth_ipv6_frame_with_plen(17, 8, &payload);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(layers(&packet), [&Eth as &dyn Protocol, &Ipv6, &Udp, &Raw]);
        assert_eq!(packet.layer(Udp).unwrap().range(), 54..62);
        // The bytes past the payload length stay visible as a raw trailer.
        assert_eq!(packet.layer(Raw).unwrap().range(), 62..64);
    }

    #[test]
    fn icmpv6_checksum_ignores_the_padding() {
        let (src, dst) = endpoints();
        let mut message = vec![
            0x80, 0x00, 0x00, 0x00, // type, code, checksum
            0x12, 0x34, 0x00, 0x01, // identifier, sequence
            b'h', b'i', b'!', b'?',
        ];
        let checksum = ipv6_transport_checksum_zeroing(src, dst, 58, &message, 2..4);
        message[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut payload = message.clone();
        payload.extend_from_slice(&[0xaa, 0xaa]);
        let data = eth_ipv6_frame_with_plen(58, 12, &payload);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(packet.layer(Icmpv6).unwrap().range(), 54..66);
        assert_eq!(packet.layer(Raw).unwrap().range(), 66..68);
        assert!(
            packet
                .layer_viewer(Icmpv6)
                .unwrap()
                .validate_checksum_ipv6(src, dst)
        );
    }

    #[test]
    fn extension_header_longer_than_the_payload_is_clamped() {
        // Hop-by-Hop that declares 24 octets while the payload length says 8.
        let mut payload = vec![17, 2, 0, 0, 0, 0, 0, 0];
        payload.extend_from_slice(&udp_header());
        let data = eth_ipv6_frame_with_plen(0, 8, &payload);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(
            layers(&packet),
            [&Eth as &dyn Protocol, &Ipv6, &Ipv6Hopopt, &Raw]
        );

        let hopopt = packet.layer_viewer(Ipv6Hopopt).expect("hopopt layer");
        assert_eq!(hopopt.header_len(), 24);
        assert_eq!(hopopt.inner().len(), 8);

        // Everything behind the declared payload is a raw trailer.
        assert_eq!(packet.layer(Raw).unwrap().range(), 62..70);
        assert!(packet.layer_viewer(Udp).is_none());
    }

    #[test]
    fn extension_header_shorter_than_the_fixed_part_is_malformed() {
        // HIP needs 40 octets, the header length field declares 8.
        let payload = vec![17, 0, 0, 0, 0, 0, 0, 0];
        let data = eth_ipv6_frame_with_plen(139, 8, &payload);

        let mut packet = Packet::new(data.as_slice());
        let err = packet
            .try_parse::<Eth>(ParseOptions {
                fallback_to_raw_on_child_error: false,
                ..Default::default()
            })
            .expect_err("a short HIP header should be malformed");

        assert!(matches!(
            err,
            ParseError::Malformed { protocol, .. } if protocol.id() == Ipv6Hip.id()
        ));
    }

    #[test]
    fn zero_payload_length_leaves_the_capture_as_the_bound() {
        // A jumbogram or an offloaded packet: no declared end.
        let mut payload = udp_header();
        payload.extend_from_slice(&[0xaa, 0xaa]);
        let data = eth_ipv6_frame_with_plen(17, 0, &payload);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(layers(&packet), [&Eth as &dyn Protocol, &Ipv6, &Udp, &Raw]);
        assert_eq!(packet.layer(Raw).unwrap().range(), 62..64);
    }

    #[test]
    fn payload_length_beyond_the_capture_is_truncated() {
        // The payload length declares 40 octets, the capture stops after 8.
        let mut payload = tcp_header();
        payload.truncate(8);
        let data = eth_ipv6_frame_with_plen(6, 40, &payload);

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(layers(&packet), [&Eth as &dyn Protocol, &Ipv6, &Raw]);
        assert_eq!(packet.layer(Raw).unwrap().range(), 54..62);
    }
}
