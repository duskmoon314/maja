//! Internet Protocol version 6 (IPv6) parsing.
//!
//! IPv6 has a fixed 40-byte base header. Extension headers can appear between
//! the base header and the transport header; this parser skips common extension
//! headers and dispatches from the first transport header it recognizes. It does
//! not currently create separate layers for extension headers.
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
        layer::{Protocol, ProtocolExt, ip::protocol::IpProtocol},
        utils::field::{FieldMut, FieldRef},
    },
};

impl_target!(frominto, core::net::Ipv6Addr, u128);

/// Internet Protocol version 6 (IPv6) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6;

impl Ipv6 {
    /// IPv6 fixed header length.
    const MIN_LEN: usize = 40;
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

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let header = ctx.require(&Ipv6, offset, Ipv6::MIN_LEN)?;
        let ipv6 = Ipv6Viewer::new(header);
        let next_header = ipv6.next_header().get();

        ctx.push_layer(&Ipv6, offset, Ipv6::MIN_LEN);

        let (next_header, next_offset) = next_transport_header(ctx, offset, next_header)?;
        let Some(next_header) = next_header else {
            ctx.parse_raw(next_offset);
            return Ok(());
        };

        match next_header {
            IpProtocol::Tcp => ctx.parse_child::<crate::packet::layer::tcp::Tcp>(next_offset)?,
            IpProtocol::Udp => ctx.parse_child::<crate::packet::layer::udp::Udp>(next_offset)?,
            IpProtocol::Gre => ctx.parse_child::<crate::packet::layer::gre::Gre>(next_offset)?,
            IpProtocol::Sctp => ctx.parse_child::<crate::packet::layer::sctp::Sctp>(next_offset)?,
            IpProtocol::Ipv6Icmp => {
                ctx.parse_child::<crate::packet::layer::icmpv6::Icmpv6>(next_offset)?
            }
            protocol
                if ctx
                    .options
                    .registry
                    .contains_key(&(Ipv6.id(), protocol.into())) =>
            {
                let parse_fn = ctx.options.registry[&(Ipv6.id(), protocol.into())];
                ctx.parse_child_with(parse_fn, next_offset)?;
            }
            _ => ctx.parse_raw(next_offset),
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

fn next_transport_header(
    ctx: &ParseContext,
    ipv6_offset: usize,
    mut next_header: IpProtocol,
) -> Result<(Option<IpProtocol>, usize), crate::packet::error::ParseError> {
    let mut offset = ipv6_offset + Ipv6::MIN_LEN;

    loop {
        match next_header {
            IpProtocol::Hopopt | IpProtocol::Ipv6Route | IpProtocol::Ipv6Opts => {
                let ext = ctx.require(&Ipv6, offset, 2)?;
                next_header = IpProtocol::from(ext[0]);
                let ext_len = (ext[1] as usize + 1) * 8;
                ctx.require(&Ipv6, offset, ext_len)?;
                offset += ext_len;
            }
            IpProtocol::Ipv6Frag => {
                let ext = ctx.require(&Ipv6, offset, 8)?;
                next_header = IpProtocol::from(ext[0]);
                let fragment = u16::from_be_bytes([ext[2], ext[3]]);
                let fragment_offset = (fragment & 0xfff8) >> 3;
                if fragment_offset != 0 {
                    return Ok((None, offset));
                }
                offset += 8;
            }
            IpProtocol::Ah => {
                let ext = ctx.require(&Ipv6, offset, 2)?;
                next_header = IpProtocol::from(ext[0]);
                let ext_len = (ext[1] as usize + 2) * 4;
                ctx.require(&Ipv6, offset, ext_len)?;
                offset += ext_len;
            }
            IpProtocol::Esp => return Ok((None, offset)),
            _ => return Ok((Some(next_header), offset)),
        }
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

    use crate::packet::{Packet, layer::eth::Eth};

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
}
