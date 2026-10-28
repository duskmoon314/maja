//! IPv6 Routing header
//! ([RFC 8200 section 4.4](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.4)).
//!
//! The Routing header carries the intermediate nodes a packet has to visit.
//! `Routing Type` selects the payload format; this module decodes the fields
//! every routing header has and delegates the type-specific payloads to
//! submodules:
//!
//! - [`type0`] decodes the deprecated source route (type 0)
//!   ([RFC 2460 section 4.4](https://www.rfc-editor.org/rfc/rfc2460.html#section-4.4)),
//!   which is a list of IPv6 addresses.
//! - [`srh`] decodes the Segment Routing header (type 4)
//!   ([RFC 8754 section 2](https://www.rfc-editor.org/rfc/rfc8754.html#section-2)).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! .                       Type-Specific Data                      .
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use super::super::Ipv6AddrSpec;
use super::header::{self, Ipv6ExtHeaderViewer};
use crate::impl_target;
use crate::{
    field_spec,
    packet::{
        ParseContext,
        error::ParseError,
        layer::{Protocol, ProtocolExt},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod srh;
pub mod type0;

pub use srh::Ipv6Srh;
pub use type0::Ipv6RouteType0;

/// Internet Protocol version 6 Routing header.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Route;

impl Ipv6Route {
    /// Fixed part of the header: next header, header extension length, routing
    /// type, and segments left.
    pub const MIN_LEN: usize = 4;
}

impl Protocol for Ipv6Route {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let route = Ipv6RouteViewer::new(bytes);

        write!(
            fmt,
            "[Ipv6Route] type={} segments_left={} next={}",
            route.routing_type().get(),
            route.segments_left().get(),
            route.next_header().get(),
        )
    }
}

impl ProtocolExt for Ipv6Route {
    type Viewer<'a> = Ipv6RouteViewer<&'a [u8]>;
    type ViewerMut<'a> = Ipv6RouteViewer<&'a mut [u8]>;

    fn parse(ctx: &mut ParseContext, offset: usize) -> Result<(), ParseError> {
        header::parse_ext_header(ctx, offset, &Ipv6Route, Ipv6Route::MIN_LEN)
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        Ipv6RouteViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        Ipv6RouteViewer::new(bytes)
    }
}

/// IPv6 Routing Type
/// ([RFC 8200 section 4.4](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.4)).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    // num_enum traits
    FromPrimitive,
    IntoPrimitive,
    // strum traits
    AsRefStr,
    Display,
    EnumString,
)]
#[repr(u8)]
#[non_exhaustive]
pub enum Ipv6RouteType {
    /// Source Route, deprecated by
    /// [RFC 5095](https://www.rfc-editor.org/rfc/rfc5095.html).
    SourceRoute = 0,
    /// NIMROD, deprecated.
    Nimrod = 1,
    /// Type 2 Routing Header (Mobile IPv6).
    MobileIpv6 = 2,
    /// RPL Source Route
    /// ([RFC 6554 section 3](https://www.rfc-editor.org/rfc/rfc6554.html#section-3)).
    RplSourceRoute = 3,
    /// Segment Routing Header
    /// ([RFC 8754 section 2](https://www.rfc-editor.org/rfc/rfc8754.html#section-2)).
    SegmentRouting = 4,
    /// Routing type outside the values above.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, Ipv6RouteType, u8);

field_spec!(RouteTypeSpec, Ipv6RouteType, u8);
field_spec!(RouteSegmentsLeftSpec, u8, u8);

/// Zero-copy viewer for the IPv6 Routing header.
pub struct Ipv6RouteViewer<T>
where
    T: AsRef<[u8]>,
{
    header: Ipv6ExtHeaderViewer<T>,
}

impl<T: AsRef<[u8]>> core::ops::Deref for Ipv6RouteViewer<T> {
    type Target = Ipv6ExtHeaderViewer<T>;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> core::ops::DerefMut for Ipv6RouteViewer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.header
    }
}

impl<T> Ipv6RouteViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the routing type: 2..3
    const FIELD_ROUTING_TYPE: core::ops::Range<usize> = 2..3;
    /// Field range of segments left: 3..4
    const FIELD_SEGMENTS_LEFT: core::ops::Range<usize> = 3..4;

    /// Create a new Routing header viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self {
            header: Ipv6ExtHeaderViewer::new(data),
        }
    }

    /// Get the accessor of the routing type.
    #[inline]
    pub fn routing_type(&self) -> FieldRef<'_, RouteTypeSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_ROUTING_TYPE])
    }

    /// Get the accessor of the number of route segments still to be visited.
    #[inline]
    pub fn segments_left(&self) -> FieldRef<'_, RouteSegmentsLeftSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_SEGMENTS_LEFT])
    }

    /// Get the raw type-specific data after the fixed header fields.
    pub fn data(&self) -> &[u8] {
        &self.inner().as_ref()[Ipv6Route::MIN_LEN..]
    }

    /// Return the source route payload, if this is a type 0 header.
    pub fn type0(&self) -> Option<Ipv6RouteType0<&[u8]>> {
        if self.routing_type().get() != Ipv6RouteType::SourceRoute {
            return None;
        }

        Ipv6RouteType0::parse(self.data())
    }

    /// Return the Segment Routing payload, if this is a type 4 header.
    pub fn srh(&self) -> Option<Ipv6Srh<&[u8]>> {
        if self.routing_type().get() != Ipv6RouteType::SegmentRouting {
            return None;
        }

        Ipv6Srh::parse(self.data())
    }
}

impl<T> Ipv6RouteViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable accessor of the routing type.
    #[inline]
    pub fn routing_type_mut(&mut self) -> FieldMut<'_, RouteTypeSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_ROUTING_TYPE])
    }

    /// Get the mutable accessor of the number of route segments still to be visited.
    #[inline]
    pub fn segments_left_mut(&mut self) -> FieldMut<'_, RouteSegmentsLeftSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_SEGMENTS_LEFT])
    }

    /// Get the mutable raw type-specific data after the fixed header fields.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.inner_mut().as_mut()[Ipv6Route::MIN_LEN..]
    }

    /// Return the mutable source route payload, if this is a type 0 header.
    pub fn type0_mut(&mut self) -> Option<Ipv6RouteType0<&mut [u8]>> {
        if self.routing_type().get() != Ipv6RouteType::SourceRoute {
            return None;
        }

        Ipv6RouteType0::parse(self.data_mut())
    }

    /// Return the mutable Segment Routing payload, if this is a type 4 header.
    pub fn srh_mut(&mut self) -> Option<Ipv6Srh<&mut [u8]>> {
        if self.routing_type().get() != Ipv6RouteType::SegmentRouting {
            return None;
        }

        Ipv6Srh::parse(self.data_mut())
    }
}

/// Iterator over the IPv6 addresses of a routing header.
///
/// Routing type 0 carries its source route list and the Segment Routing header
/// its segment list; both are consecutive 16-octet addresses, so one iterator
/// serves both.
#[derive(Debug, Clone)]
pub struct Ipv6RouteAddrs<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Ipv6RouteAddrs<'a> {
    /// Iterate over the complete 16-octet addresses at the start of `bytes`.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl Iterator for Ipv6RouteAddrs<'_> {
    type Item = core::net::Ipv6Addr;

    fn next(&mut self) -> Option<Self::Item> {
        let addr = self.bytes.get(self.offset..self.offset + 16)?;
        self.offset += 16;

        let mut octets = [0u8; 16];
        octets.copy_from_slice(addr);

        Some(core::net::Ipv6Addr::from(octets))
    }
}

/// Mutable iterator over the IPv6 addresses of a routing header.
///
/// Every address is a 16-octet field, so the same iterator serves the source
/// route of routing type 0 and the segment list of the Segment Routing header.
#[derive(Debug)]
pub struct Ipv6RouteAddrsMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> Ipv6RouteAddrsMut<'a> {
    /// Iterate mutably over the complete 16-octet addresses at the start of
    /// `bytes`.
    pub(crate) const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> Iterator for Ipv6RouteAddrsMut<'a> {
    type Item = FieldMut<'a, Ipv6AddrSpec>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() < 16 {
            return None;
        }

        let bytes = core::mem::take(&mut self.bytes);
        let (addr, rest) = bytes.split_at_mut(16);
        self.bytes = rest;

        Some(FieldMut::new(addr))
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::layer::ip::protocol::IpProtocol;
    use crate::packet::{
        Packet,
        layer::{eth::Eth, ip::v6::Ipv6, udp::Udp},
    };

    use super::*;

    /// Ethernet + IPv6 + a Routing header + `payload`.
    fn route_frame(routing_type: u8, data: &[u8], payload: &[u8]) -> Vec<u8> {
        let header_len = (Ipv6Route::MIN_LEN + data.len()).next_multiple_of(8);
        let mut route = vec![17, (header_len / 8 - 1) as u8, routing_type, 1];
        route.extend_from_slice(data);
        route.resize(header_len, 0);
        route.extend_from_slice(payload);

        super::super::test_util::eth_ipv6_frame(43, &route)
    }

    #[test]
    fn parse_ipv6_route_packet() {
        let data = route_frame(0, &[0; 32], &super::super::test_util::udp_header());

        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert!(packet.layer_viewer(Ipv6).is_some());

        let route = packet.layer_viewer(Ipv6Route).expect("routing layer");
        assert_eq!(route.next_header().get(), IpProtocol::Udp);
        assert_eq!(route.routing_type().get(), Ipv6RouteType::SourceRoute);
        assert_eq!(route.segments_left().get(), 1);
        assert_eq!(route.hdr_ext_len().get(), 4);
        assert_eq!(route.header_len(), 40);
        assert_eq!(route.data().len(), 36);

        assert!(packet.layer_viewer(Udp).is_some());
    }

    #[test]
    fn route_type_dispatches_the_sub_viewer() {
        // The type-specific data starts with the four reserved octets.
        let mut data = vec![0u8; 4];
        for addr in ["2001:db8:3::1", "2001:db8:3::2"] {
            data.extend_from_slice(&addr.parse::<core::net::Ipv6Addr>().unwrap().octets());
        }

        let bytes = route_frame(0, &data, &super::super::test_util::udp_header());

        let mut packet = Packet::new(bytes.as_slice());
        packet.parse::<Eth>(Default::default());

        let route = packet.layer_viewer(Ipv6Route).expect("routing layer");
        assert!(route.type0().is_some());

        // The type-specific payloads only fire for their own routing type.
        assert!(route.srh().is_none());
    }

    #[test]
    fn ipv6_route_viewer_mut() {
        let mut data = [17, 0, 0, 1, 0, 0, 0, 0];
        let mut route = Ipv6RouteViewer::new(&mut data[..]);

        route.next_header_mut().set(IpProtocol::Udp);
        route.hdr_ext_len_mut().set(0);
        route.segments_left_mut().set(3);

        assert_eq!(data, [17, 0, 0, 3, 0, 0, 0, 0]);
    }
}
