//! Internet Group Management Protocol (IGMP).
//!
//! This parser covers the common IGMPv2-style fixed header used by membership
//! query and report messages. Message-type-specific payloads beyond this common
//! eight-byte layout are not decoded yet.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      Type     | Max Resp Time |           Checksum            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Group Address                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod message_type;

pub use message_type::IgmpType;

/// Internet Group Management Protocol (IGMP) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Igmp;

impl Igmp {
    /// IGMPv2-style fixed header length.
    const MIN_LEN: usize = 8;
}

impl Protocol for Igmp {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let igmp = IgmpViewer::new(bytes);

        write!(
            fmt,
            "[Igmp] {} {}",
            igmp.message_type().get(),
            igmp.group_addr().get()
        )
    }
}

impl ProtocolExt for Igmp {
    type Viewer<'a> = IgmpViewer<&'a [u8]>;
    type ViewerMut<'a> = IgmpViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        ctx.require(&Igmp, offset, Igmp::MIN_LEN)?;

        ctx.push_layer(&Igmp, offset, Igmp::MIN_LEN);

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        IgmpViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        IgmpViewer::new(bytes)
    }
}

field_spec!(TypeSpec, IgmpType, u8);
field_spec!(MaxRespTimeSpec, u8, u8);
field_spec!(ChecksumSpec, u16, u16);
field_spec!(Ipv4AddrSpec, core::net::Ipv4Addr, u32);

/// Internet Group Management Protocol (IGMP).
pub struct IgmpViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IgmpViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the message type: 0..1
    const FIELD_TYPE: core::ops::Range<usize> = 0..1;
    /// Field range of the max response time/code: 1..2
    const FIELD_MAX_RESP_TIME: core::ops::Range<usize> = 1..2;
    /// Field range of the checksum: 2..4
    const FIELD_CHECKSUM: core::ops::Range<usize> = 2..4;
    /// Field range of the group address: 4..8
    const FIELD_GROUP_ADDR: core::ops::Range<usize> = 4..8;

    /// Create a new IGMP viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the IGMP message type.
    #[inline]
    pub fn message_type(&self) -> FieldRef<'_, TypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TYPE])
    }

    /// Get the accessor of the max response time/code.
    #[inline]
    pub fn max_resp_time(&self) -> FieldRef<'_, MaxRespTimeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_MAX_RESP_TIME])
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, ChecksumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the accessor of the group address.
    #[inline]
    pub fn group_addr(&self) -> FieldRef<'_, Ipv4AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_GROUP_ADDR])
    }
}

impl<T> IgmpViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the IGMP message type.
    #[inline]
    pub fn message_type_mut(&mut self) -> FieldMut<'_, TypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TYPE])
    }

    /// Get the mutable accessor of the max response time/code.
    #[inline]
    pub fn max_resp_time_mut(&mut self) -> FieldMut<'_, MaxRespTimeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_MAX_RESP_TIME])
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, ChecksumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CHECKSUM])
    }

    /// Get the mutable accessor of the group address.
    #[inline]
    pub fn group_addr_mut(&mut self) -> FieldMut<'_, Ipv4AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_GROUP_ADDR])
    }
}

impl<T> core::fmt::Debug for IgmpViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Igmp")
            .field("message_type", &self.message_type().get())
            .field("max_resp_time", &self.max_resp_time().get())
            .field("checksum", &self.checksum().get())
            .field("group_addr", &self.group_addr().get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    #[test]
    fn igmp_viewer() {
        let data: [u8; 8] = [
            0x16, // type: v2 membership report
            0x00, // max response time
            0x00, 0x00, // checksum
            224, 0, 0, 1, // group address
        ];

        let igmp = IgmpViewer::new(&data);

        assert_eq!(igmp.message_type(), IgmpType::V2MembershipReport);
        assert_eq!(igmp.max_resp_time(), 0);
        assert_eq!(igmp.checksum(), 0);
        assert_eq!(igmp.group_addr(), Ipv4Addr::new(224, 0, 0, 1));
    }

    #[test]
    fn igmp_viewer_mut() {
        let mut data: [u8; 8] = [0; 8];

        let mut igmp = IgmpViewer::new(&mut data);
        igmp.message_type_mut().set(IgmpType::MembershipQuery);
        igmp.max_resp_time_mut().set(100);
        igmp.checksum_mut().set(0x1234);
        igmp.group_addr_mut().set(Ipv4Addr::new(224, 0, 0, 1));

        assert_eq!(data, [0x11, 100, 0x12, 0x34, 224, 0, 0, 1]);
    }

    #[test]
    fn parse_ethernet_ipv4_igmp_packet() {
        let data: [u8; 46] = [
            0x01, 0x00, 0x5e, 0x00, 0x00, 0x01, // destination MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // source MAC
            0x08, 0x00, // EtherType: IPv4
            0x46, // version + ihl
            0xc0, // dscp + ecn
            0x00, 0x1c, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x01, // ttl
            0x02, // protocol: IGMP
            0x00, 0x00, // checksum
            10, 0, 1, 1, // source IP
            224, 0, 0, 1, // destination IP
            0x94, 0x04, 0x00, 0x00, // Router Alert option
            0x16, // type: v2 membership report
            0x00, // max response time
            0x00, 0x00, // checksum
            224, 0, 0, 1, // group address
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let igmp = packet.layer_viewer(Igmp).expect("IGMP layer not found");
        assert_eq!(igmp.message_type(), IgmpType::V2MembershipReport);
        assert_eq!(igmp.group_addr(), Ipv4Addr::new(224, 0, 0, 1));
    }
}
