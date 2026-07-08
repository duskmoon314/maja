//! Virtual eXtensible Local Area Network (VxLAN).
//!
//! VxLAN encapsulates an inner Ethernet frame in UDP. RFC 7348 defines UDP
//! destination port 4789 for the base encapsulation and an 8-byte VxLAN header
//! before the inner Ethernet frame. The rfc7348bis draft keeps the same wire
//! length while naming the first 16 bits as VxLAN flags and the next 16 bits as
//! reserved. This parser records only the VxLAN header as the VxLAN layer and
//! then dispatches the payload as Ethernet, so callers can inspect the inner
//! packet through normal layer lookups.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Vxlan Flags          |           Reserved            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                VNI                            |   Reserved    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  Inner Ethernet frame                         |
//! ~                              ...                              ~
//! ```

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt, eth::Eth},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod flags;
pub mod vni;

pub use flags::VxlanFlags;
pub use vni::VxlanVni;

/// VxLAN protocol marker.
#[derive(Debug, Clone, Copy)]
pub struct Vxlan;

impl Vxlan {
    /// RFC 7348 VxLAN header length.
    const MIN_LEN: usize = 8;
}

impl Protocol for Vxlan {
    fn display(&self, bytes: &[u8], fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let vxlan = VxlanViewer::new(bytes);
        write!(fmt, "[Vxlan] vni {}", vxlan.vni_id())
    }
}

impl ProtocolExt for Vxlan {
    type Viewer<'a> = VxlanViewer<&'a [u8]>;
    type ViewerMut<'a> = VxlanViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        ctx.require(&Vxlan, offset, Vxlan::MIN_LEN)?;
        ctx.push_layer(&Vxlan, offset, Vxlan::MIN_LEN);
        ctx.parse_child::<Eth>(offset + Vxlan::MIN_LEN)?;
        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        VxlanViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        VxlanViewer::new(bytes)
    }
}

field_spec!(FlagsSpec, VxlanFlags, u16);
field_spec!(Reserved16Spec, u16, u16);
field_spec!(VniSpec, VxlanVni, [u8; 3]);
field_spec!(Reserved8Spec, u8, u8);

/// VxLAN header viewer.
pub struct VxlanViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> VxlanViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the 16-bit flags field: 0..2.
    const FIELD_FLAGS: core::ops::Range<usize> = 0..2;
    /// Field range of the first reserved field: 2..4.
    const FIELD_RESERVED_1: core::ops::Range<usize> = 2..4;
    /// Field range of the 24-bit VNI: 4..7.
    const FIELD_VNI: core::ops::Range<usize> = 4..7;
    /// Field range of the second reserved field: 7..8.
    const FIELD_RESERVED_2: core::ops::Range<usize> = 7..8;

    /// Create a VxLAN viewer over raw bytes.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the VxLAN flags field.
    #[inline]
    pub fn flags(&self) -> FieldRef<'_, FlagsSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS])
    }

    /// Return whether the I flag marks the VNI as valid.
    #[inline]
    pub fn vni_is_valid(&self) -> bool {
        self.flags().get().contains(VxlanFlags::I)
    }

    /// Get the first reserved 16-bit field.
    #[inline]
    pub fn reserved_1(&self) -> FieldRef<'_, Reserved16Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RESERVED_1])
    }

    /// Get the VNI field.
    #[inline]
    pub fn vni(&self) -> FieldRef<'_, VniSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_VNI])
    }

    /// Return the VNI as a numeric `u32`.
    #[inline]
    pub fn vni_id(&self) -> u32 {
        self.vni().get().get()
    }

    /// Get the trailing reserved byte.
    #[inline]
    pub fn reserved_2(&self) -> FieldRef<'_, Reserved8Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RESERVED_2])
    }
}

impl<T> VxlanViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable VxLAN flags field.
    #[inline]
    pub fn flags_mut(&mut self) -> FieldMut<'_, FlagsSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS])
    }

    /// Get the mutable first reserved 16-bit field.
    #[inline]
    pub fn reserved_1_mut(&mut self) -> FieldMut<'_, Reserved16Spec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_RESERVED_1])
    }

    /// Get the mutable VNI field.
    #[inline]
    pub fn vni_mut(&mut self) -> FieldMut<'_, VniSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_VNI])
    }

    /// Get the mutable trailing reserved byte.
    #[inline]
    pub fn reserved_2_mut(&mut self) -> FieldMut<'_, Reserved8Spec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_RESERVED_2])
    }
}

impl<T> core::fmt::Debug for VxlanViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vxlan")
            .field("flags", &self.flags().get())
            .field("vni", &self.vni().get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::{
        Packet, ParseOptions,
        layer::{
            eth::{Eth, EthType},
            ip::v4::Ipv4,
            udp::Udp,
        },
    };

    use super::*;

    #[test]
    fn vxlan_viewer_reads_and_writes_header_fields() {
        let mut data = [0x08, 0, 0, 0, 0, 0, 42, 0];

        {
            let vxlan = VxlanViewer::new(&data);
            assert!(vxlan.vni_is_valid());
            assert_eq!(vxlan.flags().get(), VxlanFlags::I);
            assert_eq!(vxlan.reserved_1().get(), 0);
            assert_eq!(vxlan.vni_id(), 42);
            assert_eq!(vxlan.reserved_2().get(), 0);
        }

        {
            let mut vxlan = VxlanViewer::new(&mut data);
            vxlan
                .vni_mut()
                .set(VxlanVni::new(0x00ab_cdef).expect("valid VNI"));
        }

        assert_eq!(&data[4..7], &[0xab, 0xcd, 0xef]);
    }

    #[test]
    fn udp_vxlan_parses_inner_ethernet_frame() {
        let data = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // outer dst mac
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, // outer src mac
            0x08, 0x00, // IPv4
            0x45, 0x00, 0x00, 0x46, // IPv4 version/IHL, total length
            0x00, 0x00, 0x00, 0x00, // identification, flags/fragment
            0x40, 0x11, 0x00, 0x00, // ttl, UDP, checksum
            192, 0, 2, 1, // outer src
            192, 0, 2, 2, // outer dst
            0xc0, 0x00, 0x12, 0xb5, // UDP src, VxLAN dst port 4789
            0x00, 0x32, 0x00, 0x00, // UDP length, checksum
            0x08, 0x00, 0x00, 0x00, // VxLAN flags, reserved
            0x00, 0x00, 0x2a, 0x00, // VNI 42, reserved
            0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // inner dst mac
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // inner src mac
            0x08, 0x00, // inner IPv4
            0x45, 0x00, 0x00, 0x14, // inner IPv4 version/IHL, total length
            0x00, 0x00, 0x00, 0x00, // identification, flags/fragment
            0x40, 0xff, 0x00, 0x00, // ttl, unknown protocol, checksum
            10, 0, 0, 1, // inner src
            10, 0, 0, 2, // inner dst
        ];

        let mut packet = Packet::new(&data);
        packet
            .try_parse::<Eth>(ParseOptions::default())
            .expect("parse VxLAN packet");

        assert_eq!(packet.layers().len(), 6);
        assert!(packet.layer_viewer(Udp).is_some());

        let vxlan = packet.layer_viewer(Vxlan).expect("vxlan layer");
        assert!(vxlan.vni_is_valid());
        assert_eq!(vxlan.vni_id(), 42);

        let vxlan_meta = packet.layer(Vxlan).expect("vxlan metadata");
        assert_eq!(vxlan_meta.range(), 42..50);

        let inner = packet.layer_viewer(Eth).expect("latest eth is inner eth");
        assert_eq!(inner.eth_type().get(), EthType::Ipv4);
        assert_eq!(
            packet
                .nth_layer_viewer(Eth, 0)
                .expect("nth 0 eth is inner eth")
                .src()
                .get()
                .to_string(),
            "02:00:00:00:00:01"
        );
        assert_eq!(
            packet
                .nth_layer_viewer(Eth, 1)
                .expect("nth 1 eth is outer eth")
                .src()
                .get()
                .to_string(),
            "10:11:12:13:14:15"
        );
        assert!(packet.nth_layer(Eth, 2).is_none());
        assert_eq!(packet.layer(Ipv4).expect("latest IPv4").offset, 64);
        assert_eq!(
            packet
                .nth_layer_viewer(Ipv4, 1)
                .expect("outer IPv4")
                .src()
                .get(),
            core::net::Ipv4Addr::new(192, 0, 2, 1)
        );

        let mut inner_packet = Packet::new(&packet.as_bytes()[vxlan_meta.range().end..]);
        inner_packet
            .try_parse::<Eth>(ParseOptions::default())
            .expect("parse extracted inner frame");
        assert_eq!(
            inner_packet
                .layer_viewer(Ipv4)
                .expect("inner IPv4")
                .src()
                .get(),
            core::net::Ipv4Addr::new(10, 0, 0, 1)
        );
    }
}
