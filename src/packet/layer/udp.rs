//! User Datagram Protocol (UDP) parsing.
//!
//! UDP has a fixed eight-byte header followed by application payload bytes.
//! This parser records only the UDP header as the UDP layer. Well-known ports
//! dispatch to DNS, DHCP, NTP, or VxLAN, custom port registrations are tried
//! next, and remaining unrecognized payload bytes are recorded as `Raw`.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Source Port          |       Destination Port        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            Length             |           Checksum            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Payload                            |
//! ~                              ...                              ~
//! ```

use std::{fmt::Debug, net::Ipv4Addr};

use crate::{
    field_spec,
    packet::{
        layer::{Protocol, ProtocolExt},
        utils::{
            checksum::ipv4_transport_checksum_zeroing,
            field::{FieldMut, FieldRef},
        },
    },
};

pub mod craft;
pub use craft::UdpBuilder;

/// User Datagram Protocol LayerKind
#[derive(Debug, Clone, Copy)]
pub struct Udp;

impl Udp {
    /// UDP header length.
    const MIN_LEN: usize = 8;

    /// Domain Name System UDP service port.
    pub const DNS_PORT: u16 = 53;

    /// DHCP server UDP service port.
    pub const DHCP_SERVER_PORT: u16 = 67;

    /// DHCP client UDP service port.
    pub const DHCP_CLIENT_PORT: u16 = 68;

    /// Network Time Protocol UDP service port.
    pub const NTP_PORT: u16 = 123;

    /// RFC 7348 VxLAN UDP destination port.
    pub const VXLAN_PORT: u16 = 4789;
}

impl Protocol for Udp {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let udp = UdpViewer::new(bytes);

        write!(
            fmt,
            "[Udp] {:<5} -> {:<5}",
            udp.src_port().get(),
            udp.dst_port().get()
        )
    }
}

impl ProtocolExt for Udp {
    type Viewer<'a> = UdpViewer<&'a [u8]>;
    type ViewerMut<'a> = UdpViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut crate::packet::ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let header = ctx.require(&Udp, offset, Udp::MIN_LEN)?;

        ctx.push_layer(&Udp, offset, Udp::MIN_LEN);

        let udp = UdpViewer::new(header);
        let src_port = udp.src_port().get();
        let dst_port = udp.dst_port().get();
        let payload_offset = offset + Udp::MIN_LEN;

        match (src_port, dst_port) {
            (Self::DNS_PORT, _) | (_, Self::DNS_PORT) => {
                ctx.parse_child::<crate::packet::layer::dns::Dns>(payload_offset)?;
            }
            (Self::DHCP_SERVER_PORT | Self::DHCP_CLIENT_PORT, _)
            | (_, Self::DHCP_SERVER_PORT | Self::DHCP_CLIENT_PORT) => {
                ctx.parse_child::<crate::packet::layer::dhcp::Dhcp>(payload_offset)?;
            }
            (Self::NTP_PORT, _) | (_, Self::NTP_PORT) => {
                ctx.parse_child::<crate::packet::layer::ntp::Ntp>(payload_offset)?;
            }
            (_, Self::VXLAN_PORT) => {
                ctx.parse_child::<crate::packet::layer::vxlan::Vxlan>(payload_offset)?;
            }
            (_, port) if ctx.options.registry.contains_key(&(Udp.id(), port.into())) => {
                let parse_fn = ctx.options.registry[&(Udp.id(), port.into())];
                ctx.parse_child_with(parse_fn, payload_offset)?;
            }
            (port, _)
                if src_port != dst_port
                    && ctx.options.registry.contains_key(&(Udp.id(), port.into())) =>
            {
                let parse_fn = ctx.options.registry[&(Udp.id(), port.into())];
                ctx.parse_child_with(parse_fn, payload_offset)?;
            }
            _ => ctx.parse_raw(payload_offset),
        }

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        UdpViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        UdpViewer::new(bytes)
    }
}

field_spec!(PortSpec, u16, u16);
field_spec!(LengthSpec, u16, u16);
field_spec!(ChecksumSpec, u16, u16);

/// User Datagram Protocol (UDP)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Length             |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct UdpViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> UdpViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the source port: 0..2
    const FIELD_SRC_PORT: core::ops::Range<usize> = 0..2;
    /// Field range of the destination port: 2..4
    const FIELD_DST_PORT: core::ops::Range<usize> = 2..4;
    /// Field range of the length: 4..6
    const FIELD_LENGTH: core::ops::Range<usize> = 4..6;
    /// Field range of the checksum: 6..8
    const FIELD_CHECKSUM: core::ops::Range<usize> = 6..8;

    /// Create a new UDP viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Calculate the UDP checksum using an IPv4 pseudo header.
    ///
    /// The checksum field is treated as zero during calculation. The UDP
    /// length field bounds the datagram bytes used from this viewer, so callers
    /// may pass either an exact UDP datagram slice or a larger slice that
    /// starts at the UDP header. To validate packets with payload, the viewer
    /// must include the payload bytes, not only the eight-byte UDP header.
    ///
    /// If the calculated one's-complement value is zero, this returns
    /// `0xffff`, which is the value transmitted for an enabled UDP checksum on
    /// IPv4. A stored checksum field of zero means checksum validation is
    /// disabled for IPv4; see [`validate_checksum_ipv4`](UdpViewer::validate_checksum_ipv4).
    #[inline]
    pub fn calculate_checksum_ipv4(&self, src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
        let data = self.data.as_ref();
        let datagram_len = usize::from(self.length().get()).min(data.len());
        let checksum = ipv4_transport_checksum_zeroing(
            src,
            dst,
            17,
            &data[..datagram_len],
            Self::FIELD_CHECKSUM,
        );
        if checksum == 0 { 0xffff } else { checksum }
    }

    /// Return whether the UDP checksum is valid for the given IPv4 endpoints.
    ///
    /// IPv4 permits a UDP checksum field of zero to mean that checksum
    /// validation was not used. This helper returns `true` for that disabled
    /// state; otherwise it recalculates the enabled checksum and compares it
    /// with the packet's checksum field.
    #[inline]
    pub fn validate_checksum_ipv4(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        let checksum = self.checksum().get();
        checksum == 0 || checksum == self.calculate_checksum_ipv4(src, dst)
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

    /// Get the accessor of the length.
    #[inline]
    pub fn length(&self) -> FieldRef<'_, LengthSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_LENGTH])
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, ChecksumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CHECKSUM])
    }
}

impl<T> UdpViewer<T>
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

    /// Get the mutable accessor of the length.
    #[inline]
    pub fn length_mut(&mut self) -> FieldMut<'_, LengthSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_LENGTH])
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, ChecksumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CHECKSUM])
    }
}

impl<T> Debug for UdpViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpViewer")
            .field("src_port", &self.src_port().get())
            .field("dst_port", &self.dst_port().get())
            .field("length", &self.length().get())
            .field("checksum", &self.checksum().get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_viewer() {
        let data: [u8; 8] = [
            0x00, 0x50, // src port
            0x00, 0x51, // dst port
            0x00, 0x0a, // length
            0x00, 0x00, // checksum
        ];

        let udp = UdpViewer::new(&data);

        assert_eq!(udp.src_port(), 80);
        assert_eq!(udp.dst_port(), 81);
        assert_eq!(udp.length(), 10);
        assert_eq!(udp.checksum(), 0);
    }

    #[test]
    fn udp_viewer_mut() {
        let mut data: [u8; 8] = [
            0x00, 0x50, // src port
            0x00, 0x51, // dst port
            0x00, 0x0a, // length
            0x00, 0x00, // checksum
        ];

        let mut udp = UdpViewer::new(&mut data);

        udp.src_port_mut().set(8080);
        udp.dst_port_mut().set(8081);
        udp.length_mut().set(20);
        udp.checksum_mut().set(0xffff);

        assert_eq!(data, [0x1f, 0x90, 0x1f, 0x91, 0x00, 0x14, 0xff, 0xff]);
    }

    #[test]
    fn udp_checksum_helpers() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(192, 0, 2, 2);
        let mut data = [
            0x30, 0x39, // src port
            0x00, 0x35, // dst port
            0x00, 0x0a, // length
            0x00, 0x00, // checksum
            b'h', b'i',
        ];

        assert!(UdpViewer::new(&data).validate_checksum_ipv4(src, dst));

        {
            let mut udp = UdpViewer::new(&mut data);
            let checksum = udp.calculate_checksum_ipv4(src, dst);
            udp.checksum_mut().set(checksum);
        }

        assert!(UdpViewer::new(&data).validate_checksum_ipv4(src, dst));

        data[9] = b'o';
        assert!(!UdpViewer::new(&data).validate_checksum_ipv4(src, dst));
    }
}
