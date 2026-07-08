//! Dynamic Host Configuration Protocol (DHCP).
//!
//! DHCP reuses the BOOTP message layout: a 236-byte fixed BOOTP header,
//! followed by the four-byte DHCP magic cookie and a variable list of DHCP
//! options. This parser records the whole DHCP payload as one layer and exposes
//! fixed BOOTP fields plus an option iterator. The `htype` field uses values
//! from the ARP hardware type registry, but DHCP stores that value in one
//! octet.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      Op       |     HType     |     HLen      |     Hops      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              XID                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Secs                |           Flags               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            CIADDR                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            YIADDR                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            SIADDR                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            GIADDR                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        CHADDR (16 bytes)                      |
//! ~                                                               ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         SNAME (64 bytes)                      |
//! ~                                                               ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         FILE (128 bytes)                      |
//! ~                                                               ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Options                            |
//! ~                              ...                              ~
//! ```

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt, arp::ArpHardwareType},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod op;
pub mod option;

pub use op::DhcpOp;
pub use option::{DhcpOption, DhcpOptionCode, DhcpOptions};

/// Dynamic Host Configuration Protocol (DHCP) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Dhcp;

impl Dhcp {
    /// DHCP fixed header length including the magic cookie.
    const MIN_LEN: usize = 240;
}

impl Protocol for Dhcp {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dhcp = DhcpViewer::new(bytes);

        write!(
            fmt,
            "[Dhcp] {} xid {:#010x} {}",
            dhcp.op().get(),
            dhcp.xid().get(),
            dhcp.yiaddr().get()
        )
    }
}

impl ProtocolExt for Dhcp {
    type Viewer<'a> = DhcpViewer<&'a [u8]>;
    type ViewerMut<'a> = DhcpViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        ctx.require(&Dhcp, offset, Dhcp::MIN_LEN)?;

        ctx.push_layer(&Dhcp, offset, ctx.bytes.len() - offset);

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        DhcpViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        DhcpViewer::new(bytes)
    }
}

field_spec!(OpSpec, DhcpOp, u8);
field_spec!(HtypeSpec, ArpHardwareType, u8);
field_spec!(HlenSpec, u8, u8);
field_spec!(HopsSpec, u8, u8);
field_spec!(XidSpec, u32, u32);
field_spec!(SecsSpec, u16, u16);
field_spec!(FlagsSpec, u16, u16);
field_spec!(Ipv4AddrSpec, core::net::Ipv4Addr, u32);

/// Dynamic Host Configuration Protocol (DHCP).
pub struct DhcpViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> DhcpViewer<T>
where
    T: AsRef<[u8]>,
{
    /// DHCP magic cookie.
    pub const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

    /// Field range of op: 0..1
    const FIELD_OP: core::ops::Range<usize> = 0..1;
    /// Field range of htype: 1..2
    const FIELD_HTYPE: core::ops::Range<usize> = 1..2;
    /// Field range of hlen: 2..3
    const FIELD_HLEN: core::ops::Range<usize> = 2..3;
    /// Field range of hops: 3..4
    const FIELD_HOPS: core::ops::Range<usize> = 3..4;
    /// Field range of xid: 4..8
    const FIELD_XID: core::ops::Range<usize> = 4..8;
    /// Field range of secs: 8..10
    const FIELD_SECS: core::ops::Range<usize> = 8..10;
    /// Field range of flags: 10..12
    const FIELD_FLAGS: core::ops::Range<usize> = 10..12;
    /// Field range of ciaddr: 12..16
    const FIELD_CIADDR: core::ops::Range<usize> = 12..16;
    /// Field range of yiaddr: 16..20
    const FIELD_YIADDR: core::ops::Range<usize> = 16..20;
    /// Field range of siaddr: 20..24
    const FIELD_SIADDR: core::ops::Range<usize> = 20..24;
    /// Field range of giaddr: 24..28
    const FIELD_GIADDR: core::ops::Range<usize> = 24..28;
    /// Field range of chaddr: 28..44
    const FIELD_CHADDR: core::ops::Range<usize> = 28..44;
    /// Field range of sname: 44..108
    const FIELD_SNAME: core::ops::Range<usize> = 44..108;
    /// Field range of file: 108..236
    const FIELD_FILE: core::ops::Range<usize> = 108..236;
    /// Field range of magic cookie: 236..240
    const FIELD_MAGIC_COOKIE: core::ops::Range<usize> = 236..240;

    /// Create a new DHCP viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Return whether the DHCP magic cookie is present.
    #[inline]
    pub fn has_magic_cookie(&self) -> bool {
        self.data.as_ref()[Self::FIELD_MAGIC_COOKIE] == Self::MAGIC_COOKIE
    }

    /// Iterate over DHCP options.
    #[inline]
    pub fn options(&self) -> DhcpOptions<'_> {
        DhcpOptions::new(self.options_bytes())
    }

    /// Get raw DHCP option bytes after the magic cookie.
    #[inline]
    pub fn options_bytes(&self) -> &[u8] {
        if self.data.as_ref().len() <= Dhcp::MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[Dhcp::MIN_LEN..]
        }
    }

    /// Get the accessor of op.
    #[inline]
    pub fn op(&self) -> FieldRef<'_, OpSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_OP])
    }

    /// Get the accessor of htype.
    #[inline]
    pub fn htype(&self) -> FieldRef<'_, HtypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_HTYPE])
    }

    /// Get the accessor of hlen.
    #[inline]
    pub fn hlen(&self) -> FieldRef<'_, HlenSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_HLEN])
    }

    /// Get the accessor of hops.
    #[inline]
    pub fn hops(&self) -> FieldRef<'_, HopsSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_HOPS])
    }

    /// Get the accessor of xid.
    #[inline]
    pub fn xid(&self) -> FieldRef<'_, XidSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_XID])
    }

    /// Get the accessor of secs.
    #[inline]
    pub fn secs(&self) -> FieldRef<'_, SecsSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SECS])
    }

    /// Get the accessor of flags.
    #[inline]
    pub fn flags(&self) -> FieldRef<'_, FlagsSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS])
    }

    /// Get the accessor of ciaddr.
    #[inline]
    pub fn ciaddr(&self) -> FieldRef<'_, Ipv4AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CIADDR])
    }

    /// Get the accessor of yiaddr.
    #[inline]
    pub fn yiaddr(&self) -> FieldRef<'_, Ipv4AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_YIADDR])
    }

    /// Get the accessor of siaddr.
    #[inline]
    pub fn siaddr(&self) -> FieldRef<'_, Ipv4AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SIADDR])
    }

    /// Get the accessor of giaddr.
    #[inline]
    pub fn giaddr(&self) -> FieldRef<'_, Ipv4AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_GIADDR])
    }

    /// Get the client hardware address bytes.
    #[inline]
    pub fn chaddr(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_CHADDR]
    }

    /// Get the active client hardware address bytes using HLEN.
    #[inline]
    pub fn client_hardware_addr(&self) -> &[u8] {
        let len = (self.hlen().get() as usize).min(Self::FIELD_CHADDR.len());
        &self.data.as_ref()[Self::FIELD_CHADDR.start..Self::FIELD_CHADDR.start + len]
    }

    /// Get the server host name bytes.
    #[inline]
    pub fn sname(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_SNAME]
    }

    /// Get the boot file name bytes.
    #[inline]
    pub fn boot_file(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_FILE]
    }

    /// Get the magic cookie bytes.
    #[inline]
    pub fn magic_cookie(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_MAGIC_COOKIE]
    }
}

impl<T> DhcpViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get mutable raw DHCP option bytes after the magic cookie.
    #[inline]
    pub fn options_bytes_mut(&mut self) -> &mut [u8] {
        let data = self.data.as_mut();
        if data.len() <= Dhcp::MIN_LEN {
            &mut data[0..0]
        } else {
            &mut data[Dhcp::MIN_LEN..]
        }
    }

    /// Get the mutable accessor of op.
    #[inline]
    pub fn op_mut(&mut self) -> FieldMut<'_, OpSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_OP])
    }

    /// Get the mutable accessor of htype.
    #[inline]
    pub fn htype_mut(&mut self) -> FieldMut<'_, HtypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_HTYPE])
    }

    /// Get the mutable accessor of hlen.
    #[inline]
    pub fn hlen_mut(&mut self) -> FieldMut<'_, HlenSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_HLEN])
    }

    /// Get the mutable accessor of hops.
    #[inline]
    pub fn hops_mut(&mut self) -> FieldMut<'_, HopsSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_HOPS])
    }

    /// Get the mutable accessor of xid.
    #[inline]
    pub fn xid_mut(&mut self) -> FieldMut<'_, XidSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_XID])
    }

    /// Get the mutable accessor of secs.
    #[inline]
    pub fn secs_mut(&mut self) -> FieldMut<'_, SecsSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SECS])
    }

    /// Get the mutable accessor of flags.
    #[inline]
    pub fn flags_mut(&mut self) -> FieldMut<'_, FlagsSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS])
    }

    /// Get the mutable accessor of ciaddr.
    #[inline]
    pub fn ciaddr_mut(&mut self) -> FieldMut<'_, Ipv4AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CIADDR])
    }

    /// Get the mutable accessor of yiaddr.
    #[inline]
    pub fn yiaddr_mut(&mut self) -> FieldMut<'_, Ipv4AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_YIADDR])
    }

    /// Get the mutable accessor of siaddr.
    #[inline]
    pub fn siaddr_mut(&mut self) -> FieldMut<'_, Ipv4AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SIADDR])
    }

    /// Get the mutable accessor of giaddr.
    #[inline]
    pub fn giaddr_mut(&mut self) -> FieldMut<'_, Ipv4AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_GIADDR])
    }

    /// Get mutable client hardware address bytes.
    #[inline]
    pub fn chaddr_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_CHADDR]
    }

    /// Get mutable server host name bytes.
    #[inline]
    pub fn sname_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_SNAME]
    }

    /// Get mutable boot file name bytes.
    #[inline]
    pub fn boot_file_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_FILE]
    }
}

impl<T> core::fmt::Debug for DhcpViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dhcp")
            .field("op", &self.op().get())
            .field("htype", &self.htype().get())
            .field("hlen", &self.hlen().get())
            .field("xid", &self.xid().get())
            .field("ciaddr", &self.ciaddr().get())
            .field("yiaddr", &self.yiaddr().get())
            .field("siaddr", &self.siaddr().get())
            .field("giaddr", &self.giaddr().get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    fn discover_packet() -> [u8; 244] {
        let mut data = [0; 244];
        data[0] = 1; // boot request
        data[1] = 1; // ethernet
        data[2] = 6; // mac length
        data[4..8].copy_from_slice(&0x3903_f326_u32.to_be_bytes());
        data[10..12].copy_from_slice(&0x8000_u16.to_be_bytes());
        data[28..34].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data[236..240].copy_from_slice(&DhcpViewer::<&[u8]>::MAGIC_COOKIE);
        data[240] = 53; // DHCP Message Type
        data[241] = 1;
        data[242] = 1; // Discover
        data[243] = 255; // End
        data
    }

    #[test]
    fn dhcp_viewer() {
        let data = discover_packet();
        let dhcp = DhcpViewer::new(&data);
        let options: Vec<_> = dhcp.options().collect();

        assert_eq!(dhcp.op(), DhcpOp::BootRequest);
        assert_eq!(dhcp.htype(), ArpHardwareType::Ethernet);
        assert_eq!(dhcp.hlen(), 6);
        assert_eq!(dhcp.xid(), 0x3903_f326);
        assert_eq!(dhcp.flags(), 0x8000);
        assert_eq!(dhcp.ciaddr(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(
            dhcp.client_hardware_addr(),
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert!(dhcp.has_magic_cookie());
        assert_eq!(
            options[0],
            DhcpOption::Option {
                code: DhcpOptionCode::MessageType,
                len: 1,
                data: &[1],
            }
        );
        assert_eq!(options[1], DhcpOption::End);
    }

    #[test]
    fn dhcp_viewer_mut() {
        let mut data = [0; 240];
        let mut dhcp = DhcpViewer::new(&mut data);

        dhcp.op_mut().set(DhcpOp::BootReply);
        dhcp.htype_mut().set(ArpHardwareType::Ethernet);
        dhcp.hlen_mut().set(6);
        dhcp.xid_mut().set(0x3903_f326);
        dhcp.yiaddr_mut().set(Ipv4Addr::new(192, 0, 2, 10));
        dhcp.chaddr_mut()[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        assert_eq!(data[0], 2);
        assert_eq!(data[1], 1);
        assert_eq!(&data[4..8], &0x3903_f326_u32.to_be_bytes());
        assert_eq!(&data[16..20], &[192, 0, 2, 10]);
        assert_eq!(&data[28..34], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn parse_ethernet_ipv4_udp_dhcp_packet() {
        let dhcp = discover_packet();
        let mut data = Vec::new();
        data.extend_from_slice(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // destination MAC
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // version + ihl
            0x00, // dscp + ecn
        ]);
        data.extend_from_slice(&(20u16 + 8 + dhcp.len() as u16).to_be_bytes());
        data.extend_from_slice(&[
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x11, // protocol: UDP
            0x00, 0x00, // checksum
            0, 0, 0, 0, // source IP
            255, 255, 255, 255, // destination IP
            0x00, 0x44, // source port 68
            0x00, 0x43, // destination port 67
        ]);
        data.extend_from_slice(&(8u16 + dhcp.len() as u16).to_be_bytes());
        data.extend_from_slice(&[0x00, 0x00]); // UDP checksum
        data.extend_from_slice(&dhcp);

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let dhcp = packet.layer_viewer(Dhcp).expect("DHCP layer not found");
        assert_eq!(dhcp.op(), DhcpOp::BootRequest);
        assert_eq!(dhcp.xid(), 0x3903_f326);
    }
}
