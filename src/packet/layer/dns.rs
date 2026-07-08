//! Domain Name System (DNS).
//!
//! DNS messages start with a fixed 12-byte header containing the transaction
//! ID, flag bits, and record-section counts. The question and resource record
//! sections follow the fixed header; this layer currently exposes the header
//! fields and raw trailing DNS payload bytes.
//!
//! ```text
//!   0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                              ID                               |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |QR |    Opcode     |AA |TC |RD |RA | Z |AD |CD |     RCODE     |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                           QDCOUNT                             |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                           ANCOUNT                             |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                           NSCOUNT                             |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                           ARCOUNT                             |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                  Questions / resource records                 |
//! ~                              ...                              ~
//! ```

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod opcode;
pub mod rcode;

pub use opcode::DnsOpcode;
pub use rcode::DnsRcode;

/// Domain Name System (DNS) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Dns;

impl Dns {
    /// DNS fixed header length.
    const MIN_LEN: usize = 12;
}

impl Protocol for Dns {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dns = DnsViewer::new(bytes);

        write!(
            fmt,
            "[Dns] id {} {} qd {} an {}",
            dns.id().get(),
            dns.opcode().get(),
            dns.qdcount().get(),
            dns.ancount().get()
        )
    }
}

impl ProtocolExt for Dns {
    type Viewer<'a> = DnsViewer<&'a [u8]>;
    type ViewerMut<'a> = DnsViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        ctx.require(&Dns, offset, Dns::MIN_LEN)?;

        ctx.push_layer(&Dns, offset, ctx.bytes.len() - offset);

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        DnsViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        DnsViewer::new(bytes)
    }
}

field_spec!(IdSpec, u16, u16);
field_spec!(QrSpec, bool, u8, 0x80, 7);
field_spec!(OpcodeSpec, DnsOpcode, u8, 0x78, 3);
field_spec!(AaSpec, bool, u8, 0x04, 2);
field_spec!(TcSpec, bool, u8, 0x02, 1);
field_spec!(RdSpec, bool, u8, 0x01);
field_spec!(RaSpec, bool, u8, 0x80, 7);
field_spec!(ZSpec, bool, u8, 0x40, 6);
field_spec!(AdSpec, bool, u8, 0x20, 5);
field_spec!(CdSpec, bool, u8, 0x10, 4);
field_spec!(RcodeSpec, DnsRcode, u8, 0x0F);
field_spec!(CountSpec, u16, u16);

/// Domain Name System (DNS).
///
/// ```text
///   0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// |                              ID                               |
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// |QR |    Opcode     |AA |TC |RD |RA | Z |AD |CD |     RCODE     |
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// |                           QDCOUNT                             |
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// |                           ANCOUNT                             |
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// |                           NSCOUNT                             |
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// |                           ARCOUNT                             |
/// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// ```
pub struct DnsViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> DnsViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the message ID: 0..2
    const FIELD_ID: core::ops::Range<usize> = 0..2;
    /// Field range of the first flags byte: 2..3
    const FIELD_FLAGS_HI: core::ops::Range<usize> = 2..3;
    /// Field range of the second flags byte: 3..4
    const FIELD_FLAGS_LO: core::ops::Range<usize> = 3..4;
    /// Field range of QDCOUNT: 4..6
    const FIELD_QDCOUNT: core::ops::Range<usize> = 4..6;
    /// Field range of ANCOUNT: 6..8
    const FIELD_ANCOUNT: core::ops::Range<usize> = 6..8;
    /// Field range of NSCOUNT: 8..10
    const FIELD_NSCOUNT: core::ops::Range<usize> = 8..10;
    /// Field range of ARCOUNT: 10..12
    const FIELD_ARCOUNT: core::ops::Range<usize> = 10..12;

    /// Create a new DNS viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get DNS payload bytes after the fixed header.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        if self.data.as_ref().len() <= Dns::MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[Dns::MIN_LEN..]
        }
    }

    /// Get the accessor of the message ID.
    #[inline]
    pub fn id(&self) -> FieldRef<'_, IdSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ID])
    }

    /// Get whether this is a response.
    #[inline]
    pub fn qr(&self) -> FieldRef<'_, QrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_HI])
    }

    /// Get the accessor of the opcode.
    #[inline]
    pub fn opcode(&self) -> FieldRef<'_, OpcodeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_HI])
    }

    /// Get the authoritative-answer flag.
    #[inline]
    pub fn aa(&self) -> FieldRef<'_, AaSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_HI])
    }

    /// Get the truncation flag.
    #[inline]
    pub fn tc(&self) -> FieldRef<'_, TcSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_HI])
    }

    /// Get the recursion-desired flag.
    #[inline]
    pub fn rd(&self) -> FieldRef<'_, RdSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_HI])
    }

    /// Get the recursion-available flag.
    #[inline]
    pub fn ra(&self) -> FieldRef<'_, RaSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_LO])
    }

    /// Get the reserved Z bit.
    #[inline]
    pub fn z(&self) -> FieldRef<'_, ZSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_LO])
    }

    /// Get the authenticated-data flag.
    #[inline]
    pub fn ad(&self) -> FieldRef<'_, AdSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_LO])
    }

    /// Get the checking-disabled flag.
    #[inline]
    pub fn cd(&self) -> FieldRef<'_, CdSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_LO])
    }

    /// Get the accessor of the response code.
    #[inline]
    pub fn rcode(&self) -> FieldRef<'_, RcodeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_LO])
    }

    /// Get the question count.
    #[inline]
    pub fn qdcount(&self) -> FieldRef<'_, CountSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_QDCOUNT])
    }

    /// Get the answer count.
    #[inline]
    pub fn ancount(&self) -> FieldRef<'_, CountSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ANCOUNT])
    }

    /// Get the authority count.
    #[inline]
    pub fn nscount(&self) -> FieldRef<'_, CountSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_NSCOUNT])
    }

    /// Get the additional record count.
    #[inline]
    pub fn arcount(&self) -> FieldRef<'_, CountSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ARCOUNT])
    }
}

impl<T> DnsViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get mutable DNS payload bytes after the fixed header.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.data.as_mut();
        if data.len() <= Dns::MIN_LEN {
            &mut data[0..0]
        } else {
            &mut data[Dns::MIN_LEN..]
        }
    }

    /// Get the mutable accessor of the message ID.
    #[inline]
    pub fn id_mut(&mut self) -> FieldMut<'_, IdSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ID])
    }

    /// Get the mutable response flag.
    #[inline]
    pub fn qr_mut(&mut self) -> FieldMut<'_, QrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_HI])
    }

    /// Get the mutable accessor of the opcode.
    #[inline]
    pub fn opcode_mut(&mut self) -> FieldMut<'_, OpcodeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_HI])
    }

    /// Get the mutable authoritative-answer flag.
    #[inline]
    pub fn aa_mut(&mut self) -> FieldMut<'_, AaSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_HI])
    }

    /// Get the mutable truncation flag.
    #[inline]
    pub fn tc_mut(&mut self) -> FieldMut<'_, TcSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_HI])
    }

    /// Get the mutable recursion-desired flag.
    #[inline]
    pub fn rd_mut(&mut self) -> FieldMut<'_, RdSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_HI])
    }

    /// Get the mutable recursion-available flag.
    #[inline]
    pub fn ra_mut(&mut self) -> FieldMut<'_, RaSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_LO])
    }

    /// Get the mutable reserved Z bit.
    #[inline]
    pub fn z_mut(&mut self) -> FieldMut<'_, ZSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_LO])
    }

    /// Get the mutable authenticated-data flag.
    #[inline]
    pub fn ad_mut(&mut self) -> FieldMut<'_, AdSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_LO])
    }

    /// Get the mutable checking-disabled flag.
    #[inline]
    pub fn cd_mut(&mut self) -> FieldMut<'_, CdSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_LO])
    }

    /// Get the mutable accessor of the response code.
    #[inline]
    pub fn rcode_mut(&mut self) -> FieldMut<'_, RcodeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_LO])
    }

    /// Get the mutable question count.
    #[inline]
    pub fn qdcount_mut(&mut self) -> FieldMut<'_, CountSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_QDCOUNT])
    }

    /// Get the mutable answer count.
    #[inline]
    pub fn ancount_mut(&mut self) -> FieldMut<'_, CountSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ANCOUNT])
    }

    /// Get the mutable authority count.
    #[inline]
    pub fn nscount_mut(&mut self) -> FieldMut<'_, CountSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_NSCOUNT])
    }

    /// Get the mutable additional record count.
    #[inline]
    pub fn arcount_mut(&mut self) -> FieldMut<'_, CountSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ARCOUNT])
    }
}

impl<T> core::fmt::Debug for DnsViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dns")
            .field("id", &self.id().get())
            .field("qr", &self.qr().get())
            .field("opcode", &self.opcode().get())
            .field("ad", &self.ad().get())
            .field("cd", &self.cd().get())
            .field("rcode", &self.rcode().get())
            .field("qdcount", &self.qdcount().get())
            .field("ancount", &self.ancount().get())
            .field("nscount", &self.nscount().get())
            .field("arcount", &self.arcount().get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    #[test]
    fn dns_viewer() {
        let data: [u8; 12] = [
            0x12, 0x34, // id
            0x81, 0x80, // standard response, recursion available, no error
            0x00, 0x01, // qdcount
            0x00, 0x01, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];

        let dns = DnsViewer::new(&data);

        assert_eq!(dns.id(), 0x1234);
        assert_eq!(dns.qr(), true);
        assert_eq!(dns.opcode(), DnsOpcode::Query);
        assert_eq!(dns.rd(), true);
        assert_eq!(dns.ra(), true);
        assert_eq!(dns.z(), false);
        assert_eq!(dns.ad(), false);
        assert_eq!(dns.cd(), false);
        assert_eq!(dns.rcode(), DnsRcode::NoError);
        assert_eq!(dns.qdcount(), 1);
        assert_eq!(dns.ancount(), 1);
        assert_eq!(dns.nscount(), 0);
        assert_eq!(dns.arcount(), 0);
    }

    #[test]
    fn dns_viewer_mut() {
        let mut data: [u8; 12] = [0; 12];

        let mut dns = DnsViewer::new(&mut data);
        dns.id_mut().set(0x1234);
        dns.qr_mut().set(true);
        dns.opcode_mut().set(DnsOpcode::Query);
        dns.rd_mut().set(true);
        dns.ra_mut().set(true);
        dns.ad_mut().set(true);
        dns.cd_mut().set(true);
        dns.rcode_mut().set(DnsRcode::NoError);
        dns.qdcount_mut().set(1);
        dns.ancount_mut().set(1);

        assert_eq!(
            data,
            [
                0x12, 0x34, // id
                0x81, 0xb0, // flags
                0x00, 0x01, // qdcount
                0x00, 0x01, // ancount
                0x00, 0x00, // nscount
                0x00, 0x00, // arcount
            ]
        );
    }

    #[test]
    fn parse_ethernet_ipv4_udp_dns_packet() {
        let data: [u8; 54] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // version + ihl
            0x00, // dscp + ecn
            0x00, 0x28, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x11, // protocol: UDP
            0x00, 0x00, // checksum
            10, 0, 1, 1, // source IP
            10, 0, 1, 2, // destination IP
            0x30, 0x39, // source port 12345
            0x00, 0x35, // destination port 53
            0x00, 0x14, // length
            0x00, 0x00, // checksum
            0x12, 0x34, // id
            0x01, 0x00, // standard query, recursion desired
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let dns = packet.layer_viewer(Dns).expect("DNS layer not found");
        assert_eq!(dns.id(), 0x1234);
        assert_eq!(dns.qr(), false);
        assert_eq!(dns.opcode(), DnsOpcode::Query);
        assert_eq!(dns.rd(), true);
        assert_eq!(dns.qdcount(), 1);
    }
}
