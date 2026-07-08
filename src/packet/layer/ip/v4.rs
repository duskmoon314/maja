//! Internet Protocol version 4 (IPv4) parsing.
//!
//! IPv4 starts with a variable-length header. The IHL field gives the header
//! length in 32-bit words; bytes beyond the 20-byte fixed header are exposed as
//! raw IPv4 options and can be iterated with [`option_iter`](Ipv4Viewer::option_iter).
//! Fragmented packets with a non-zero fragment offset are not dispatched into a
//! transport parser and their remaining payload is recorded as `Raw`.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Version|  IHL  |  DSCP   | ECN |          Total Length         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Identification        |Flags|      Fragment Offset    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Time to Live |    Protocol   |        Header Checksum        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Source Address                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Destination Address                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Options (if IHL > 5)       |    Padding    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Payload                            |
//! ~                              ...                              ~
//! ```

use crate::{
    field_spec, impl_target,
    packet::{
        layer::{Protocol, ProtocolExt, ip::protocol::IpProtocol},
        utils::{
            checksum::internet_checksum_zeroing,
            field::{FieldMut, FieldRef},
        },
    },
};

pub mod craft;
pub mod option;

pub use craft::Ipv4Builder;
pub use option::{Ipv4Option, Ipv4OptionKind, Ipv4Options};

/// Ipv4 LayerKind
#[derive(Debug, Clone, Copy)]
pub struct Ipv4;

impl Ipv4 {
    /// Minimum IPv4 header length.
    const MIN_LEN: usize = 20;
}

impl Protocol for Ipv4 {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ipv4 = Ipv4Viewer::new(bytes);

        write!(
            fmt,
            "[Ipv4] {:<15} -> {:<15} {:<4}",
            ipv4.src().get(),
            ipv4.dst().get(),
            ipv4.total_length().get()
        )
    }
}

impl ProtocolExt for Ipv4 {
    type Viewer<'a> = Ipv4Viewer<&'a [u8]>;
    type ViewerMut<'a> = Ipv4Viewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut crate::packet::ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let min_header = ctx.require(&Ipv4, offset, Ipv4::MIN_LEN)?;

        let ipv4 = Ipv4Viewer::new(min_header);
        let header_len = ipv4.header_len();
        if header_len < Ipv4::MIN_LEN {
            return Err(crate::packet::error::ParseError::Malformed {
                protocol: &Ipv4,
                field: "ihl",
                reason: "header length is smaller than the minimum IPv4 header length",
            });
        }

        let header = ctx.require(&Ipv4, offset, header_len)?;

        ctx.push_layer(&Ipv4, offset, header_len);

        let ipv4 = Ipv4Viewer::new(header);
        if ipv4.fragment_offset().get() != 0 {
            ctx.parse_raw(offset + header_len);
            return Ok(());
        }

        match ipv4.protocol().get() {
            IpProtocol::Icmp => {
                ctx.parse_child::<crate::packet::layer::icmp::Icmp>(offset + header_len)?;
            }

            IpProtocol::Igmp => {
                ctx.parse_child::<crate::packet::layer::igmp::Igmp>(offset + header_len)?;
            }

            IpProtocol::Gre => {
                ctx.parse_child::<crate::packet::layer::gre::Gre>(offset + header_len)?;
            }

            IpProtocol::Tcp => {
                ctx.parse_child::<crate::packet::layer::tcp::Tcp>(offset + header_len)?;
            }

            IpProtocol::Udp => {
                ctx.parse_child::<crate::packet::layer::udp::Udp>(offset + header_len)?;
            }

            IpProtocol::Sctp => {
                ctx.parse_child::<crate::packet::layer::sctp::Sctp>(offset + header_len)?;
            }

            protocol
                if ctx
                    .options
                    .registry
                    .contains_key(&(Ipv4.id(), protocol.into())) =>
            {
                let parse_fn = ctx.options.registry[&(Ipv4.id(), protocol.into())];
                ctx.parse_child_with(parse_fn, offset + header_len)?;
            }

            _ => ctx.parse_raw(offset + header_len),
        }

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        Ipv4Viewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        Ipv4Viewer::new(bytes)
    }
}

impl_target!(frominto, core::net::Ipv4Addr, u32);

field_spec!(VersionSpec, u8, u8, 0xF0, 4);
field_spec!(IhlSpec, u8, u8, 0x0F);
field_spec!(DscpSpec, u8, u8, 0xFC, 2);
field_spec!(EcnSpec, u8, u8, 0x03);
field_spec!(TosSpec, u8, u8);
field_spec!(TotalLengthSpec, u16, u16);
field_spec!(IdentificationSpec, u16, u16);
field_spec!(FlagsSpec, u8, u8, 0xE0, 5);
field_spec!(FragmentOffsetSpec, u16, u16, 0x1FFF);
field_spec!(TtlSpec, u8, u8);
field_spec!(ProtocolSpec, IpProtocol, u8, 0xFF);
field_spec!(ChecksumSpec, u16, u16);
field_spec!(Ipv4AddrSpec, core::net::Ipv4Addr, u32);

/// Zero-copy viewer for an IPv4 header.
///
/// The viewer exposes fixed header fields and option bytes through typed field
/// accessors. The minimum IPv4 header is 20 bytes; callers that construct a
/// viewer directly must ensure the backing slice covers the header length.
pub struct Ipv4Viewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Ipv4Viewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the version: 0..1 (4bits)
    const FIELD_VERSION: core::ops::Range<usize> = 0..1;
    /// Field range of the ihl: 0..1 (4bits)
    const FIELD_IHL: core::ops::Range<usize> = 0..1;
    /// Field range of the dscp: 1..2 (6bits)
    const FIELD_DSCP: core::ops::Range<usize> = 1..2;
    /// Field range of the ecn: 1..2 (2bits)
    const FIELD_ECN: core::ops::Range<usize> = 1..2;
    /// Field range of the tos: 1..2
    const FIELD_TOS: core::ops::Range<usize> = 1..2;
    /// Field range of the total length: 2..4
    const FIELD_TOTAL_LENGTH: core::ops::Range<usize> = 2..4;
    /// Field range of the identification: 4..6
    const FIELD_IDENTIFICATION: core::ops::Range<usize> = 4..6;
    /// Field range of the flags: 6..7 (3bits)
    const FIELD_FLAGS: core::ops::Range<usize> = 6..7;
    /// Field range of the fragment offset: 6..8 (13bits)
    const FIELD_FRAGMENT_OFFSET: core::ops::Range<usize> = 6..8;
    /// Field range of the ttl: 8..9
    const FIELD_TTL: core::ops::Range<usize> = 8..9;
    /// Field range of the protocol: 9..10
    const FIELD_PROTOCOL: core::ops::Range<usize> = 9..10;
    /// Field range of the checksum: 10..12
    const FIELD_CHECKSUM: core::ops::Range<usize> = 10..12;
    /// Field range of the src: 12..16
    const FIELD_SRC: core::ops::Range<usize> = 12..16;
    /// Field range of the dst: 16..20
    const FIELD_DST: core::ops::Range<usize> = 16..20;

    /// Create a new Ipv4Viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Return the IPv4 header length in octets.
    #[inline]
    pub fn header_len(&self) -> usize {
        self.ihl().get() as usize * 4
    }

    /// Get the raw IPv4 options bytes.
    #[inline]
    pub fn options(&self) -> &[u8] {
        let len = self.header_len().min(self.data.as_ref().len());
        if len <= Ipv4::MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[Ipv4::MIN_LEN..len]
        }
    }

    /// Iterate over IPv4 options.
    #[inline]
    pub fn option_iter(&self) -> Ipv4Options<'_> {
        Ipv4Options::new(self.options())
    }

    /// Calculate the IPv4 header checksum for this header.
    ///
    /// The checksum field is treated as zero during calculation. If this
    /// viewer was created from a full IPv4 packet, only the bytes covered by
    /// the IHL field are used.
    #[inline]
    pub fn calculate_checksum(&self) -> u16 {
        let data = self.data.as_ref();
        let header_len = self.header_len().min(data.len());
        internet_checksum_zeroing(&data[..header_len], Self::FIELD_CHECKSUM)
    }

    /// Return whether the IPv4 header checksum matches the header bytes.
    ///
    /// This helper validates only the IPv4 header checksum. It does not
    /// validate transport checksums in TCP, UDP, or ICMP payloads.
    #[inline]
    pub fn validate_checksum(&self) -> bool {
        self.checksum().get() == self.calculate_checksum()
    }

    /// Get the accessor of the version.
    #[inline]
    pub fn version(&self) -> FieldRef<'_, VersionSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_VERSION])
    }

    /// Get the accessor of the ihl.
    #[inline]
    pub fn ihl(&self) -> FieldRef<'_, IhlSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_IHL])
    }

    /// Get the accessor of the dscp.
    #[inline]
    pub fn dscp(&self) -> FieldRef<'_, DscpSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DSCP])
    }

    /// Get the accessor of the ecn.
    #[inline]
    pub fn ecn(&self) -> FieldRef<'_, EcnSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ECN])
    }

    /// Get the accessor of the tos.
    #[inline]
    pub fn tos(&self) -> FieldRef<'_, TosSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TOS])
    }

    /// Get the accessor of the total length.
    #[inline]
    pub fn total_length(&self) -> FieldRef<'_, TotalLengthSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TOTAL_LENGTH])
    }

    /// Get the accessor of the identification.
    #[inline]
    pub fn identification(&self) -> FieldRef<'_, IdentificationSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_IDENTIFICATION])
    }

    /// Get the accessor of the flags.
    #[inline]
    pub fn flags(&self) -> FieldRef<'_, FlagsSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS])
    }

    /// Get the accessor of the fragment offset.
    #[inline]
    pub fn fragment_offset(&self) -> FieldRef<'_, FragmentOffsetSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FRAGMENT_OFFSET])
    }

    /// Get the accessor of the ttl.
    #[inline]
    pub fn ttl(&self) -> FieldRef<'_, TtlSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TTL])
    }

    /// Get the accessor of the protocol.
    #[inline]
    pub fn protocol(&self) -> FieldRef<'_, ProtocolSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PROTOCOL])
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, ChecksumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the accessor of the src ip address.
    #[inline]
    pub fn src(&self) -> FieldRef<'_, Ipv4AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SRC])
    }

    /// Get the accessor of the dst ip address.
    #[inline]
    pub fn dst(&self) -> FieldRef<'_, Ipv4AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DST])
    }
}

impl<T> Ipv4Viewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable raw IPv4 options bytes.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let len = self.header_len().min(self.data.as_ref().len());
        let data = self.data.as_mut();
        if len <= Ipv4::MIN_LEN {
            &mut data[0..0]
        } else {
            &mut data[Ipv4::MIN_LEN..len]
        }
    }

    /// Get the mutable accessor of the version.
    #[inline]
    pub fn version_mut(&mut self) -> FieldMut<'_, VersionSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_VERSION])
    }

    /// Get the mutable accessor of the ihl.
    #[inline]
    pub fn ihl_mut(&mut self) -> FieldMut<'_, IhlSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_IHL])
    }

    /// Get the mutable accessor of the dscp.
    #[inline]
    pub fn dscp_mut(&mut self) -> FieldMut<'_, DscpSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_DSCP])
    }

    /// Get the mutable accessor of the ecn.
    #[inline]
    pub fn ecn_mut(&mut self) -> FieldMut<'_, EcnSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ECN])
    }

    /// Get the mutable accessor of the tos.
    #[inline]
    pub fn tos_mut(&mut self) -> FieldMut<'_, TosSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TOS])
    }

    /// Get the mutable accessor of the total length.
    #[inline]
    pub fn total_length_mut(&mut self) -> FieldMut<'_, TotalLengthSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TOTAL_LENGTH])
    }

    /// Get the mutable accessor of the identification.
    #[inline]
    pub fn identification_mut(&mut self) -> FieldMut<'_, IdentificationSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_IDENTIFICATION])
    }

    /// Get the mutable accessor of the flags.
    #[inline]
    pub fn flags_mut(&mut self) -> FieldMut<'_, FlagsSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS])
    }

    /// Get the mutable accessor of the fragment offset.
    #[inline]
    pub fn fragment_offset_mut(&mut self) -> FieldMut<'_, FragmentOffsetSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FRAGMENT_OFFSET])
    }

    /// Get the mutable accessor of the ttl.
    #[inline]
    pub fn ttl_mut(&mut self) -> FieldMut<'_, TtlSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TTL])
    }

    /// Get the mutable accessor of the protocol.
    #[inline]
    pub fn protocol_mut(&mut self) -> FieldMut<'_, ProtocolSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PROTOCOL])
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, ChecksumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CHECKSUM])
    }

    /// Get the mutable accessor of the src ip address.
    #[inline]
    pub fn src_mut(&mut self) -> FieldMut<'_, Ipv4AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SRC])
    }

    /// Get the mutable accessor of the dst ip address.
    #[inline]
    pub fn dst_mut(&mut self) -> FieldMut<'_, Ipv4AddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_DST])
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::layer::eth::Eth;

    use super::*;

    #[test]
    fn ipv4_viewer() {
        let data: [u8; 20] = [
            0x45, // version 4, ihl 5
            0x00, // dscp 0, ecn 0
            0x00, 0x20, // total length 20 + 8 + 4 = 32 (Assume a UDP with 4 bytes data)
            0x00, 0x00, // identification 0
            0x00, 0x00, // flags 0, fragment offset 0
            0x40, // ttl 64
            0x11, // protocol udp
            0x00, 0x00, // checksum 0 (TODO: check this)
            0x7f, 0x00, 0x00, 0x01, // src ip
            0x7f, 0x00, 0x00, 0x02, // dst ip
        ];

        let ipv4 = Ipv4Viewer::new(data);

        assert_eq!(ipv4.version(), 4);
        assert_eq!(ipv4.ihl(), 5);
        assert_eq!(ipv4.dscp(), 0);
        assert_eq!(ipv4.ecn(), 0);
        assert_eq!(ipv4.tos(), 0);
        assert_eq!(ipv4.total_length(), 32);
        assert_eq!(ipv4.identification(), 0);
        assert_eq!(ipv4.flags(), 0);
        assert_eq!(ipv4.fragment_offset(), 0);
        assert_eq!(ipv4.ttl(), 64);
        assert_eq!(ipv4.protocol(), IpProtocol::Udp);
        assert_eq!(ipv4.checksum(), 0);
        assert_eq!(ipv4.src(), core::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ipv4.dst(), core::net::Ipv4Addr::new(127, 0, 0, 2));
    }

    #[test]
    fn ipv4_viewer_mut() {
        let mut data: [u8; 20] = [
            0x45, // version 4, ihl 5
            0x00, // dscp 0, ecn 0
            0x00, 0x20, // total length 20 + 8 + 4 = 32 (Assume a UDP with 4 bytes data)
            0x00, 0x00, // identification 0
            0x00, 0x00, // flags 0, fragment offset 0
            0x40, // ttl 64
            0x11, // protocol udp
            0x00, 0x00, // checksum 0 (TODO: check this)
            0x7f, 0x00, 0x00, 0x01, // src ip
            0x7f, 0x00, 0x00, 0x02, // dst ip
        ];

        let mut ipv4 = Ipv4Viewer::new(&mut data);

        ipv4.protocol_mut().set(IpProtocol::Tcp);
        ipv4.ttl_mut().set(128);

        assert_eq!(
            data,
            [
                0x45, // version 4, ihl 5
                0x00, // dscp 0, ecn 0
                0x00, 0x20, // total length 20 + 8 + 4 = 32 (Assume a UDP with 4 bytes data)
                0x00, 0x00, // identification 0
                0x00, 0x00, // flags 0, fragment offset 0
                0x80, // ttl 128
                0x06, // protocol tcp
                0x00, 0x00, // checksum 0 (TODO: check this)
                0x7f, 0x00, 0x00, 0x01, // src ip
                0x7f, 0x00, 0x00, 0x02, // dst ip
            ]
        )
    }

    #[test]
    fn ipv4_options() {
        let data: [u8; 28] = [
            0x47, // version 4, ihl 7
            0x00, // dscp 0, ecn 0
            0x00, 0x1c, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags 0, fragment offset 0
            0x40, // ttl 64
            0x01, // protocol icmp
            0x00, 0x00, // checksum
            0x7f, 0x00, 0x00, 0x01, // src ip
            0x7f, 0x00, 0x00, 0x02, // dst ip
            0x01, // NOP
            0x94, 0x04, 0x00, 0x00, // Router Alert
            0x00, 0x00, 0x00, // EOL + padding
        ];

        let ipv4 = Ipv4Viewer::new(&data);
        let options: Vec<_> = ipv4.option_iter().collect();

        assert_eq!(ipv4.header_len(), 28);
        assert_eq!(
            ipv4.options(),
            &[0x01, 0x94, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(options[0], Ipv4Option::NoOperation);
        assert_eq!(
            options[1],
            Ipv4Option::Option {
                kind: Ipv4OptionKind::RouterAlert,
                len: 4,
                data: &[0x00, 0x00],
            }
        );
        assert_eq!(options[1].router_alert(), Some(0));
        assert_eq!(options[2], Ipv4Option::EndOfOptions);
    }

    #[test]
    fn ipv4_checksum_helpers() {
        let mut data: [u8; 20] = [
            0x45, // version 4, ihl 5
            0x00, // dscp 0, ecn 0
            0x00, 0x20, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags 0, fragment offset 0
            0x40, // ttl 64
            0x11, // protocol udp
            0x00, 0x00, // checksum
            0x7f, 0x00, 0x00, 0x01, // src ip
            0x7f, 0x00, 0x00, 0x02, // dst ip
        ];

        {
            let mut ipv4 = Ipv4Viewer::new(&mut data);
            let checksum = ipv4.calculate_checksum();
            ipv4.checksum_mut().set(checksum);
        }

        assert!(Ipv4Viewer::new(&data).validate_checksum());

        data[8] = 63;
        assert!(!Ipv4Viewer::new(&data).validate_checksum());
    }

    #[test]
    fn ipv4_viewer_from_packet() {
        use crate::packet::Packet;

        let data: [u8; 34] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // dst mac
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, // src mac
            0x08, 0x00, // eth type ipv4
            0x45, // version 4, ihl 5
            0x00, // dscp 0, ecn 0
            0x00, 0x20, // total length 20 + 8 + 4 = 32 (Assume a UDP with 4 bytes data)
            0x00, 0x00, // identification 0
            0x00, 0x00, // flags 0, fragment offset 0
            0x80, // ttl 128
            0x06, // protocol tcp
            0x00, 0x00, // checksum 0 (TODO: check this)
            0x7f, 0x00, 0x00, 0x01, // src ip
            0x7f, 0x00, 0x00, 0x02, // dst ip
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let ipv4 = packet.layer_viewer(Ipv4).expect("Ipv4 layer not found");

        assert_eq!(ipv4.version(), 4);
        assert_eq!(ipv4.ihl(), 5);
        assert_eq!(ipv4.dscp(), 0);
        assert_eq!(ipv4.ecn(), 0);
        assert_eq!(ipv4.tos(), 0);
        assert_eq!(ipv4.total_length(), 32);
        assert_eq!(ipv4.identification(), 0);
        assert_eq!(ipv4.flags(), 0);
        assert_eq!(ipv4.fragment_offset(), 0);
        assert_eq!(ipv4.ttl(), 128);
        assert_eq!(ipv4.protocol(), IpProtocol::Tcp);
        assert_eq!(ipv4.checksum(), 0);
        assert_eq!(ipv4.src(), core::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ipv4.dst(), core::net::Ipv4Addr::new(127, 0, 0, 2));
    }
}
