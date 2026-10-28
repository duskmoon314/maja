//! Host Identity Protocol header
//! ([RFC 7401 section 5.1](https://www.rfc-editor.org/rfc/rfc7401.html#section-5.1)).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Next Header   | Header Length |0| Packet Type |Version| RES.|1|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Checksum             |           Controls            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                Sender's Host Identity Tag (HIT)               |
//! |                                                               |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Receiver's Host Identity Tag (HIT)              |
//! |                                                               |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! /                        HIP Parameters                         /
//! /                                                               /
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use core::net::Ipv6Addr;

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::{
    field_spec, impl_target,
    packet::{
        ParseContext,
        error::ParseError,
        layer::{Protocol, ProtocolExt},
        utils::field::{FieldMut, FieldRef},
    },
};

use super::header::{self, Ipv6ExtHeaderViewer};

/// Host Identity Protocol header.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Hip;

impl Ipv6Hip {
    /// Fixed part of the header, up to and including the receiver's HIT.
    pub const MIN_LEN: usize = 40;
}

impl Protocol for Ipv6Hip {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hip = Ipv6HipViewer::new(bytes);

        write!(
            fmt,
            "[Ipv6Hip] type={} version={} len={}",
            hip.packet_type().get(),
            hip.version().get(),
            hip.header_len()
        )
    }
}

impl ProtocolExt for Ipv6Hip {
    type Viewer<'a> = Ipv6HipViewer<&'a [u8]>;
    type ViewerMut<'a> = Ipv6HipViewer<&'a mut [u8]>;

    fn parse(ctx: &mut ParseContext, offset: usize) -> Result<(), ParseError> {
        header::parse_ext_header(ctx, offset, &Ipv6Hip, Ipv6Hip::MIN_LEN)
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        Ipv6HipViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        Ipv6HipViewer::new(bytes)
    }
}

/// HIP Packet Type (`Packet Type`,
/// [RFC 7401 Table 11](https://www.rfc-editor.org/rfc/rfc7401.html#section-5.3)).
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
pub enum HipPacketType {
    /// I1, the HIP Initiator Packet.
    I1 = 1,
    /// R1, the HIP Responder Packet.
    R1 = 2,
    /// I2, the Second HIP Initiator Packet.
    I2 = 3,
    /// R2, the Second HIP Responder Packet.
    R2 = 4,
    /// UPDATE, the HIP Update Packet.
    Update = 16,
    /// NOTIFY, the HIP Notify Packet.
    Notify = 17,
    /// CLOSE, the HIP Association Closing Packet.
    Close = 18,
    /// CLOSE_ACK, the HIP Closing Acknowledgment Packet.
    CloseAck = 19,
    /// Packet type outside the values of Table 11.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, HipPacketType, u8);

field_spec!(HipPacketTypeSpec, HipPacketType, u8, 0x7F);
field_spec!(HipVersionSpec, u8, u8, 0xF0, 4);
field_spec!(HipReservedSpec, u8, u8, 0x0E, 1);
field_spec!(HipChecksumSpec, u16, u16);
field_spec!(HipControlsSpec, u16, u16);
field_spec!(HipHitSpec, Ipv6Addr, u128);

/// Zero-copy viewer for the Host Identity Protocol header.
pub struct Ipv6HipViewer<T>
where
    T: AsRef<[u8]>,
{
    header: Ipv6ExtHeaderViewer<T>,
}

impl<T: AsRef<[u8]>> core::ops::Deref for Ipv6HipViewer<T> {
    type Target = Ipv6ExtHeaderViewer<T>;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> core::ops::DerefMut for Ipv6HipViewer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.header
    }
}

impl<T> Ipv6HipViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the zero bit and the packet type: 2..3
    const FIELD_PACKET_TYPE: core::ops::Range<usize> = 2..3;
    /// Field range of the version: 3..4
    const FIELD_VERSION: core::ops::Range<usize> = 3..4;
    /// Field range of the reserved bits: 3..4
    const FIELD_RESERVED: core::ops::Range<usize> = 3..4;
    /// Field range of the checksum: 4..6
    const FIELD_CHECKSUM: core::ops::Range<usize> = 4..6;
    /// Field range of the controls: 6..8
    const FIELD_CONTROLS: core::ops::Range<usize> = 6..8;
    /// Field range of the sender's HIT: 8..24
    const FIELD_SENDER_HIT: core::ops::Range<usize> = 8..24;
    /// Field range of the receiver's HIT: 24..40
    const FIELD_RECEIVER_HIT: core::ops::Range<usize> = 24..40;

    /// Create a new HIP header viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self {
            header: Ipv6ExtHeaderViewer::new(data),
        }
    }

    /// Get the accessor of the packet type, i.e. which HIP message this is.
    #[inline]
    pub fn packet_type(&self) -> FieldRef<'_, HipPacketTypeSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_PACKET_TYPE])
    }

    /// Get the accessor of the HIP version.
    #[inline]
    pub fn version(&self) -> FieldRef<'_, HipVersionSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_VERSION])
    }

    /// Get the accessor of the reserved bits.
    #[inline]
    pub fn reserved(&self) -> FieldRef<'_, HipReservedSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_RESERVED])
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, HipChecksumSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the accessor of the controls.
    #[inline]
    pub fn controls(&self) -> FieldRef<'_, HipControlsSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_CONTROLS])
    }

    /// Get the accessor of the sender's host identity tag.
    #[inline]
    pub fn sender_hit(&self) -> FieldRef<'_, HipHitSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_SENDER_HIT])
    }

    /// Get the accessor of the receiver's host identity tag.
    #[inline]
    pub fn receiver_hit(&self) -> FieldRef<'_, HipHitSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_RECEIVER_HIT])
    }

    /// Get the bytes after the fixed part, the HIP parameters
    /// ([RFC 7401 section 5.2](https://www.rfc-editor.org/rfc/rfc7401.html#section-5.2)).
    pub fn data(&self) -> &[u8] {
        &self.inner().as_ref()[Ipv6Hip::MIN_LEN..]
    }
}

impl<T> Ipv6HipViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable accessor of the packet type, i.e. which HIP message this is.
    #[inline]
    pub fn packet_type_mut(&mut self) -> FieldMut<'_, HipPacketTypeSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_PACKET_TYPE])
    }

    /// Get the mutable accessor of the HIP version.
    #[inline]
    pub fn version_mut(&mut self) -> FieldMut<'_, HipVersionSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_VERSION])
    }

    /// Get the mutable accessor of the reserved bits.
    #[inline]
    pub fn reserved_mut(&mut self) -> FieldMut<'_, HipReservedSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_RESERVED])
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, HipChecksumSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_CHECKSUM])
    }

    /// Get the mutable accessor of the controls.
    #[inline]
    pub fn controls_mut(&mut self) -> FieldMut<'_, HipControlsSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_CONTROLS])
    }

    /// Get the mutable accessor of the sender's host identity tag.
    #[inline]
    pub fn sender_hit_mut(&mut self) -> FieldMut<'_, HipHitSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_SENDER_HIT])
    }

    /// Get the mutable accessor of the receiver's host identity tag.
    #[inline]
    pub fn receiver_hit_mut(&mut self) -> FieldMut<'_, HipHitSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_RECEIVER_HIT])
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::layer::ip::protocol::IpProtocol;
    use crate::packet::layer::{Protocol, ip::v6::Ipv6, raw::Raw};
    use crate::packet::{
        Packet,
        layer::{eth::Eth, udp::Udp},
    };

    use super::super::test_util::{eth_ipv6_frame, layers, udp_header};
    use super::*;

    #[test]
    fn ipv6_hip_viewer() {
        let mut payload = vec![
            u8::from(crate::packet::layer::ip::protocol::IpProtocol::Udp),
            4, // header length: (4 + 1) * 8 = 40 octets, the fixed part
            u8::from(HipPacketType::I1),
            0x21, // version 2, the Shim6 compatibility bit
            0x12,
            0x34, // checksum
            0x00,
            0x01, // controls
        ];
        payload.extend_from_slice(&[0x11; 16]); // sender's HIT
        payload.extend_from_slice(&[0x22; 16]); // receiver's HIT
        payload.extend_from_slice(&udp_header());

        let data = eth_ipv6_frame(139, &payload);
        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        let hip = packet.layer_viewer(Ipv6Hip).expect("hip layer");
        assert_eq!(u8::from(hip.next_header().get()), 17);
        assert_eq!(hip.hdr_ext_len().get(), 4);
        assert_eq!(hip.header_len(), 40);
        assert_eq!(hip.packet_type().get(), HipPacketType::I1);
        assert_eq!(hip.version().get(), 2);
        assert_eq!(hip.reserved().get(), 0);
        assert_eq!(hip.checksum().get(), 0x1234);
        assert_eq!(hip.controls().get(), 1);
        assert_eq!(hip.sender_hit().get(), Ipv6Addr::from([0x11; 16]));
        assert_eq!(hip.receiver_hit().get(), Ipv6Addr::from([0x22; 16]));
        assert!(hip.data().is_empty());

        assert!(packet.layer_viewer(Udp).is_some());
    }

    #[test]
    fn ipv6_hip_short_header_is_malformed() {
        // Header Length 0 declares eight octets, less than the 40-octet fixed part.
        let mut payload = vec![17, 0, u8::from(HipPacketType::I1), 0, 0, 0, 0, 0];
        payload.extend_from_slice(&udp_header());

        let data = eth_ipv6_frame(139, &payload);
        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(layers(&packet), [&Eth as &dyn Protocol, &Ipv6, &Raw]);
        assert!(packet.layer_viewer(Ipv6Hip).is_none());
    }

    #[test]
    fn ipv6_hip_viewer_mut() {
        let mut data = [0u8; Ipv6Hip::MIN_LEN];
        {
            let mut hip = Ipv6HipViewer::new(&mut data[..]);

            hip.next_header_mut().set(IpProtocol::Tcp);
            hip.hdr_ext_len_mut().set(4);
            hip.packet_type_mut().set(HipPacketType::R1);
            hip.version_mut().set(2);
            hip.checksum_mut().set(0x1234);
            hip.controls_mut().set(1);
            hip.sender_hit_mut().set(Ipv6Addr::from([0x11; 16]));
            hip.receiver_hit_mut().set(Ipv6Addr::from([0x22; 16]));
        }

        assert_eq!(data[0], 6);
        assert_eq!(data[1], 4);
        assert_eq!(data[2], u8::from(HipPacketType::R1));
        assert_eq!(data[3], 0x20); // version 2; the Shim6 bit has no setter
        assert_eq!(data[8..24], [0x11; 16]);
        assert_eq!(data[24..40], [0x22; 16]);
    }
}
