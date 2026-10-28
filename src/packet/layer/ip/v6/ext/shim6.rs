//! Shim6 control message header (the common layout of
//! [section 5.1](https://www.rfc-editor.org/rfc/rfc5533.html#section-5.1))
//! ([RFC 5533 section 5.3](https://www.rfc-editor.org/rfc/rfc5533.html#section-5.3)).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |P|     Type    |Type-specific|S|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            Checksum           |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//! |                    Type-specific format                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

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

/// Shim6 header.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Shim6;

impl Ipv6Shim6 {
    /// Fixed part of a control message: next header, header length, the type
    /// octet, the type-specific octet and the checksum.
    pub const MIN_LEN: usize = 6;
}

impl Protocol for Ipv6Shim6 {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shim6 = Ipv6Shim6Viewer::new(bytes);

        if shim6.is_payload_extension().get() {
            write!(
                fmt,
                "[Ipv6Shim6] payload next={}",
                shim6.next_header().get()
            )
        } else {
            write!(
                fmt,
                "[Ipv6Shim6] type={} len={}",
                shim6.message_type().get(),
                shim6.header_len(),
            )
        }
    }
}

impl ProtocolExt for Ipv6Shim6 {
    type Viewer<'a> = Ipv6Shim6Viewer<&'a [u8]>;
    type ViewerMut<'a> = Ipv6Shim6Viewer<&'a mut [u8]>;

    fn parse(ctx: &mut ParseContext, offset: usize) -> Result<(), ParseError> {
        header::parse_ext_header(ctx, offset, &Ipv6Shim6, Ipv6Shim6::MIN_LEN)
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        Ipv6Shim6Viewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        Ipv6Shim6Viewer::new(bytes)
    }
}

field_spec!(Shim6PayloadExtensionSpec, bool, u8, 0x80, 7);
/// Shim6 control message type (`Type`,
/// [RFC 5533 section 5.3](https://www.rfc-editor.org/rfc/rfc5533.html#section-5.3)).
///
/// Type codes 0-63 do not trigger an R1bis message on a missing context, codes
/// 64-127 do.
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
pub enum Shim6MessageType {
    /// I1, the first establishment message from the initiator.
    I1 = 1,
    /// R1, the first establishment message from the responder.
    R1 = 2,
    /// I2, the second establishment message from the initiator.
    I2 = 3,
    /// R2, the second establishment message from the responder.
    R2 = 4,
    /// R1bis, the reply to a reference to a non-existent context.
    R1bis = 5,
    /// I2bis, the reply to an R1bis message.
    I2bis = 6,
    /// Update Request.
    UpdateRequest = 64,
    /// Update Acknowledgement.
    UpdateAcknowledgement = 65,
    /// Keepalive.
    Keepalive = 66,
    /// Probe Message.
    Probe = 67,
    /// Error Message.
    Error = 68,
    /// Message type outside the table above.
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, Shim6MessageType, u8);

field_spec!(Shim6TypeSpec, Shim6MessageType, u8, 0x7F);
field_spec!(Shim6TypeSpecificSpec, u8, u8, 0xFE, 1);
field_spec!(Shim6ChecksumSpec, u16, u16);

/// Zero-copy viewer for the Shim6 header.
pub struct Ipv6Shim6Viewer<T>
where
    T: AsRef<[u8]>,
{
    header: Ipv6ExtHeaderViewer<T>,
}

impl<T: AsRef<[u8]>> core::ops::Deref for Ipv6Shim6Viewer<T> {
    type Target = Ipv6ExtHeaderViewer<T>;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> core::ops::DerefMut for Ipv6Shim6Viewer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.header
    }
}

impl<T> Ipv6Shim6Viewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the P bit: 2..3
    const FIELD_P_BIT: core::ops::Range<usize> = 2..3;
    /// Field range of the message type: 2..3
    const FIELD_MESSAGE_TYPE: core::ops::Range<usize> = 2..3;
    /// Field range of the type-specific bits: 3..4
    const FIELD_TYPE_SPECIFIC: core::ops::Range<usize> = 3..4;
    /// Field range of the checksum: 4..6
    const FIELD_CHECKSUM: core::ops::Range<usize> = 4..6;

    /// Create a new Shim6 header viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self {
            header: Ipv6ExtHeaderViewer::new(data),
        }
    }

    /// Get the accessor of the P bit, set in a payload extension header.
    #[inline]
    pub fn is_payload_extension(&self) -> FieldRef<'_, Shim6PayloadExtensionSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_P_BIT])
    }

    /// Get the accessor of the message type
    /// ([RFC 5533 section 5.3](https://www.rfc-editor.org/rfc/rfc5533.html#section-5.3)).
    #[inline]
    pub fn message_type(&self) -> FieldRef<'_, Shim6TypeSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_MESSAGE_TYPE])
    }

    /// Get the accessor of the seven bits that the type-specific format uses.
    #[inline]
    pub fn type_specific(&self) -> FieldRef<'_, Shim6TypeSpecificSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_TYPE_SPECIFIC])
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, Shim6ChecksumSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the type-specific format
    /// ([RFC 5533 section 5.3](https://www.rfc-editor.org/rfc/rfc5533.html#section-5.3)).
    pub fn data(&self) -> &[u8] {
        &self.inner().as_ref()[Ipv6Shim6::MIN_LEN..]
    }
}

impl<T> Ipv6Shim6Viewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable accessor of the P bit, set in a payload extension header.
    #[inline]
    pub fn is_payload_extension_mut(&mut self) -> FieldMut<'_, Shim6PayloadExtensionSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_P_BIT])
    }

    /// Get the mutable accessor of the message type
    /// ([RFC 5533 section 5.3](https://www.rfc-editor.org/rfc/rfc5533.html#section-5.3)).
    #[inline]
    pub fn message_type_mut(&mut self) -> FieldMut<'_, Shim6TypeSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_MESSAGE_TYPE])
    }

    /// Get the mutable accessor of the seven bits that the type-specific format uses.
    #[inline]
    pub fn type_specific_mut(&mut self) -> FieldMut<'_, Shim6TypeSpecificSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_TYPE_SPECIFIC])
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, Shim6ChecksumSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_CHECKSUM])
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::layer::ip::protocol::IpProtocol;
    use crate::packet::{
        Packet,
        layer::{eth::Eth, udp::Udp},
    };

    use super::super::test_util::{eth_ipv6_frame, udp_header};
    use super::*;

    #[test]
    fn ipv6_shim6_viewer() {
        let mut payload = vec![
            u8::from(crate::packet::layer::ip::protocol::IpProtocol::Udp),
            0,                              // header length: one octet
            u8::from(Shim6MessageType::I1), // P clear (0x80), type I1
            0x00,                           // type-specific bits clear, S clear
            0x12,
            0x34, // checksum
            0x00,
            0x00, // type-specific format
        ];
        payload.extend_from_slice(&udp_header());

        let data = eth_ipv6_frame(140, &payload);
        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        let shim6 = packet.layer_viewer(Ipv6Shim6).expect("shim6 layer");
        assert!(!shim6.is_payload_extension().get());
        assert_eq!(shim6.message_type().get(), Shim6MessageType::I1);
        assert_eq!(shim6.type_specific().get(), 0);
        assert_eq!(shim6.checksum().get(), 0x1234);
        assert_eq!(shim6.header_len(), 8);
        assert_eq!(shim6.data(), &[0x00, 0x00]);
        assert_eq!(u8::from(shim6.next_header().get()), 17);

        assert!(packet.layer_viewer(Udp).is_some());
    }

    #[test]
    fn ipv6_shim6_viewer_mut() {
        let mut data = [17, 0, 1, 0, 0x12, 0x34, 0, 0];
        let mut shim6 = Ipv6Shim6Viewer::new(&mut data[..]);

        shim6.next_header_mut().set(IpProtocol::Tcp);
        shim6.hdr_ext_len_mut().set(1);
        shim6.is_payload_extension_mut().set(true);
        shim6.checksum_mut().set(0xabcd);

        assert_eq!(data, [6, 1, 0x81, 0, 0xab, 0xcd, 0, 0]);
    }
}
