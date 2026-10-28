//! IPv6 Mobility header
//! ([RFC 6275 section 6.1.1](https://www.rfc-editor.org/rfc/rfc6275.html#section-6.1.1)).
//!
//! ```text
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Payload Proto |  Header Len   |   MH Type     |   Reserved    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Checksum            |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//! |                                                               |
//! .                                                               .
//! .                       Message Data                            .
//! .                                                               .
//! |                                                               |
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

/// Internet Protocol version 6 Mobility header.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Mobility;

impl Ipv6Mobility {
    /// Fixed part of the header: payload proto, header length, MH type,
    /// reserved and checksum.
    pub const MIN_LEN: usize = 6;
}

impl Protocol for Ipv6Mobility {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mobility = Ipv6MobilityViewer::new(bytes);

        write!(
            fmt,
            "[Ipv6Mobility] type={} payload={} len={}",
            mobility.mh_type().get(),
            mobility.next_header().get(),
            mobility.header_len(),
        )
    }
}

impl ProtocolExt for Ipv6Mobility {
    type Viewer<'a> = Ipv6MobilityViewer<&'a [u8]>;
    type ViewerMut<'a> = Ipv6MobilityViewer<&'a mut [u8]>;

    fn parse(ctx: &mut ParseContext, offset: usize) -> Result<(), ParseError> {
        header::parse_ext_header(ctx, offset, &Ipv6Mobility, Ipv6Mobility::MIN_LEN)
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        Ipv6MobilityViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        Ipv6MobilityViewer::new(bytes)
    }
}

/// Mobility Header message type (`MH Type`,
/// [RFC 6275 section 6.1.2 and onward](https://www.rfc-editor.org/rfc/rfc6275.html#section-6.1.2)).
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
pub enum MobilityType {
    /// Binding Refresh Request.
    BindingRefreshRequest = 0,
    /// Home Test Init.
    HomeTestInit = 1,
    /// Care-of Test Init.
    CareOfTestInit = 2,
    /// Home Test.
    HomeTest = 3,
    /// Care-of Test.
    CareOfTest = 4,
    /// Binding Update.
    BindingUpdate = 5,
    /// Binding Acknowledgement.
    BindingAcknowledgement = 6,
    /// Binding Error.
    BindingError = 7,
    /// Message type outside the values of
    /// [RFC 6275 section 6.1.2](https://www.rfc-editor.org/rfc/rfc6275.html#section-6.1.2).
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl_target!(frominto, MobilityType, u8);

field_spec!(MhTypeSpec, MobilityType, u8);
field_spec!(MobilityReservedSpec, u8, u8);
field_spec!(ChecksumSpec, u16, u16);

/// Zero-copy viewer for the IPv6 Mobility header.
pub struct Ipv6MobilityViewer<T>
where
    T: AsRef<[u8]>,
{
    header: Ipv6ExtHeaderViewer<T>,
}

impl<T: AsRef<[u8]>> core::ops::Deref for Ipv6MobilityViewer<T> {
    type Target = Ipv6ExtHeaderViewer<T>;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> core::ops::DerefMut for Ipv6MobilityViewer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.header
    }
}

impl<T> Ipv6MobilityViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the MH type: 2..3
    const FIELD_MH_TYPE: core::ops::Range<usize> = 2..3;
    /// Field range of the reserved octet: 3..4
    const FIELD_RESERVED: core::ops::Range<usize> = 3..4;
    /// Field range of the checksum: 4..6
    const FIELD_CHECKSUM: core::ops::Range<usize> = 4..6;

    /// Create a new Mobility header viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self {
            header: Ipv6ExtHeaderViewer::new(data),
        }
    }

    /// Get the accessor of the MH type.
    #[inline]
    pub fn mh_type(&self) -> FieldRef<'_, MhTypeSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_MH_TYPE])
    }

    /// Get the accessor of the reserved octet.
    #[inline]
    pub fn reserved(&self) -> FieldRef<'_, MobilityReservedSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_RESERVED])
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, ChecksumSpec> {
        FieldRef::new(&self.inner().as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the message data
    /// ([RFC 6275 section 6.1.1](https://www.rfc-editor.org/rfc/rfc6275.html#section-6.1.1)).
    pub fn data(&self) -> &[u8] {
        &self.inner().as_ref()[Ipv6Mobility::MIN_LEN..]
    }
}

impl<T> Ipv6MobilityViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable accessor of the MH type.
    #[inline]
    pub fn mh_type_mut(&mut self) -> FieldMut<'_, MhTypeSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_MH_TYPE])
    }

    /// Get the mutable accessor of the reserved octet.
    #[inline]
    pub fn reserved_mut(&mut self) -> FieldMut<'_, MobilityReservedSpec> {
        FieldMut::new(&mut self.inner_mut().as_mut()[Self::FIELD_RESERVED])
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, ChecksumSpec> {
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
    fn ipv6_mobility_viewer() {
        // Header Len 0 -> one octet of padding after the fixed part; a Binding
        // Update that points at UDP.
        let mut payload = vec![
            u8::from(crate::packet::layer::ip::protocol::IpProtocol::Udp),
            0, // header len
            u8::from(MobilityType::BindingUpdate),
            0, // reserved
            0x12,
            0x34, // checksum
            0x00,
            0x00, // message data (padding)
        ];
        payload.extend_from_slice(&udp_header());

        let data = eth_ipv6_frame(135, &payload);
        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        let mobility = packet.layer_viewer(Ipv6Mobility).expect("mobility layer");
        assert_eq!(
            u8::from(mobility.next_header().get()),
            17,
            "payload proto is the next header"
        );
        assert_eq!(mobility.hdr_ext_len().get(), 0);
        assert_eq!(mobility.header_len(), 8);
        assert_eq!(mobility.mh_type().get(), MobilityType::BindingUpdate);
        assert_eq!(mobility.reserved().get(), 0);
        assert_eq!(mobility.checksum().get(), 0x1234);
        assert_eq!(mobility.data(), &[0x00, 0x00]);

        assert!(packet.layer_viewer(Udp).is_some());
    }

    #[test]
    fn ipv6_mobility_viewer_mut() {
        let mut data = [17, 0, 5, 0, 0x12, 0x34, 0, 0];
        let mut mobility = Ipv6MobilityViewer::new(&mut data[..]);

        mobility.next_header_mut().set(IpProtocol::Tcp);
        mobility.hdr_ext_len_mut().set(1);
        mobility
            .mh_type_mut()
            .set(MobilityType::BindingAcknowledgement);
        mobility.checksum_mut().set(0xabcd);

        assert_eq!(data, [6, 1, 6, 0, 0xab, 0xcd, 0, 0]);
    }
}
