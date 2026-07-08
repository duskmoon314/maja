//! Internet Control Message Protocol version 6 (ICMPv6).
//!
//! ICMPv6 keeps the same common type/code/checksum prefix shape as ICMPv4, but
//! message bodies include IPv6-specific error payloads, echo payloads, and
//! Neighbor Discovery Protocol messages. This parser records the whole ICMPv6
//! message as one layer and exposes typed body viewers through
//! [`message`](crate::packet::layer::icmpv6::Icmpv6Viewer::message).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |     Code      |           Checksum            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 Message-specific body                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Optional message data                    |
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

pub mod echo;
pub mod message_type;
pub mod ndp;
pub mod quoted;

pub use echo::Icmpv6EchoViewer;
pub use message_type::Icmpv6Type;
pub use ndp::{
    Icmpv6NdpViewer, Icmpv6NeighborAdvertisementViewer, Icmpv6NeighborSolicitationViewer,
    Icmpv6RedirectViewer, Icmpv6RouterAdvertisementViewer, Icmpv6RouterSolicitationViewer,
};
pub use quoted::Icmpv6QuotedPacketViewer;

/// Internet Control Message Protocol version 6 (ICMPv6) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Icmpv6;

impl Icmpv6 {
    /// Minimum ICMPv6 header length.
    const MIN_LEN: usize = 4;
}

impl Protocol for Icmpv6 {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let icmpv6 = Icmpv6Viewer::new(bytes);

        write!(
            fmt,
            "[Icmpv6] {} code {}",
            icmpv6.message_type().get(),
            icmpv6.code().get()
        )
    }
}

impl ProtocolExt for Icmpv6 {
    type Viewer<'a> = Icmpv6Viewer<&'a [u8]>;
    type ViewerMut<'a> = Icmpv6Viewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        ctx.require(&Icmpv6, offset, Icmpv6::MIN_LEN)?;

        let len = ctx.bytes.len() - offset;
        ctx.push_layer(&Icmpv6, offset, len);

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        Icmpv6Viewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        Icmpv6Viewer::new(bytes)
    }
}

field_spec!(TypeSpec, Icmpv6Type, u8);
field_spec!(CodeSpec, u8, u8);
field_spec!(ChecksumSpec, u16, u16);
field_spec!(RestOfHeaderSpec, u32, u32);
field_spec!(IdentifierSpec, u16, u16);
field_spec!(SequenceSpec, u16, u16);

/// Internet Control Message Protocol version 6 (ICMPv6).
pub struct Icmpv6Viewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6Viewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the message type: 0..1
    const FIELD_TYPE: core::ops::Range<usize> = 0..1;
    /// Field range of the code: 1..2
    const FIELD_CODE: core::ops::Range<usize> = 1..2;
    /// Field range of the checksum: 2..4
    const FIELD_CHECKSUM: core::ops::Range<usize> = 2..4;
    /// Field range of the message-specific 32-bit field: 4..8
    const FIELD_REST_OF_HEADER: core::ops::Range<usize> = 4..8;
    /// Field range of the echo identifier: 4..6
    const FIELD_IDENTIFIER: core::ops::Range<usize> = 4..6;
    /// Field range of the echo sequence number: 6..8
    const FIELD_SEQUENCE: core::ops::Range<usize> = 6..8;

    /// Create a new ICMPv6 viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the ICMPv6 message type.
    #[inline]
    pub fn message_type(&self) -> FieldRef<'_, TypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TYPE])
    }

    /// Get the accessor of the ICMPv6 code.
    #[inline]
    pub fn code(&self) -> FieldRef<'_, CodeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CODE])
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, ChecksumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the accessor of the 32-bit message-specific field.
    #[inline]
    pub fn rest_of_header(&self) -> FieldRef<'_, RestOfHeaderSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_REST_OF_HEADER])
    }

    /// Get the accessor of the echo identifier field.
    #[inline]
    pub fn identifier(&self) -> FieldRef<'_, IdentifierSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_IDENTIFIER])
    }

    /// Get the accessor of the echo sequence field.
    #[inline]
    pub fn sequence(&self) -> FieldRef<'_, SequenceSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SEQUENCE])
    }

    /// Get the message-specific body bytes after type/code/checksum.
    #[inline]
    pub fn body(&self) -> &[u8] {
        if self.data.as_ref().len() <= Icmpv6::MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[Icmpv6::MIN_LEN..]
        }
    }

    /// Get a typed view of the ICMPv6 message body when recognized.
    #[inline]
    pub fn message(&self) -> Icmpv6MessageViewer<'_> {
        match self.message_type().get() {
            Icmpv6Type::EchoRequest | Icmpv6Type::EchoReply => self
                .echo()
                .map(Icmpv6MessageViewer::Echo)
                .unwrap_or_else(|| Icmpv6MessageViewer::Raw(self.body())),
            Icmpv6Type::DestinationUnreachable
            | Icmpv6Type::PacketTooBig
            | Icmpv6Type::TimeExceeded
            | Icmpv6Type::ParameterProblem => self
                .quoted_packet()
                .map(Icmpv6MessageViewer::QuotedPacket)
                .unwrap_or_else(|| Icmpv6MessageViewer::Raw(self.body())),
            Icmpv6Type::RouterSolicitation
            | Icmpv6Type::RouterAdvertisement
            | Icmpv6Type::NeighborSolicitation
            | Icmpv6Type::NeighborAdvertisement
            | Icmpv6Type::Redirect => self
                .ndp()
                .map(Icmpv6MessageViewer::Ndp)
                .unwrap_or_else(|| Icmpv6MessageViewer::Raw(self.body())),
            _ => Icmpv6MessageViewer::Raw(self.body()),
        }
    }

    /// Get an ICMPv6 echo body view for echo request/reply messages.
    #[inline]
    pub fn echo(&self) -> Option<Icmpv6EchoViewer<&[u8]>> {
        if !matches!(
            self.message_type().get(),
            Icmpv6Type::EchoRequest | Icmpv6Type::EchoReply
        ) {
            return None;
        }

        self.body()
            .get(..echo::MIN_LEN)
            .map(|_| Icmpv6EchoViewer::new(self.body()))
    }

    /// Get an ICMPv6 quoted-packet body view for common error messages.
    #[inline]
    pub fn quoted_packet(&self) -> Option<Icmpv6QuotedPacketViewer<&[u8]>> {
        if !matches!(
            self.message_type().get(),
            Icmpv6Type::DestinationUnreachable
                | Icmpv6Type::PacketTooBig
                | Icmpv6Type::TimeExceeded
                | Icmpv6Type::ParameterProblem
        ) {
            return None;
        }

        self.body()
            .get(..quoted::MIN_LEN)
            .map(|_| Icmpv6QuotedPacketViewer::new(self.body()))
    }

    /// Get an ICMPv6 Neighbor Discovery Protocol body view.
    #[inline]
    pub fn ndp(&self) -> Option<Icmpv6NdpViewer<'_>> {
        let body = self.body();

        match self.message_type().get() {
            Icmpv6Type::RouterSolicitation => {
                body.get(..ndp::ROUTER_SOLICITATION_MIN_LEN).map(|_| {
                    Icmpv6NdpViewer::RouterSolicitation(Icmpv6RouterSolicitationViewer::new(body))
                })
            }
            Icmpv6Type::RouterAdvertisement => {
                body.get(..ndp::ROUTER_ADVERTISEMENT_MIN_LEN).map(|_| {
                    Icmpv6NdpViewer::RouterAdvertisement(Icmpv6RouterAdvertisementViewer::new(body))
                })
            }
            Icmpv6Type::NeighborSolicitation => {
                body.get(..ndp::NEIGHBOR_SOLICITATION_MIN_LEN).map(|_| {
                    Icmpv6NdpViewer::NeighborSolicitation(Icmpv6NeighborSolicitationViewer::new(
                        body,
                    ))
                })
            }
            Icmpv6Type::NeighborAdvertisement => {
                body.get(..ndp::NEIGHBOR_ADVERTISEMENT_MIN_LEN).map(|_| {
                    Icmpv6NdpViewer::NeighborAdvertisement(Icmpv6NeighborAdvertisementViewer::new(
                        body,
                    ))
                })
            }
            Icmpv6Type::Redirect => body
                .get(..ndp::REDIRECT_MIN_LEN)
                .map(|_| Icmpv6NdpViewer::Redirect(Icmpv6RedirectViewer::new(body))),
            _ => None,
        }
    }
}

impl<T> Icmpv6Viewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the ICMPv6 message type.
    #[inline]
    pub fn message_type_mut(&mut self) -> FieldMut<'_, TypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TYPE])
    }

    /// Get the mutable accessor of the ICMPv6 code.
    #[inline]
    pub fn code_mut(&mut self) -> FieldMut<'_, CodeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CODE])
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, ChecksumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CHECKSUM])
    }

    /// Get the mutable accessor of the 32-bit message-specific field.
    #[inline]
    pub fn rest_of_header_mut(&mut self) -> FieldMut<'_, RestOfHeaderSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_REST_OF_HEADER])
    }

    /// Get the mutable accessor of the echo identifier field.
    #[inline]
    pub fn identifier_mut(&mut self) -> FieldMut<'_, IdentifierSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_IDENTIFIER])
    }

    /// Get the mutable accessor of the echo sequence field.
    #[inline]
    pub fn sequence_mut(&mut self) -> FieldMut<'_, SequenceSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SEQUENCE])
    }

    /// Get mutable message-specific body bytes after type/code/checksum.
    #[inline]
    pub fn body_mut(&mut self) -> &mut [u8] {
        let data = self.data.as_mut();
        if data.len() <= Icmpv6::MIN_LEN {
            &mut data[0..0]
        } else {
            &mut data[Icmpv6::MIN_LEN..]
        }
    }

    /// Get a mutable ICMPv6 echo body view for echo request/reply messages.
    #[inline]
    pub fn echo_mut(&mut self) -> Option<Icmpv6EchoViewer<&mut [u8]>> {
        if !matches!(
            self.message_type().get(),
            Icmpv6Type::EchoRequest | Icmpv6Type::EchoReply
        ) || self.body().len() < echo::MIN_LEN
        {
            return None;
        }

        Some(Icmpv6EchoViewer::new(self.body_mut()))
    }
}

impl<T> core::fmt::Debug for Icmpv6Viewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Icmpv6")
            .field("message_type", &self.message_type().get())
            .field("code", &self.code().get())
            .field("checksum", &self.checksum().get())
            .finish()
    }
}

/// Message-specific ICMPv6 body viewer.
#[derive(Debug)]
pub enum Icmpv6MessageViewer<'a> {
    /// Echo request or reply.
    Echo(Icmpv6EchoViewer<&'a [u8]>),
    /// Error message carrying a quoted invoking packet.
    QuotedPacket(Icmpv6QuotedPacketViewer<&'a [u8]>),
    /// Neighbor Discovery Protocol message.
    Ndp(Icmpv6NdpViewer<'a>),
    /// Raw message body after the common ICMPv6 header.
    Raw(&'a [u8]),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmpv6_viewer() {
        let data: [u8; 8] = [
            0x80, // type: echo request
            0x00, // code
            0x00, 0x00, // checksum
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence
        ];

        let icmpv6 = Icmpv6Viewer::new(&data);

        assert_eq!(icmpv6.message_type(), Icmpv6Type::EchoRequest);
        assert_eq!(icmpv6.code(), 0);
        assert_eq!(icmpv6.checksum(), 0);
        assert_eq!(icmpv6.identifier(), 0x1234);
        assert_eq!(icmpv6.sequence(), 1);
        let echo = icmpv6.echo().expect("echo body");
        assert_eq!(echo.identifier(), 0x1234);
        assert_eq!(echo.sequence(), 1);
        assert_eq!(echo.payload(), &[]);
        assert!(matches!(icmpv6.message(), Icmpv6MessageViewer::Echo(_)));
    }

    #[test]
    fn icmpv6_quoted_packet_viewer() {
        let data: [u8; 16] = [
            0x02, // type: packet too big
            0x00, // code
            0x00, 0x00, // checksum
            0x00, 0x00, 0x05, 0xdc, // MTU
            0x60, 0x00, 0x00, 0x00, // quoted packet
            0x00, 0x00, 0x00, 0x00,
        ];

        let icmpv6 = Icmpv6Viewer::new(&data);
        let quoted = icmpv6.quoted_packet().expect("quoted packet body");

        assert_eq!(quoted.mtu(), 1500);
        assert_eq!(
            quoted.quoted_packet(),
            &[0x60, 0x00, 0x00, 0x00, 0, 0, 0, 0]
        );
        assert!(matches!(
            icmpv6.message(),
            Icmpv6MessageViewer::QuotedPacket(_)
        ));
    }

    #[test]
    fn icmpv6_neighbor_solicitation_viewer() {
        let data: [u8; 28] = [
            0x87, // type: neighbor solicitation
            0x00, // code
            0x00, 0x00, // checksum
            0x00, 0x00, 0x00, 0x00, // reserved
            0x20, 0x01, 0x0d, 0xb8, // target address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
            0xaa, 0xbb, // option bytes
        ];

        let icmpv6 = Icmpv6Viewer::new(&data);
        let Some(Icmpv6NdpViewer::NeighborSolicitation(ns)) = icmpv6.ndp() else {
            panic!("neighbor solicitation body");
        };

        assert_eq!(ns.reserved(), 0);
        assert_eq!(
            ns.target_addr(),
            core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(ns.options(), &[0x01, 0x01, 0xaa, 0xbb]);
        assert!(matches!(icmpv6.message(), Icmpv6MessageViewer::Ndp(_)));
    }
}
