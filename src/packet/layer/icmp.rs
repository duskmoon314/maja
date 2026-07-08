//! Internet Control Message Protocol (ICMPv4).
//!
//! ICMPv4 messages share a common type/code/checksum prefix. The following
//! four bytes are message-specific: echo messages use identifier and sequence
//! fields, error messages carry a rest-of-header field followed by a quoted
//! invoking packet, and other message families have their own typed body
//! viewers.
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
        utils::{
            checksum::internet_checksum_zeroing,
            field::{FieldMut, FieldRef},
        },
    },
};

pub mod address_mask;
pub mod echo;
pub mod message_type;
pub mod quoted;
pub mod redirect;
pub mod timestamp;

pub use address_mask::IcmpAddressMaskViewer;
pub use echo::{IcmpEchoBuilder, IcmpEchoViewer};
pub use message_type::IcmpType;
pub use quoted::IcmpQuotedPacketViewer;
pub use redirect::IcmpRedirectViewer;
pub use timestamp::IcmpTimestampViewer;

/// Internet Control Message Protocol (ICMPv4) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Icmp;

impl Icmp {
    /// Minimum ICMP header length.
    const MIN_LEN: usize = 4;
}

impl Protocol for Icmp {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let icmp = IcmpViewer::new(bytes);

        write!(
            fmt,
            "[Icmp] {} code {}",
            icmp.message_type().get(),
            icmp.code().get()
        )
    }
}

impl ProtocolExt for Icmp {
    type Viewer<'a> = IcmpViewer<&'a [u8]>;
    type ViewerMut<'a> = IcmpViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        ctx.require(&Icmp, offset, Icmp::MIN_LEN)?;

        let len = ctx.bytes.len() - offset;
        ctx.push_layer(&Icmp, offset, len);

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        IcmpViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        IcmpViewer::new(bytes)
    }
}

field_spec!(TypeSpec, IcmpType, u8);
field_spec!(CodeSpec, u8, u8);
field_spec!(ChecksumSpec, u16, u16);
field_spec!(RestOfHeaderSpec, u32, u32);
field_spec!(IdentifierSpec, u16, u16);
field_spec!(SequenceSpec, u16, u16);

/// Internet Control Message Protocol (ICMPv4).
pub struct IcmpViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the message type: 0..1
    const FIELD_TYPE: core::ops::Range<usize> = 0..1;
    /// Field range of the code: 1..2
    const FIELD_CODE: core::ops::Range<usize> = 1..2;
    /// Field range of the checksum: 2..4
    const FIELD_CHECKSUM: core::ops::Range<usize> = 2..4;
    /// Field range of the rest-of-header field: 4..8
    const FIELD_REST_OF_HEADER: core::ops::Range<usize> = 4..8;
    /// Field range of the echo identifier: 4..6
    const FIELD_IDENTIFIER: core::ops::Range<usize> = 4..6;
    /// Field range of the echo sequence number: 6..8
    const FIELD_SEQUENCE: core::ops::Range<usize> = 6..8;

    /// Create a new ICMP viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Calculate the ICMP checksum for this message.
    ///
    /// The checksum field is treated as zero during calculation. ICMP covers
    /// the entire message, so callers that want to include echo payload bytes
    /// must create the viewer from the full ICMP message slice, not only the
    /// common header bytes.
    #[inline]
    pub fn calculate_checksum(&self) -> u16 {
        internet_checksum_zeroing(self.data.as_ref(), Self::FIELD_CHECKSUM)
    }

    /// Return whether this ICMP message's checksum matches its bytes.
    ///
    /// ICMP checksums cover the whole message. If this viewer was created from
    /// only the ICMP layer header, validation only covers those bytes.
    #[inline]
    pub fn validate_checksum(&self) -> bool {
        self.checksum().get() == self.calculate_checksum()
    }

    /// Get the accessor of the ICMP message type.
    #[inline]
    pub fn message_type(&self) -> FieldRef<'_, TypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TYPE])
    }

    /// Get the accessor of the ICMP code.
    #[inline]
    pub fn code(&self) -> FieldRef<'_, CodeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CODE])
    }

    /// Get the accessor of the checksum.
    #[inline]
    pub fn checksum(&self) -> FieldRef<'_, ChecksumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CHECKSUM])
    }

    /// Get the accessor of the 32-bit rest-of-header field.
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
        if self.data.as_ref().len() <= Icmp::MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[Icmp::MIN_LEN..]
        }
    }

    /// Get a typed view of the ICMP message body when recognized.
    #[inline]
    pub fn message(&self) -> IcmpMessageViewer<'_> {
        match self.message_type().get() {
            IcmpType::EchoRequest | IcmpType::EchoReply => self
                .echo()
                .map(IcmpMessageViewer::Echo)
                .unwrap_or_else(|| IcmpMessageViewer::Raw(self.body())),
            IcmpType::DestinationUnreachable
            | IcmpType::SourceQuench
            | IcmpType::TimeExceeded
            | IcmpType::ParameterProblem => self
                .quoted_packet()
                .map(IcmpMessageViewer::QuotedPacket)
                .unwrap_or_else(|| IcmpMessageViewer::Raw(self.body())),
            IcmpType::Redirect => self
                .redirect()
                .map(IcmpMessageViewer::Redirect)
                .unwrap_or_else(|| IcmpMessageViewer::Raw(self.body())),
            IcmpType::TimestampRequest | IcmpType::TimestampReply => self
                .timestamp()
                .map(IcmpMessageViewer::Timestamp)
                .unwrap_or_else(|| IcmpMessageViewer::Raw(self.body())),
            IcmpType::AddressMaskRequest | IcmpType::AddressMaskReply => self
                .address_mask()
                .map(IcmpMessageViewer::AddressMask)
                .unwrap_or_else(|| IcmpMessageViewer::Raw(self.body())),
            _ => IcmpMessageViewer::Raw(self.body()),
        }
    }

    /// Get an ICMP echo body view for echo request/reply messages.
    #[inline]
    pub fn echo(&self) -> Option<IcmpEchoViewer<&[u8]>> {
        if !matches!(
            self.message_type().get(),
            IcmpType::EchoRequest | IcmpType::EchoReply
        ) {
            return None;
        }

        self.body()
            .get(..echo::MIN_LEN)
            .map(|_| IcmpEchoViewer::new(self.body()))
    }

    /// Get an ICMP quoted-packet body view for common error messages.
    #[inline]
    pub fn quoted_packet(&self) -> Option<IcmpQuotedPacketViewer<&[u8]>> {
        if !matches!(
            self.message_type().get(),
            IcmpType::DestinationUnreachable
                | IcmpType::SourceQuench
                | IcmpType::TimeExceeded
                | IcmpType::ParameterProblem
        ) {
            return None;
        }

        self.body()
            .get(..quoted::MIN_LEN)
            .map(|_| IcmpQuotedPacketViewer::new(self.body()))
    }

    /// Get an ICMP redirect body view.
    #[inline]
    pub fn redirect(&self) -> Option<IcmpRedirectViewer<&[u8]>> {
        if self.message_type() != IcmpType::Redirect {
            return None;
        }

        self.body()
            .get(..redirect::MIN_LEN)
            .map(|_| IcmpRedirectViewer::new(self.body()))
    }

    /// Get an ICMP timestamp body view.
    #[inline]
    pub fn timestamp(&self) -> Option<IcmpTimestampViewer<&[u8]>> {
        if !matches!(
            self.message_type().get(),
            IcmpType::TimestampRequest | IcmpType::TimestampReply
        ) {
            return None;
        }

        self.body()
            .get(..timestamp::MIN_LEN)
            .map(|_| IcmpTimestampViewer::new(self.body()))
    }

    /// Get an ICMP address mask body view.
    #[inline]
    pub fn address_mask(&self) -> Option<IcmpAddressMaskViewer<&[u8]>> {
        if !matches!(
            self.message_type().get(),
            IcmpType::AddressMaskRequest | IcmpType::AddressMaskReply
        ) {
            return None;
        }

        self.body()
            .get(..address_mask::MIN_LEN)
            .map(|_| IcmpAddressMaskViewer::new(self.body()))
    }
}

impl<T> IcmpViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the ICMP message type.
    #[inline]
    pub fn message_type_mut(&mut self) -> FieldMut<'_, TypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TYPE])
    }

    /// Get the mutable accessor of the ICMP code.
    #[inline]
    pub fn code_mut(&mut self) -> FieldMut<'_, CodeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CODE])
    }

    /// Get the mutable accessor of the checksum.
    #[inline]
    pub fn checksum_mut(&mut self) -> FieldMut<'_, ChecksumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CHECKSUM])
    }

    /// Get the mutable accessor of the 32-bit rest-of-header field.
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
        if data.len() <= Icmp::MIN_LEN {
            &mut data[0..0]
        } else {
            &mut data[Icmp::MIN_LEN..]
        }
    }

    /// Get a mutable ICMP echo body view for echo request/reply messages.
    #[inline]
    pub fn echo_mut(&mut self) -> Option<IcmpEchoViewer<&mut [u8]>> {
        if !matches!(
            self.message_type().get(),
            IcmpType::EchoRequest | IcmpType::EchoReply
        ) || self.body().len() < echo::MIN_LEN
        {
            return None;
        }

        Some(IcmpEchoViewer::new(self.body_mut()))
    }
}

impl<T> core::fmt::Debug for IcmpViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Icmp")
            .field("message_type", &self.message_type().get())
            .field("code", &self.code().get())
            .field("checksum", &self.checksum().get())
            .finish()
    }
}

/// Message-specific ICMPv4 body viewer.
#[derive(Debug)]
pub enum IcmpMessageViewer<'a> {
    /// Echo request or reply.
    Echo(IcmpEchoViewer<&'a [u8]>),
    /// Error message carrying a quoted invoking packet.
    QuotedPacket(IcmpQuotedPacketViewer<&'a [u8]>),
    /// Redirect message.
    Redirect(IcmpRedirectViewer<&'a [u8]>),
    /// Timestamp request or reply.
    Timestamp(IcmpTimestampViewer<&'a [u8]>),
    /// Address mask request or reply.
    AddressMask(IcmpAddressMaskViewer<&'a [u8]>),
    /// Raw message body after the common ICMP header.
    Raw(&'a [u8]),
}

#[cfg(test)]
mod tests {
    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    #[test]
    fn icmp_viewer() {
        let data: [u8; 8] = [
            0x08, // type: echo request
            0x00, // code
            0x00, 0x00, // checksum
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence
        ];

        let icmp = IcmpViewer::new(&data);

        assert_eq!(icmp.message_type(), IcmpType::EchoRequest);
        assert_eq!(icmp.code(), 0);
        assert_eq!(icmp.checksum(), 0);
        assert_eq!(icmp.identifier(), 0x1234);
        assert_eq!(icmp.sequence(), 1);
        let echo = icmp.echo().expect("echo body");
        assert_eq!(echo.identifier(), 0x1234);
        assert_eq!(echo.sequence(), 1);
        assert_eq!(echo.payload(), &[]);
        assert!(matches!(icmp.message(), IcmpMessageViewer::Echo(_)));
    }

    #[test]
    fn parse_ethernet_ipv4_icmp_packet() {
        let data: [u8; 42] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // version + ihl
            0x00, // dscp + ecn
            0x00, 0x1c, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x01, // protocol: ICMP
            0x00, 0x00, // checksum
            10, 0, 1, 1, // source IP
            10, 0, 1, 2,    // destination IP
            0x08, // type: echo request
            0x00, // code
            0x00, 0x00, // checksum
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let icmp = packet.layer_viewer(Icmp).expect("ICMP layer not found");
        assert_eq!(icmp.message_type(), IcmpType::EchoRequest);
        assert_eq!(icmp.identifier(), 0x1234);
        assert_eq!(icmp.echo().expect("echo body").sequence(), 1);
    }

    #[test]
    fn icmp_quoted_packet_viewer() {
        let data: [u8; 16] = [
            0x03, // type: destination unreachable
            0x04, // code: fragmentation needed
            0x00, 0x00, // checksum
            0x00, 0x00, 0x05, 0xdc, // unused + next-hop MTU
            0x45, 0x00, 0x00, 0x14, // quoted packet
            0x00, 0x00, 0x00, 0x00,
        ];

        let icmp = IcmpViewer::new(&data);
        let quoted = icmp.quoted_packet().expect("quoted packet body");

        assert_eq!(quoted.rest_of_header(), 0x0000_05dc);
        assert_eq!(quoted.next_hop_mtu(), 1500);
        assert_eq!(
            quoted.quoted_packet(),
            &[0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0]
        );
        assert!(matches!(icmp.message(), IcmpMessageViewer::QuotedPacket(_)));
    }
}
