//! Transport Layer Security (TLS) record layer.
//!
//! TLS is parsed at the record layer. Each record starts with an 8-bit content
//! type, a 16-bit legacy protocol version, and a 16-bit fragment length. The
//! fragment contains bytes for the protocol named by the content type.
//!
//! ```text
//!   0               1               2               3               4
//! +---------------+---------------+---------------+---------------+---------------+
//! | Content Type  |      Legacy Record Version    |            Length             |
//! +---------------+---------------+---------------+---------------+---------------+
//! |                         Fragment (Length bytes)                               |
//! ~                                      ...                                      ~
//! ```
//!
//! When the record content type is `handshake`, the fragment starts with a TLS
//! handshake message header. Handshake messages can be fragmented across records
//! or coalesced into one record; this viewer only exposes the first handshake
//! header when it is present in the record bytes.
//!
//! ```text
//!   0               1               2               3
//! +---------------+---------------+---------------+---------------+
//! | HandshakeType |               Length (uint24)                 |
//! +---------------+---------------+---------------+---------------+
//! |                    Handshake body (Length bytes)              |
//! ~                              ...                              ~
//! ```

use std::fmt::Debug;

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod content_type;
pub mod handshake_type;

pub use content_type::TlsContentType;
pub use handshake_type::TlsHandshakeType;

/// Transport Layer Security (TLS) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Tls;

impl Tls {
    /// TLS record header length.
    const MIN_LEN: usize = 5;
}

impl Protocol for Tls {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tls = TlsViewer::new(bytes);

        if let Some(handshake_type) = tls.handshake_type() {
            write!(
                fmt,
                "[Tls] {} {} v{:#06x} len {}",
                tls.content_type().get(),
                handshake_type.get(),
                tls.legacy_version().get(),
                tls.length().get()
            )
        } else {
            write!(
                fmt,
                "[Tls] {} v{:#06x} len {}",
                tls.content_type().get(),
                tls.legacy_version().get(),
                tls.length().get()
            )
        }
    }
}

impl ProtocolExt for Tls {
    type Viewer<'a> = TlsViewer<&'a [u8]>;
    type ViewerMut<'a> = TlsViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let header = ctx.require(&Tls, offset, Tls::MIN_LEN)?;

        let tls = TlsViewer::new(header);
        let len = Tls::MIN_LEN + tls.length().get() as usize;
        ctx.require(&Tls, offset, len)?;

        ctx.push_layer(&Tls, offset, len);

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        TlsViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        TlsViewer::new(bytes)
    }
}

field_spec!(ContentTypeSpec, TlsContentType, u8);
field_spec!(VersionSpec, u16, u16);
field_spec!(LengthSpec, u16, u16);
field_spec!(HandshakeTypeSpec, TlsHandshakeType, u8);
field_spec!(HandshakeLengthSpec, [u8; 3], [u8; 3]);

/// Return whether bytes start with a plausible TLS record header.
pub(crate) fn looks_like_record(bytes: &[u8]) -> bool {
    let Some(header) = bytes.get(..Tls::MIN_LEN) else {
        return false;
    };

    matches!(header[0], 20..=24) && header[1] == 0x03 && header[2] <= 0x04
}

/// Transport Layer Security record header and first record payload.
pub struct TlsViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> TlsViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the content type: 0..1
    const FIELD_CONTENT_TYPE: core::ops::Range<usize> = 0..1;
    /// Field range of the legacy record version: 1..3
    const FIELD_LEGACY_VERSION: core::ops::Range<usize> = 1..3;
    /// Field range of the TLS record payload length: 3..5
    const FIELD_LENGTH: core::ops::Range<usize> = 3..5;
    /// Field range of the handshake type within handshake records: 5..6
    const FIELD_HANDSHAKE_TYPE: core::ops::Range<usize> = 5..6;
    /// Field range of the handshake message length within handshake records: 6..9
    const FIELD_HANDSHAKE_LENGTH: core::ops::Range<usize> = 6..9;

    /// Create a new TLS viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the TLS record payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let len = Tls::MIN_LEN + self.length().get() as usize;
        let end = len.min(self.data.as_ref().len());
        &self.data.as_ref()[Tls::MIN_LEN..end]
    }

    /// Get the accessor of the content type.
    #[inline]
    pub fn content_type(&self) -> FieldRef<'_, ContentTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CONTENT_TYPE])
    }

    /// Get the accessor of the legacy record version.
    #[inline]
    pub fn legacy_version(&self) -> FieldRef<'_, VersionSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_LEGACY_VERSION])
    }

    /// Get the accessor of the TLS record payload length.
    #[inline]
    pub fn length(&self) -> FieldRef<'_, LengthSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_LENGTH])
    }

    /// Get the accessor of the first TLS handshake message type, when present.
    #[inline]
    pub fn handshake_type(&self) -> Option<FieldRef<'_, HandshakeTypeSpec>> {
        if self.content_type() != TlsContentType::Handshake {
            return None;
        }

        self.data
            .as_ref()
            .get(Self::FIELD_HANDSHAKE_TYPE)
            .map(FieldRef::new)
    }

    /// Get the accessor of the first TLS handshake message length, when present.
    #[inline]
    pub fn handshake_len_raw(&self) -> Option<FieldRef<'_, HandshakeLengthSpec>> {
        if self.content_type() != TlsContentType::Handshake {
            return None;
        }

        self.data
            .as_ref()
            .get(Self::FIELD_HANDSHAKE_LENGTH)
            .map(FieldRef::new)
    }

    /// Get the first TLS handshake message length, when present.
    #[inline]
    pub fn handshake_len(&self) -> Option<usize> {
        let raw = self.handshake_len_raw()?.get();
        Some(((raw[0] as usize) << 16) | ((raw[1] as usize) << 8) | raw[2] as usize)
    }
}

impl<T> TlsViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable TLS record payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let len = Tls::MIN_LEN + self.length().get() as usize;
        let end = len.min(self.data.as_ref().len());
        &mut self.data.as_mut()[Tls::MIN_LEN..end]
    }

    /// Get the mutable accessor of the content type.
    #[inline]
    pub fn content_type_mut(&mut self) -> FieldMut<'_, ContentTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CONTENT_TYPE])
    }

    /// Get the mutable accessor of the legacy record version.
    #[inline]
    pub fn legacy_version_mut(&mut self) -> FieldMut<'_, VersionSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_LEGACY_VERSION])
    }

    /// Get the mutable accessor of the TLS record payload length.
    #[inline]
    pub fn length_mut(&mut self) -> FieldMut<'_, LengthSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_LENGTH])
    }

    /// Get the mutable accessor of the first TLS handshake message type, when present.
    #[inline]
    pub fn handshake_type_mut(&mut self) -> Option<FieldMut<'_, HandshakeTypeSpec>> {
        if self.content_type() != TlsContentType::Handshake {
            return None;
        }

        self.data
            .as_mut()
            .get_mut(Self::FIELD_HANDSHAKE_TYPE)
            .map(FieldMut::new)
    }

    /// Get the mutable accessor of the first TLS handshake message length, when present.
    #[inline]
    pub fn handshake_len_raw_mut(&mut self) -> Option<FieldMut<'_, HandshakeLengthSpec>> {
        if self.content_type() != TlsContentType::Handshake {
            return None;
        }

        self.data
            .as_mut()
            .get_mut(Self::FIELD_HANDSHAKE_LENGTH)
            .map(FieldMut::new)
    }
}

impl<T> Debug for TlsViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls")
            .field("content_type", &self.content_type().get())
            .field("legacy_version", &self.legacy_version().get())
            .field("length", &self.length().get())
            .field(
                "handshake_type",
                &self.handshake_type().map(|message_type| message_type.get()),
            )
            .field("handshake_len", &self.handshake_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    #[test]
    fn tls_viewer() {
        let data: [u8; 9] = [
            0x16, // handshake
            0x03, 0x03, // TLS 1.2 legacy record version
            0x00, 0x04, // record payload length
            0x01, // client hello
            0x00, 0x00, 0x00, // handshake length
        ];

        let tls = TlsViewer::new(&data);

        assert_eq!(tls.content_type(), TlsContentType::Handshake);
        assert_eq!(tls.legacy_version(), 0x0303);
        assert_eq!(tls.length(), 4);
        assert_eq!(tls.payload(), &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(
            tls.handshake_type().expect("handshake type"),
            TlsHandshakeType::ClientHello
        );
        assert_eq!(tls.handshake_len(), Some(0));
        assert!(looks_like_record(&data));
    }

    #[test]
    fn tls_viewer_mut() {
        let mut data: [u8; 9] = [0; 9];

        let mut tls = TlsViewer::new(&mut data);
        tls.content_type_mut().set(TlsContentType::Handshake);
        tls.legacy_version_mut().set(0x0303);
        tls.length_mut().set(4);
        tls.handshake_type_mut()
            .expect("handshake type")
            .set(TlsHandshakeType::ServerHello);
        tls.handshake_len_raw_mut()
            .expect("handshake length")
            .set([0x00, 0x00, 0x00]);

        assert_eq!(
            data,
            [
                0x16, // handshake
                0x03, 0x03, // TLS 1.2 legacy record version
                0x00, 0x04, // record payload length
                0x02, // server hello
                0x00, 0x00, 0x00, // handshake length
            ]
        );
    }

    #[test]
    fn parse_ethernet_ipv4_tcp_tls_packet() {
        let data: [u8; 63] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // version + ihl
            0x00, // dscp + ecn
            0x00, 0x31, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x06, // protocol: TCP
            0x00, 0x00, // checksum
            10, 0, 1, 1, // source IP
            10, 0, 1, 2, // destination IP
            0x01, 0xbb, // source port 443
            0x30, 0x39, // destination port 12345
            0x00, 0x00, 0x00, 0x01, // sequence number
            0x00, 0x00, 0x00, 0x00, // acknowledgment number
            0x50, // data offset
            0x18, // flags: PSH ACK
            0x20, 0x00, // window size
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent pointer
            0x16, // handshake
            0x03, 0x03, // TLS 1.2 legacy record version
            0x00, 0x04, // record payload length
            0x01, // client hello
            0x00, 0x00, 0x00, // handshake length
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let tls = packet.layer_viewer(Tls).expect("TLS layer not found");
        assert_eq!(tls.content_type(), TlsContentType::Handshake);
        assert_eq!(
            tls.handshake_type().expect("handshake type"),
            TlsHandshakeType::ClientHello
        );
        assert_eq!(tls.handshake_len(), Some(0));
    }
}
