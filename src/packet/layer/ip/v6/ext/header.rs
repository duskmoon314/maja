//! The standard layout of an IPv6 extension header: a next-header octet, a
//! header extension length octet and the header-specific data behind them.
//!
//! [`options`](super::options), [`mobility`](super::mobility), [`hip`](super::hip) and
//! [`shim6`](super::shim6) share this layout, its length rule and its parse
//! entry point.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Header  |  Hdr Ext Len  |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//! |                     header-specific data                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::{
    field_spec,
    packet::{
        ParseContext,
        error::ParseError,
        layer::Protocol,
        utils::field::{FieldMut, FieldRef},
    },
};

use super::super::{NextHeaderSpec, dispatch::dispatch};

/// Fixed part of a standard-layout extension header: the next header and the
/// header extension length.
pub const MIN_LEN: usize = 2;

field_spec!(Ipv6HdrExtLenSpec, u8, u8);

/// Zero-copy viewer for a standard-layout extension header.
///
/// The viewer is the shared one of the extension headers built on this layout:
/// [`options`](super::options), [`mobility`](super::mobility), [`hip`](super::hip) and
/// [`shim6`](super::shim6).
pub struct Ipv6ExtHeaderViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Ipv6ExtHeaderViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the next header: 0..1
    const FIELD_NEXT_HEADER: core::ops::Range<usize> = 0..1;
    /// Field range of the header extension length: 1..2
    const FIELD_HDR_EXT_LEN: core::ops::Range<usize> = 1..2;

    /// Create a new extension header viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the next header, i.e. the header that follows this one.
    #[inline]
    pub fn next_header(&self) -> FieldRef<'_, NextHeaderSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_NEXT_HEADER])
    }

    /// Get the accessor of the header extension length field (`Hdr Ext Len`,
    /// [RFC 8200 section 4.3](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.3)),
    /// in 8-octet units not counting the first 8 octets.
    #[inline]
    pub fn hdr_ext_len(&self) -> FieldRef<'_, Ipv6HdrExtLenSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_HDR_EXT_LEN])
    }

    /// Return the full header length in octets, `(hdr_ext_len + 1) * 8`.
    #[inline]
    pub fn header_len(&self) -> usize {
        (usize::from(self.data.as_ref()[Self::FIELD_HDR_EXT_LEN.start]) + 1) * 8
    }

    /// Get the header-specific data behind the two fixed octets.
    pub fn data(&self) -> &[u8] {
        &self.data.as_ref()[MIN_LEN..]
    }
}

impl<T> Ipv6ExtHeaderViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the next header, i.e. the header that follows this one.
    #[inline]
    pub fn next_header_mut(&mut self) -> FieldMut<'_, NextHeaderSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_NEXT_HEADER])
    }

    /// Get the mutable accessor of the header extension length field
    /// (`Hdr Ext Len`,
    /// [RFC 8200 section 4.3](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.3)),
    /// in 8-octet units not counting the first 8 octets.
    #[inline]
    pub fn hdr_ext_len_mut(&mut self) -> FieldMut<'_, Ipv6HdrExtLenSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_HDR_EXT_LEN])
    }
}

/// Parse a standard-layout extension header at `offset` and dispatch the header
/// it points at.
///
/// `protocol` is the marker that identifies this header as a layer, and
/// `fixed_len` is the fixed part its declared length has to cover.
///
/// The declared length is trusted only as far as the enclosing payload or the
/// capture reaches: a header that declares more than that takes the bytes that
/// exist and ends the chain.
pub fn parse_ext_header(
    ctx: &mut ParseContext,
    offset: usize,
    protocol: &'static dyn Protocol,
    fixed_len: usize,
) -> Result<(), ParseError> {
    let prefix = ctx.require(protocol, offset, MIN_LEN)?;
    let declared = Ipv6ExtHeaderViewer::new(prefix).header_len();
    if declared < fixed_len {
        return Err(ParseError::Malformed {
            protocol,
            field: "header extension length",
            reason: "the declared header is shorter than the fixed part",
        });
    }

    let len = declared.min(ctx.rest(offset).len());
    let header = ctx.require(protocol, offset, len)?;
    let next_header = Ipv6ExtHeaderViewer::new(header).next_header().get();

    ctx.push_layer(protocol, offset, len);

    if ctx.rest(offset + len).is_empty() {
        ctx.parse_raw(offset + len);
        return Ok(());
    }

    dispatch(ctx, offset + len, next_header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::layer::ip::protocol::IpProtocol;

    #[test]
    fn ext_header_viewer_mut() {
        let mut data = [59, 0, 0, 0, 0, 0, 0, 0];
        {
            let mut header = Ipv6ExtHeaderViewer::new(&mut data[..]);

            header.next_header_mut().set(IpProtocol::Udp);
            header.hdr_ext_len_mut().set(1);

            assert_eq!(header.next_header().get(), IpProtocol::Udp);
            assert_eq!(header.header_len(), 16);
        }

        assert_eq!(data, [17, 1, 0, 0, 0, 0, 0, 0]);
    }
}
