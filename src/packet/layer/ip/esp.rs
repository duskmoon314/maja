//! IP encapsulating security payload (ESP)
//! ([RFC 4303 section 2](https://www.rfc-editor.org/rfc/rfc4303.html#section-2)).
//!
//! The security parameters index and the sequence number are plaintext; the
//! payload data behind them is ciphertext, so an ESP layer ends the chain.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
//! |               Security Parameters Index (SPI)                 | ^Int.
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
//! |                      Sequence Number                          | |ered
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
//! |                    Payload Data* (variable)                   | |   ^
//! ~                                                               ~ |   |
//! |                                                               | |Conf.
//! +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
//! |               |     Padding (0-255 bytes)                     | |ered*
//! +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
//! |                               |  Pad Length   | Next Header   | v   v
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
//! ```

use crate::{
    field_spec,
    packet::{
        ParseContext,
        error::ParseError,
        layer::{Protocol, ProtocolExt},
        utils::field::{FieldMut, FieldRef},
    },
};

/// IP encapsulating security payload header.
#[derive(Debug, Clone, Copy)]
pub struct Esp;

impl Esp {
    /// The security parameters index and the sequence number.
    pub const MIN_LEN: usize = 8;
}

impl Protocol for Esp {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let esp = EspViewer::new(bytes);

        write!(
            fmt,
            "[Esp] spi={:#010x} seq={}",
            esp.spi().get(),
            esp.sequence().get()
        )
    }
}

impl ProtocolExt for Esp {
    type Viewer<'a> = EspViewer<&'a [u8]>;
    type ViewerMut<'a> = EspViewer<&'a mut [u8]>;

    fn parse(ctx: &mut ParseContext, offset: usize) -> Result<(), ParseError> {
        ctx.require(&Esp, offset, Self::MIN_LEN)?;
        ctx.push_layer(&Esp, offset, Self::MIN_LEN);

        // The rest of the payload is encrypted.
        ctx.parse_raw(offset + Self::MIN_LEN);
        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        EspViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        EspViewer::new(bytes)
    }
}

field_spec!(EspSpiSpec, u32, u32);
field_spec!(EspSequenceSpec, u32, u32);

/// Zero-copy viewer for the plaintext part of an ESP header.
pub struct EspViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> EspViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the security parameters index: 0..4
    const FIELD_SPI: core::ops::Range<usize> = 0..4;
    /// Field range of the sequence number: 4..8
    const FIELD_SEQUENCE: core::ops::Range<usize> = 4..8;

    /// Create a new ESP header viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the security parameters index.
    #[inline]
    pub fn spi(&self) -> FieldRef<'_, EspSpiSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SPI])
    }

    /// Get the accessor of the sequence number.
    #[inline]
    pub fn sequence(&self) -> FieldRef<'_, EspSequenceSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SEQUENCE])
    }
}

impl<T> EspViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the security parameters index.
    #[inline]
    pub fn spi_mut(&mut self) -> FieldMut<'_, EspSpiSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SPI])
    }

    /// Get the mutable accessor of the sequence number.
    #[inline]
    pub fn sequence_mut(&mut self) -> FieldMut<'_, EspSequenceSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SEQUENCE])
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::layer::Protocol;
    use crate::packet::{
        Packet,
        layer::{eth::Eth, ip::v6::Ipv6, raw::Raw},
    };

    use super::*;
    use crate::packet::layer::ip::v6::ext::test_util::{eth_ipv6_frame, layers};

    #[test]
    fn esp_viewer() {
        let mut payload = vec![0x00, 0x00, 0x00, 0x2a]; // spi
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x2b]); // sequence
        payload.extend_from_slice(&[0x5a; 16]); // encrypted payload

        let data = eth_ipv6_frame(50, &payload);
        let mut packet = Packet::new(data.as_slice());
        packet.parse::<Eth>(Default::default());

        assert_eq!(layers(&packet), [&Eth as &dyn Protocol, &Ipv6, &Esp, &Raw]);

        let esp = packet.layer_viewer(Esp).expect("esp layer");
        assert_eq!(esp.spi().get(), 0x2a);
        assert_eq!(esp.sequence().get(), 0x2b);

        assert_eq!(packet.layer(Ipv6).unwrap().range(), 14..54);
        assert_eq!(packet.layer(Esp).unwrap().range(), 54..62);
        assert_eq!(packet.layer(Raw).unwrap().range(), 62..78);
    }

    #[test]
    fn esp_viewer_mut() {
        let mut data = [0u8; Esp::MIN_LEN];
        let mut esp = EspViewer::new(&mut data[..]);

        esp.spi_mut().set(0x2a);
        esp.sequence_mut().set(0x2b);

        assert_eq!(data, [0, 0, 0, 0x2a, 0, 0, 0, 0x2b]);
    }
}
