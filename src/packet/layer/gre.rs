//! Generic Routing Encapsulation (GRE).
//!
//! GRE starts with a flags/version word and an encapsulated protocol type. This
//! implementation models the RFC 2784 checksum-present bit plus the RFC 2890
//! key and sequence-number extensions. Optional checksum, key, and sequence
//! fields are present when their flags are set. This parser computes the GRE
//! header length from those flags and dispatches supported inner protocol types
//! after the GRE header.
//!
//! ```text
//!   0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! | C | 0 | K | S |            Reserved0              |    Ver    |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                         Protocol Type                         |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                      Checksum (optional)                      |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                      Reserved1 (optional)                     |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                    Key (optional, high bits)                  |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                    Key (optional, low bits)                   |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |             Sequence Number (optional, high bits)             |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |             Sequence Number (optional, low bits)              |
//! +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//! |                         Encapsulated packet                   |
//! ~                              ...                              ~
//! ```

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt, eth::EthType},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod flags;

pub use flags::GreFlags;

/// Generic Routing Encapsulation (GRE) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Gre;

impl Gre {
    /// Minimum GRE header length.
    const MIN_LEN: usize = 4;
}

impl Protocol for Gre {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let gre = GreViewer::new(bytes);

        write!(
            fmt,
            "[Gre] {:?} {:?}",
            gre.protocol_type().get(),
            gre.flags().get()
        )
    }
}

impl ProtocolExt for Gre {
    type Viewer<'a> = GreViewer<&'a [u8]>;
    type ViewerMut<'a> = GreViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let min_header = ctx.require(&Gre, offset, Gre::MIN_LEN)?;

        let gre = GreViewer::new(min_header);
        let header_len = gre.header_len();
        let header = ctx.require(&Gre, offset, header_len)?;
        let gre = GreViewer::new(header);
        let protocol_type = gre.protocol_type().get();

        ctx.push_layer(&Gre, offset, header_len);

        match protocol_type {
            EthType::Ipv4 => {
                ctx.parse_child::<crate::packet::layer::ip::v4::Ipv4>(offset + header_len)?
            }
            EthType::Ipv6 => {
                ctx.parse_child::<crate::packet::layer::ip::v6::Ipv6>(offset + header_len)?
            }
            eth_type
                if ctx
                    .options
                    .registry
                    .contains_key(&(Gre.id(), eth_type.into())) =>
            {
                let parse_fn = ctx.options.registry[&(Gre.id(), eth_type.into())];
                ctx.parse_child_with(parse_fn, offset + header_len)?;
            }
            _ => ctx.parse_raw(offset + header_len),
        }

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        GreViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        GreViewer::new(bytes)
    }
}

field_spec!(FlagsSpec, GreFlags, u16, 0xB000);
field_spec!(VersionSpec, u8, u16, 0x0007);
field_spec!(ProtocolTypeSpec, EthType, u16);
field_spec!(ChecksumSpec, u16, u16);
field_spec!(ReservedSpec, u16, u16);
field_spec!(KeySpec, u32, u32);
field_spec!(SequenceSpec, u32, u32);

/// Generic Routing Encapsulation (GRE).
pub struct GreViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> GreViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of flags/version word: 0..2
    const FIELD_FLAGS_VERSION: core::ops::Range<usize> = 0..2;
    /// Field range of the protocol type: 2..4
    const FIELD_PROTOCOL_TYPE: core::ops::Range<usize> = 2..4;

    /// Create a new GRE viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Return the GRE header length in octets.
    #[inline]
    pub fn header_len(&self) -> usize {
        let flags = self.flags().get();
        let mut len = Gre::MIN_LEN;

        if flags.contains(GreFlags::CHECKSUM) {
            len += 4;
        }
        if flags.contains(GreFlags::KEY) {
            len += 4;
        }
        if flags.contains(GreFlags::SEQUENCE) {
            len += 4;
        }

        len
    }

    /// Get the accessor of GRE flags.
    #[inline]
    pub fn flags(&self) -> FieldRef<'_, FlagsSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_VERSION])
    }

    /// Get the accessor of GRE version.
    #[inline]
    pub fn version(&self) -> FieldRef<'_, VersionSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_VERSION])
    }

    /// Get the accessor of the GRE protocol type.
    #[inline]
    pub fn protocol_type(&self) -> FieldRef<'_, ProtocolTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PROTOCOL_TYPE])
    }

    /// Get the optional checksum accessor.
    #[inline]
    pub fn checksum(&self) -> Option<FieldRef<'_, ChecksumSpec>> {
        let offset = self.checksum_offset()?;
        Some(FieldRef::new(&self.data.as_ref()[offset..offset + 2]))
    }

    /// Get the optional reserved/accessor paired with checksum.
    #[inline]
    pub fn reserved(&self) -> Option<FieldRef<'_, ReservedSpec>> {
        let offset = self.checksum_offset()? + 2;
        Some(FieldRef::new(&self.data.as_ref()[offset..offset + 2]))
    }

    /// Get the optional key accessor.
    #[inline]
    pub fn key(&self) -> Option<FieldRef<'_, KeySpec>> {
        let offset = self.key_offset()?;
        Some(FieldRef::new(&self.data.as_ref()[offset..offset + 4]))
    }

    /// Get the optional sequence number accessor.
    #[inline]
    pub fn sequence(&self) -> Option<FieldRef<'_, SequenceSpec>> {
        let offset = self.sequence_offset()?;
        Some(FieldRef::new(&self.data.as_ref()[offset..offset + 4]))
    }

    fn checksum_offset(&self) -> Option<usize> {
        if self.flags().get().contains(GreFlags::CHECKSUM) {
            Some(Gre::MIN_LEN)
        } else {
            None
        }
    }

    fn key_offset(&self) -> Option<usize> {
        if self.flags().get().contains(GreFlags::KEY) {
            Some(Gre::MIN_LEN + self.checksum_len())
        } else {
            None
        }
    }

    fn sequence_offset(&self) -> Option<usize> {
        if self.flags().get().contains(GreFlags::SEQUENCE) {
            Some(Gre::MIN_LEN + self.checksum_len() + self.key_len())
        } else {
            None
        }
    }

    fn checksum_len(&self) -> usize {
        if self.checksum_offset().is_some() {
            4
        } else {
            0
        }
    }

    fn key_len(&self) -> usize {
        if self.key_offset().is_some() { 4 } else { 0 }
    }
}

impl<T> GreViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of GRE flags.
    #[inline]
    pub fn flags_mut(&mut self) -> FieldMut<'_, FlagsSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_VERSION])
    }

    /// Get the mutable accessor of GRE version.
    #[inline]
    pub fn version_mut(&mut self) -> FieldMut<'_, VersionSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS_VERSION])
    }

    /// Get the mutable accessor of the GRE protocol type.
    #[inline]
    pub fn protocol_type_mut(&mut self) -> FieldMut<'_, ProtocolTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PROTOCOL_TYPE])
    }

    /// Get the mutable optional checksum accessor.
    #[inline]
    pub fn checksum_mut(&mut self) -> Option<FieldMut<'_, ChecksumSpec>> {
        let offset = self.checksum_offset()?;
        Some(FieldMut::new(&mut self.data.as_mut()[offset..offset + 2]))
    }

    /// Get the mutable optional reserved accessor paired with checksum.
    #[inline]
    pub fn reserved_mut(&mut self) -> Option<FieldMut<'_, ReservedSpec>> {
        let offset = self.checksum_offset()? + 2;
        Some(FieldMut::new(&mut self.data.as_mut()[offset..offset + 2]))
    }

    /// Get the mutable optional key accessor.
    #[inline]
    pub fn key_mut(&mut self) -> Option<FieldMut<'_, KeySpec>> {
        let offset = self.key_offset()?;
        Some(FieldMut::new(&mut self.data.as_mut()[offset..offset + 4]))
    }

    /// Get the mutable optional sequence number accessor.
    #[inline]
    pub fn sequence_mut(&mut self) -> Option<FieldMut<'_, SequenceSpec>> {
        let offset = self.sequence_offset()?;
        Some(FieldMut::new(&mut self.data.as_mut()[offset..offset + 4]))
    }
}

impl<T> core::fmt::Debug for GreViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gre")
            .field("flags", &self.flags().get())
            .field("version", &self.version().get())
            .field("protocol_type", &self.protocol_type().get())
            .field("header_len", &self.header_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    #[test]
    fn gre_viewer() {
        let data: [u8; 16] = [
            0xb0, 0x00, // checksum, key, sequence flags; version 0
            0x08, 0x00, // protocol type: IPv4
            0x12, 0x34, // checksum
            0x00, 0x00, // reserved
            0x01, 0x02, 0x03, 0x04, // key
            0x05, 0x06, 0x07, 0x08, // sequence
        ];

        let gre = GreViewer::new(&data);

        assert_eq!(
            gre.flags(),
            GreFlags::CHECKSUM | GreFlags::KEY | GreFlags::SEQUENCE
        );
        assert_eq!(gre.version(), 0);
        assert_eq!(gre.protocol_type(), EthType::Ipv4);
        assert_eq!(gre.header_len(), 16);
        assert_eq!(gre.checksum().expect("checksum").get(), 0x1234);
        assert_eq!(gre.reserved().expect("reserved").get(), 0);
        assert_eq!(gre.key().expect("key").get(), 0x01020304);
        assert_eq!(gre.sequence().expect("sequence").get(), 0x05060708);
    }

    #[test]
    fn gre_reserved0_bit_does_not_create_optional_checksum() {
        let data: [u8; 4] = [
            0x40, 0x00, // reserved0 bit 1 set; version 0
            0x08, 0x00, // protocol type: IPv4
        ];

        let gre = GreViewer::new(&data);

        assert_eq!(gre.flags(), GreFlags::empty());
        assert_eq!(gre.header_len(), 4);
        assert!(gre.checksum().is_none());
    }

    #[test]
    fn gre_viewer_mut() {
        let mut data: [u8; 12] = [0; 12];

        let mut gre = GreViewer::new(&mut data);
        gre.flags_mut().set(GreFlags::KEY | GreFlags::SEQUENCE);
        gre.version_mut().set(0);
        gre.protocol_type_mut().set(EthType::Ipv6);
        gre.key_mut().expect("key").set(0x01020304);
        gre.sequence_mut().expect("sequence").set(0x05060708);

        assert_eq!(
            data,
            [
                0x30, 0x00, // key, sequence flags
                0x86, 0xdd, // protocol type: IPv6
                0x01, 0x02, 0x03, 0x04, // key
                0x05, 0x06, 0x07, 0x08, // sequence
            ]
        );
    }

    #[test]
    fn parse_ethernet_ipv4_gre_ipv4_packet() {
        let data: [u8; 58] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // outer destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // outer source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // version + ihl
            0x00, // dscp + ecn
            0x00, 0x2c, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x2f, // protocol: GRE
            0x00, 0x00, // checksum
            10, 0, 1, 1, // source IP
            10, 0, 1, 2, // destination IP
            0x00, 0x00, // GRE flags/version
            0x08, 0x00, // GRE protocol type: IPv4
            0x45, // inner version + ihl
            0x00, // dscp + ecn
            0x00, 0x14, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x11, // protocol: UDP
            0x00, 0x00, // checksum
            192, 0, 2, 1, // source IP
            192, 0, 2, 2, // destination IP
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let gre = packet.layer_viewer(Gre).expect("GRE layer not found");
        assert_eq!(gre.protocol_type(), EthType::Ipv4);
        assert_eq!(
            packet
                .layer_viewer(crate::packet::layer::ip::v4::Ipv4)
                .expect("inner IPv4 layer")
                .src()
                .get(),
            core::net::Ipv4Addr::new(192, 0, 2, 1)
        );
    }
}
