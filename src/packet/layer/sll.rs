//! # Linux cooked-mode capture (SLL) Layer
//!
//! ## Layer Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Packet Type           |        ARPHRD Type            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      Link-layer Address Length|                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//! |                   Link-layer Address                          |
//! +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                               |        Protocol Type          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Payload                            |
//! ~                              ...                              ~
//! ```
//!
//! TODO: The protocol type depends on the ARPHRD type. Impl the related logic.
//! See <https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html>

use std::fmt::Debug;

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt, eth::EthType},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod arphrd_type;
pub mod packet_type;

pub use arphrd_type::ArphrdType;
pub use packet_type::PacketType;

/// Linux cooked-mode capture (SLL) LayerKind
#[derive(Debug, Clone, Copy)]
pub struct Sll;

impl Protocol for Sll {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sll = SllViewer::new(bytes);

        write!(
            fmt,
            "[Sll] {} {} {:?}",
            sll.packet_type().get(),
            sll.arphrd_type().get(),
            &sll.link_layer_addr().get().as_ref()[0..sll.link_layer_addr_len().get() as usize]
        )
    }
}

impl ProtocolExt for Sll {
    type Viewer<'a> = SllViewer<&'a [u8]>;
    type ViewerMut<'a> = SllViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let header = ctx.require(&Sll, offset, 16)?;
        let sll = SllViewer::new(header);
        let arphrd_type = sll.arphrd_type().get();
        let protocol_type = sll.protocol_type().get();

        ctx.push_layer(&Sll, offset, 16);

        match (arphrd_type, protocol_type) {
            (ArphrdType::ETHER, EthType::Ipv4) => {
                ctx.parse_child::<super::ip::v4::Ipv4>(offset + 16)?
            }
            (ArphrdType::ETHER, EthType::Arp) => ctx.parse_child::<super::arp::Arp>(offset + 16)?,
            (ArphrdType::ETHER, EthType::Ipv6) => {
                ctx.parse_child::<super::ip::v6::Ipv6>(offset + 16)?
            }
            (ArphrdType::ETHER, EthType::MplsUnicast | EthType::MplsMulticast) => {
                ctx.parse_child::<super::mpls::Mpls>(offset + 16)?
            }
            (ArphrdType::ETHER, eth_type)
                if ctx
                    .options
                    .registry
                    .contains_key(&(Sll.id(), eth_type.into())) =>
            {
                let parse_fn = ctx.options.registry[&(Sll.id(), eth_type.into())];
                ctx.parse_child_with(parse_fn, offset + 16)?;
            }

            _ => ctx.parse_raw(offset + 16),
        }

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        SllViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        SllViewer::new(bytes)
    }
}

field_spec!(PacketTypeSpec, PacketType, u16);
field_spec!(ArphrdTypeSpec, ArphrdType, u16);
field_spec!(LinkLayerAddrLenSpec, u16, u16);
field_spec!(LinkLayerAddrSpec, [u8; 8], u64);
field_spec!(ProtocolTypeSpec, EthType, u16);

/// Zero-copy viewer for a Linux cooked capture v1 (`SLL`) header.
///
/// The header is 16 bytes and carries packet direction, ARPHRD hardware type,
/// a fixed-size link-layer address field, and a protocol type similar to an
/// Ethernet EtherType.
pub struct SllViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> SllViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the packet type: 0..2
    const FIELD_PACKET_TYPE: core::ops::Range<usize> = 0..2;
    /// Field range of the ARPHRD type: 2..4
    const FIELD_ARPHRD_TYPE: core::ops::Range<usize> = 2..4;
    /// Field range of the link-layer address length: 4..6
    const FIELD_LL_ADDR_LEN: core::ops::Range<usize> = 4..6;
    /// Field range of the link-layer address: 6..14
    const FIELD_LL_ADDR: core::ops::Range<usize> = 6..14;
    /// Field range of the protocol type: 14..16
    const FIELD_PROTOCOL_TYPE: core::ops::Range<usize> = 14..16;

    /// Create a new SllViewer from the given data
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data
    pub const fn data(&self) -> &T {
        &self.data
    }

    /// Get the accessor for the packet type field
    pub fn packet_type(&self) -> FieldRef<'_, PacketTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PACKET_TYPE])
    }

    /// Get the accessor for the ARPHRD type field
    pub fn arphrd_type(&self) -> FieldRef<'_, ArphrdTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ARPHRD_TYPE])
    }

    /// Get the accessor for the link-layer address length field
    pub fn link_layer_addr_len(&self) -> FieldRef<'_, LinkLayerAddrLenSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_LL_ADDR_LEN])
    }

    /// Get the accessor for the link-layer address field
    pub fn link_layer_addr(&self) -> FieldRef<'_, LinkLayerAddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_LL_ADDR])
    }

    /// Get the accessor for the protocol type field
    pub fn protocol_type(&self) -> FieldRef<'_, ProtocolTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PROTOCOL_TYPE])
    }
}

impl<T> SllViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor for the packet type field
    pub fn packet_type_mut(&mut self) -> FieldMut<'_, PacketTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PACKET_TYPE])
    }

    /// Get the mutable accessor for the ARPHRD type field
    pub fn arphrd_type_mut(&mut self) -> FieldMut<'_, ArphrdTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ARPHRD_TYPE])
    }

    /// Get the mutable accessor for the link-layer address length field
    pub fn link_layer_addr_len_mut(&mut self) -> FieldMut<'_, LinkLayerAddrLenSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_LL_ADDR_LEN])
    }

    /// Get the mutable accessor for the link-layer address field
    pub fn link_layer_addr_mut(&mut self) -> FieldMut<'_, LinkLayerAddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_LL_ADDR])
    }

    /// Get the mutable accessor for the protocol type field
    pub fn protocol_type_mut(&mut self) -> FieldMut<'_, ProtocolTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PROTOCOL_TYPE])
    }
}

impl<T> Debug for SllViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sll")
            .field("packet_type", &self.packet_type().get())
            .field("arphrd_type", &self.arphrd_type().get())
            .field("link_layer_addr_len", &self.link_layer_addr_len().get())
            .field("link_layer_addr", &self.link_layer_addr().get())
            .field("protocol_type", &self.protocol_type().get())
            .finish()
    }
}
