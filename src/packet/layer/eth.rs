//! Ethernet II frame parsing.
//!
//! Ethernet frames start with destination and source MAC addresses followed by
//! a 16-bit type-or-length field. Values greater than `1500` are interpreted as
//! EtherType values and drive child protocol dispatch; length values dispatch
//! to LLC/SNAP parsing.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Destination MAC                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Destination MAC cont. |          Source MAC                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Source MAC cont.           | EtherType/Len |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Payload                            |
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

pub mod craft;
/// Ethernet MAC address type and conversions.
pub mod eth_addr;
/// EtherType registry values and display helpers.
pub mod eth_type;

pub use craft::EthBuilder;
pub use eth_addr::EthAddr;
pub use eth_type::EthType;
use log::debug;

/// Ethernet LayerKind
#[derive(Debug, Clone, Copy)]
pub struct Eth;

impl Protocol for Eth {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let eth = EthViewer::new(bytes);

        write!(fmt, "[Eth] {} -> {}", eth.dst().get(), eth.src().get())
    }
}

impl ProtocolExt for Eth {
    type Viewer<'a> = EthViewer<&'a [u8]>;
    type ViewerMut<'a> = EthViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let header = ctx.require(&Eth, offset, 14)?;
        let eth = EthViewer::new(header);
        let eth_type = eth.eth_type().get();

        ctx.push_layer(&Eth, offset, 14);

        match eth_type {
            EthType::Ipv4 => ctx.parse_child::<super::ip::v4::Ipv4>(offset + 14)?,
            EthType::Arp => ctx.parse_child::<super::arp::Arp>(offset + 14)?,
            EthType::Ipv6 => ctx.parse_child::<super::ip::v6::Ipv6>(offset + 14)?,
            EthType::Vlan => ctx.parse_child::<super::vlan::Vlan>(offset + 14)?,
            EthType::MplsUnicast | EthType::MplsMulticast => {
                ctx.parse_child::<super::mpls::Mpls>(offset + 14)?
            }

            EthType::Reserverd(length) if length <= 1500 => {
                ctx.parse_child::<super::llc::Llc>(offset + 14)?
            }

            eth_type
                if ctx
                    .options
                    .registry
                    .contains_key(&(Eth.id(), eth_type.into())) =>
            {
                let parse_fn = ctx.options.registry[&(Eth.id(), eth_type.into())];
                ctx.parse_child_with(parse_fn, offset + 14)?;
            }

            _ => {
                debug!("Unsupported EthType: {}", eth_type);
                ctx.parse_raw(offset + 14);
            }
        }

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        EthViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        EthViewer::new(bytes)
    }
}

field_spec!(EthAddrSpec, EthAddr, [u8; 6]);
field_spec!(EthTypeSpec, EthType, u16);

/// Zero-copy viewer for an Ethernet II header.
///
/// The viewer expects at least 14 bytes. Parsing code validates that before
/// constructing a viewer, while direct callers are responsible for providing a
/// correctly sized slice.
pub struct EthViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> EthViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the destination MAC address: 0..6
    const FIELD_DST: core::ops::Range<usize> = 0..6;
    /// Field range of the source MAC address: 6..12
    const FIELD_SRC: core::ops::Range<usize> = 6..12;
    /// Field range of the Eth type: 12..14
    const FIELD_ETH_TYPE: core::ops::Range<usize> = 12..14;

    /// Create a new EthViewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the destination MAC address.
    pub fn dst(&self) -> FieldRef<'_, EthAddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DST])
    }

    /// Get the accessor of the source MAC address.
    pub fn src(&self) -> FieldRef<'_, EthAddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SRC])
    }

    /// Get the accessor of the [`EthType`] field.
    pub fn eth_type(&self) -> FieldRef<'_, EthTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ETH_TYPE])
    }
}

impl<T> EthViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the destination MAC address.
    pub fn dst_mut(&mut self) -> FieldMut<'_, EthAddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_DST])
    }

    /// Get the mutable accessor of the source MAC address.
    pub fn src_mut(&mut self) -> FieldMut<'_, EthAddrSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SRC])
    }

    /// Get the mutable accessor of the [`EthType`] field.
    pub fn eth_type_mut(&mut self) -> FieldMut<'_, EthTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ETH_TYPE])
    }
}

impl<T> Debug for EthViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Eth")
            .field("dst", &self.dst().get())
            .field("src", &self.src().get())
            .field("eth_type", &self.eth_type().get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::{eth_addr, packet::layer::Layer};

    use super::*;

    #[test]
    fn eth_viewer() {
        let data: [u8; 14] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // dst mac
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, // src mac
            0x08, 0x00, // eth type ipv4
        ];

        let eth = EthViewer::new(&data);

        assert_eq!(eth.dst(), eth_addr!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));
        assert_eq!(eth.src(), eth_addr!(0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67));
        assert_eq!(eth.eth_type(), EthType::Ipv4);
    }

    #[test]
    fn eth_viewer_mut() {
        let mut data: [u8; 14] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // dst mac
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, // src mac
            0x08, 0x00, // eth type ipv4
        ];

        let mut eth = EthViewer::new(&mut data);

        eth.dst_mut()
            .set(eth_addr!(0x11, 0x22, 0x33, 0x44, 0x55, 0x66));
        eth.src_mut()
            .set(eth_addr!(0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC));
        eth.eth_type_mut().set(EthType::Arp);

        assert_eq!(eth.dst(), eth_addr!(0x11, 0x22, 0x33, 0x44, 0x55, 0x66));
        assert_eq!(eth.src(), eth_addr!(0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC));
        assert_eq!(eth.eth_type(), EthType::Arp);
    }

    #[test]
    fn eth_viewer_from_packet() {
        use crate::packet::Packet;

        let data: [u8; 14] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // dst mac
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, // src mac
            0x08, 0x00, // eth type ipv4
        ];

        let packet = Packet {
            bytes: &data,
            layers: vec![Layer {
                protocol: &Eth,
                offset: 0,
                len: 14,
            }],
        };

        let eth = packet.layer_viewer(Eth).expect("Eth layer not found");

        assert_eq!(eth.dst(), eth_addr!(0x01, 0x23, 0x45, 0x67, 0x89, 0xAB));
        assert_eq!(eth.src(), eth_addr!(0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67));
        assert_eq!(eth.eth_type(), EthType::Ipv4);
    }

    #[test]
    fn eth_viewer_mut_from_packet() {
        use crate::packet::Packet;

        let mut data: [u8; 14] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // dst mac
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, // src mac
            0x08, 0x00, // eth type ipv4
        ];

        let mut packet = Packet {
            bytes: &mut data,
            layers: vec![Layer {
                protocol: &Eth,
                offset: 0,
                len: 14,
            }],
        };

        let mut eth = packet.layer_viewer_mut(Eth).expect("Eth layer not found");

        eth.dst_mut()
            .set(eth_addr!(0x11, 0x22, 0x33, 0x44, 0x55, 0x66));
        eth.src_mut()
            .set(eth_addr!(0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC));
        eth.eth_type_mut().set(EthType::Arp);

        assert_eq!(
            data,
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // dst mac
                0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, // src mac
                0x08, 0x06, // eth type arp
            ]
        );
    }
}
