//! # VLAN (IEEE 802.1Q)
//!
//! ## Layer Format
//!
//! In the standard, the VLAN is inserted between the MAC Address and the
//! [`EthType`](crate::packet::layer::eth::EthType) field. That is:
//!
//! ```text
//! +----------+---------+-------------+---------+
//! | MAC Dest | MAC Src | VLAN Header | EthType |
//! +----------+---------+-------------+---------+
//! ```
//!
//! This is a bit complicated, so we view the VLAN as a separate layer:
//!
//! ```text
//! +----------+---------+------------------+-----------------------------+
//! | MAC Dest | MAC Src | EthType (0x8100) | VLAN Header (TCI + EthType) |
//! +----------+---------+------------------+-----------------------------+
//! ```
//!
//! The VLAN header is as follows:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   TCI (PCP 3, DEI 1, VID 12)  |          EtherType            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use std::fmt::Debug;

use log::debug;

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt, eth::EthType},
        utils::field::{FieldMut, FieldRef},
    },
};

/// Vlan (IEEE 802.1Q) LayerKind
#[derive(Debug, Clone, Copy)]
pub struct Vlan;

impl Protocol for Vlan {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vlan = VlanViewer::new(bytes);

        write!(fmt, "[Vlan] {}", vlan.vid().get())
    }
}

impl ProtocolExt for Vlan {
    type Viewer<'a> = VlanViewer<&'a [u8]>;
    type ViewerMut<'a> = VlanViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let header = ctx.require(&Vlan, offset, 4)?;
        let vlan = VlanViewer::new(header);
        let eth_type = vlan.eth_type().get();

        ctx.push_layer(&Vlan, offset, 4);

        match eth_type {
            EthType::Ipv4 => ctx.parse_child::<super::ip::v4::Ipv4>(offset + 4),
            EthType::Arp => ctx.parse_child::<super::arp::Arp>(offset + 4),
            EthType::Ipv6 => ctx.parse_child::<super::ip::v6::Ipv6>(offset + 4),
            EthType::MplsUnicast | EthType::MplsMulticast => {
                ctx.parse_child::<super::mpls::Mpls>(offset + 4)
            }

            EthType::Reserverd(length) if length <= 1500 => {
                ctx.parse_child::<super::llc::Llc>(offset + 4)
            }

            eth_type
                if ctx
                    .options
                    .registry
                    .contains_key(&(Vlan.id(), eth_type.into())) =>
            {
                let parse_fn = ctx.options.registry[&(Vlan.id(), eth_type.into())];
                ctx.parse_child_with(parse_fn, offset + 4)
            }

            _ => {
                debug!("Unsupported EthType: {:?}", eth_type);
                ctx.parse_raw(offset + 4);
                Ok(())
            }
        }
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        VlanViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        VlanViewer::new(bytes)
    }
}

field_spec!(TciSpec, u16, u16);
field_spec!(PcpSpec, u8, u8, 0xE0, 5);
field_spec!(DeiSpec, bool, u8, 0x10, 4);
field_spec!(VidSpec, u16, u16, 0x0FFF, 0);
field_spec!(EthTypeSpec, EthType, u16);

/// Zero-copy viewer for an IEEE 802.1Q VLAN tag.
///
/// The tag contains a 16-bit TCI field split into PCP, DEI, and VID subfields,
/// followed by the encapsulated EtherType.
pub struct VlanViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> VlanViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the TCI: 0..2
    const FIELD_TCI: core::ops::Range<usize> = 0..2;
    /// Field range of the PCP: 0..1
    const FIELD_PCP: core::ops::Range<usize> = 0..1;
    /// Field range of the DEI: 0..1
    const FIELD_DEI: core::ops::Range<usize> = 0..1;
    /// Field range of the VID: 0..2
    const FIELD_VID: core::ops::Range<usize> = 0..2;
    /// Field range of the Ethertype: 2..4
    const FIELD_ETH_TYPE: core::ops::Range<usize> = 2..4;

    /// Create a new VlanViewer from the given data
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data
    pub const fn data(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the TCI field.
    #[inline]
    pub fn tci(&self) -> FieldRef<'_, TciSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TCI])
    }

    /// Get the accessor of the PCP field.
    #[inline]
    pub fn pcp(&self) -> FieldRef<'_, PcpSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PCP])
    }

    /// Get the accessor of the DEI field.
    #[inline]
    pub fn dei(&self) -> FieldRef<'_, DeiSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DEI])
    }

    /// Get the accessor of the VID field.
    #[inline]
    pub fn vid(&self) -> FieldRef<'_, VidSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_VID])
    }

    /// Get the accessor of the EthType field.
    #[inline]
    pub fn eth_type(&self) -> FieldRef<'_, EthTypeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ETH_TYPE])
    }
}

impl<T> VlanViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the TCI field.
    #[inline]
    pub fn tci_mut(&mut self) -> FieldMut<'_, TciSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TCI])
    }

    /// Get the mutable accessor of the PCP field.
    #[inline]
    pub fn pcp_mut(&mut self) -> FieldMut<'_, PcpSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PCP])
    }

    /// Get the mutable accessor of the DEI field.
    #[inline]
    pub fn dei_mut(&mut self) -> FieldMut<'_, DeiSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_DEI])
    }

    /// Get the mutable accessor of the VID field.
    #[inline]
    pub fn vid_mut(&mut self) -> FieldMut<'_, VidSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_VID])
    }

    /// Get the mutable accessor of the EthType field.
    #[inline]
    pub fn eth_type_mut(&mut self) -> FieldMut<'_, EthTypeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ETH_TYPE])
    }
}

impl<T> Debug for VlanViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vlan")
            .field("tci", &self.tci().get())
            .field("pcp", &self.pcp().get())
            .field("dei", &self.dei().get())
            .field("vid", &self.vid().get())
            .field("eth_type", &self.eth_type().get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlan_tci_bit_fields_cover_pcp_dei_and_vid() {
        let mut data = [0x00, 0x00, 0x08, 0x00];
        let mut vlan = VlanViewer::new(&mut data);

        vlan.pcp_mut().set(7);
        vlan.dei_mut().set(true);
        vlan.vid_mut().set(0x0abc);

        assert_eq!(vlan.pcp().get(), 7);
        assert!(vlan.dei().get());
        assert_eq!(vlan.vid().get(), 0x0abc);
        assert_eq!(vlan.tci().get(), 0xfabc);
    }
}
