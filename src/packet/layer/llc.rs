//! Logic Link Control (LLC)
//!
//! LLC frames start with DSAP, SSAP, and a control field. This parser currently
//! focuses on SNAP-style LLC, where DSAP and SSAP are both `0xaa`, the control
//! field is one byte, and the following SNAP header carries an OUI plus a
//! protocol identifier similar to EtherType.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     DSAP      |     SSAP      |    Control    |      OUI      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         OUI cont.             |        Protocol ID            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Payload                            |
//! ~                              ...                              ~
//! ```

use std::fmt::Debug;

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt, eth::EthType},
        utils::field::{FieldMut, FieldRef},
    },
};

/// LLC service access point values.
pub mod lsap;
pub use lsap::Lsap;

/// LLC LayerKind
#[derive(Debug, Clone, Copy)]
pub struct Llc;

impl Protocol for Llc {}

impl ProtocolExt for Llc {
    type Viewer<'a> = LlcViewer<&'a [u8]>;
    type ViewerMut<'a> = LlcViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        let min_header = ctx.require(&Llc, offset, 3)?;
        let llc = LlcViewer::new(min_header);

        // Check control field length
        let control_first = llc.control_u().get();
        let control_length = if control_first & 0x03 == 0x03 { 1 } else { 2 };

        // Check if SNAP is used
        let is_snap = llc.dsap() == Lsap::Snap && llc.ssap() == Lsap::Snap;

        if control_length == 1 && is_snap {
            let header = ctx.require(&Llc, offset, 8)?;
            let llc = LlcViewer::new(header);

            // TODO: We only handle this case for now.
            ctx.push_layer(
                &Llc, offset, 8, // DSAP(1) + SSAP(1) + Control(1) + OUI(3) + Protocol ID(2)
            );

            match llc.protocol_id().get() {
                EthType::Ipv4 => ctx.parse_child::<super::ip::v4::Ipv4>(offset + 8)?,
                EthType::Arp => ctx.parse_child::<super::arp::Arp>(offset + 8)?,
                EthType::Ipv6 => ctx.parse_child::<super::ip::v6::Ipv6>(offset + 8)?,
                EthType::MplsUnicast | EthType::MplsMulticast => {
                    ctx.parse_child::<super::mpls::Mpls>(offset + 8)?
                }

                _ => ctx.parse_raw(offset + 8),
            }
        }

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        LlcViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        LlcViewer::new(bytes)
    }
}

field_spec!(DsapSpec, Lsap, u8);
field_spec!(SsapSpec, Lsap, u8, 0xFE);
field_spec!(CommandResponseSpec, bool, u8, 0x01);
field_spec!(UControlSpec, u8, u8);
field_spec!(ISControlSpec, u16, u16);

field_spec!(SnapOuiSpec, [u8; 3], [u8; 3]);
field_spec!(SnapProtocolIdSpec, EthType, u16);

/// Zero-copy viewer for an LLC or LLC/SNAP header.
///
/// Accessors cover the common DSAP/SSAP/control fields and the SNAP OUI and
/// protocol identifier that are valid when the frame uses SNAP encapsulation.
pub struct LlcViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> LlcViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of DSAP
    const FIELD_DSAP: std::ops::Range<usize> = 0..1;
    /// Field range of SSAP
    const FIELD_SSAP: std::ops::Range<usize> = 1..2;
    /// Field range of Control (U format)
    const FIELD_CONTROL_U: std::ops::Range<usize> = 2..3;
    /// Field range of Control (I/S format)
    const FIELD_CONTROL_IS: std::ops::Range<usize> = 2..4;

    /// Field range of OUI (SNAP)
    ///
    /// When SNAP is used, control field should be 1 byte?
    const FIELD_OUI: std::ops::Range<usize> = 3..6;
    /// Field range of Protocol ID (SNAP)
    ///
    /// When SNAP is used, control field should be 1 byte?
    const FIELD_PROTOCOL_ID: std::ops::Range<usize> = 6..8;

    /// Create a new LlcViewer from the given data
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data
    pub const fn data(&self) -> &T {
        &self.data
    }

    /// Get the accessor for DSAP field
    pub fn dsap(&self) -> FieldRef<'_, DsapSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DSAP])
    }

    /// Get the accessor for SSAP field
    pub fn ssap(&self) -> FieldRef<'_, SsapSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_SSAP])
    }

    /// Get the accessor for Control field (U format)
    pub fn control_u(&self) -> FieldRef<'_, UControlSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CONTROL_U])
    }

    /// Get the accessor for Control field (I/S format)
    pub fn control_is(&self) -> FieldRef<'_, ISControlSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CONTROL_IS])
    }

    /// Get the accessor for OUI field (SNAP)
    pub fn oui(&self) -> FieldRef<'_, SnapOuiSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_OUI])
    }

    /// Get the accessor for Protocol ID field (SNAP)
    pub fn protocol_id(&self) -> FieldRef<'_, SnapProtocolIdSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PROTOCOL_ID])
    }
}

impl<T> LlcViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor for DSAP field
    pub fn dsap_mut(&mut self) -> FieldMut<'_, DsapSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_DSAP])
    }

    /// Get the mutable accessor for SSAP field
    pub fn ssap_mut(&mut self) -> FieldMut<'_, SsapSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_SSAP])
    }

    /// Get the mutable accessor for Control field (U format)
    pub fn control_u_mut(&mut self) -> FieldMut<'_, UControlSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CONTROL_U])
    }

    /// Get the mutable accessor for Control field (I/S format)
    pub fn control_is_mut(&mut self) -> FieldMut<'_, ISControlSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_CONTROL_IS])
    }

    /// Get the mutable accessor for OUI field (SNAP)
    pub fn oui_mut(&mut self) -> FieldMut<'_, SnapOuiSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_OUI])
    }

    /// Get the mutable accessor for Protocol ID field (SNAP)
    pub fn protocol_id_mut(&mut self) -> FieldMut<'_, SnapProtocolIdSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PROTOCOL_ID])
    }
}
