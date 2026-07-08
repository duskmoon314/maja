//! Ethernet packet crafting.
//!
//! The Ethernet builder writes a 14-byte Ethernet II header into the final
//! packet buffer. If the caller does not set `eth_type`, it is inferred as IPv4
//! when the child layer is IPv4; otherwise it defaults to zero.

use super::{Eth, EthAddr, EthType, EthViewer};
use crate::packet::{
    craft::{
        CraftChild, CraftChildPlan, CraftContext, CraftError, CraftLayer, CraftPlan,
        checked_add_len,
    },
    layer::ip::v4::Ipv4,
};

/// Builder for Ethernet II frames.
#[derive(Debug, Clone, Default)]
pub struct EthBuilder {
    src: Option<EthAddr>,
    dst: Option<EthAddr>,
    eth_type: Option<EthType>,
}

impl EthBuilder {
    /// Create an empty Ethernet builder.
    ///
    /// Source and destination addresses default to `00:00:00:00:00:00`, and
    /// EtherType is inferred from the child when possible.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the source MAC address.
    pub fn src(mut self, src: impl Into<EthAddr>) -> Self {
        self.src = Some(src.into());
        self
    }

    /// Set the destination MAC address.
    pub fn dst(mut self, dst: impl Into<EthAddr>) -> Self {
        self.dst = Some(dst.into());
        self
    }

    /// Set the EtherType field.
    ///
    /// Use this for custom child protocols or when intentionally crafting a
    /// non-standard frame. If unset, IPv4 children infer `EthType::Ipv4`.
    pub fn eth_type(mut self, eth_type: impl Into<EthType>) -> Self {
        self.eth_type = Some(eth_type.into());
        self
    }
}

impl CraftLayer for EthBuilder {
    /// Return the Ethernet protocol marker used in crafted layer metadata.
    fn protocol(&self) -> &'static dyn crate::packet::layer::Protocol {
        &Eth
    }

    /// Measure the Ethernet frame length and child offset.
    ///
    /// Ethernet has a fixed 14-byte header. Any payload bytes should be
    /// represented by a child layer, usually [`Raw`](crate::packet::layer::raw::Raw).
    fn measure(
        &self,
        _context: CraftContext,
        child: Option<CraftChildPlan>,
    ) -> Result<CraftPlan, CraftError> {
        let child_len = child.map_or(0, |child| child.len());
        Ok(CraftPlan::new(
            14,
            checked_add_len("eth", "total_len", 14, child_len)?,
        ))
    }

    /// Write the Ethernet header into the final slice.
    ///
    /// Child bytes have already been written at the measured child offset.
    fn write(
        &self,
        _context: CraftContext,
        _plan: CraftPlan,
        child: Option<CraftChild>,
        bytes: &mut [u8],
    ) -> Result<(), CraftError> {
        let eth_type = self.eth_type.unwrap_or(match child {
            Some(child) if child.is(Ipv4) => EthType::Ipv4,
            _ => EthType::Reserverd(0),
        });

        {
            let mut eth = EthViewer::new(&mut bytes[..14]);
            eth.dst_mut().set(self.dst.unwrap_or_default());
            eth.src_mut().set(self.src.unwrap_or_default());
            eth.eth_type_mut().set(eth_type);
        }

        Ok(())
    }
}

crate::impl_craft_layer_div!(EthBuilder);

/// Create an Ethernet builder.
///
/// Fields map to [`EthBuilder`] methods. A field without a value calls a
/// zero-argument method; a field with `: value` passes that value to the
/// method.
///
/// ```
/// # use maja::prelude::*;
/// let _ = eth!(
///     src: eth_addr!("02:00:00:00:00:01"),
///     dst: eth_addr!("02:00:00:00:00:02"),
/// );
/// ```
#[macro_export]
macro_rules! eth {
    () => {
        $crate::packet::layer::eth::EthBuilder::new()
    };

    ($($field:ident $( : $value:expr )?),+ $(,)?) => {
        $crate::packet::layer::eth::EthBuilder::new()
            $(.$field($($value)?))+
    };
}
