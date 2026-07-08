//! UDP packet crafting.
//!
//! The UDP builder writes an eight-byte UDP header into the final packet
//! buffer. It calculates the UDP checksum when an IPv4 parent supplies
//! pseudo-header context; standalone UDP datagrams default to checksum zero
//! unless set.

use super::{Udp, UdpViewer};
use crate::packet::craft::{
    CraftChild, CraftChildPlan, CraftContext, CraftError, CraftLayer, CraftPlan, checked_add_len,
    checked_u16_len,
};

/// Builder for UDP datagrams.
///
/// If not explicitly set, the UDP length is derived from header + child bytes.
#[derive(Debug, Clone, Default)]
pub struct UdpBuilder {
    src_port: Option<u16>,
    dst_port: Option<u16>,
    length: Option<u16>,
    checksum: Option<u16>,
}

impl UdpBuilder {
    /// Create an empty UDP builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the source port.
    pub fn src_port(mut self, src_port: u16) -> Self {
        self.src_port = Some(src_port);
        self
    }

    /// Set the source port.
    ///
    /// This is a short alias for [`src_port`](UdpBuilder::src_port).
    pub fn src(self, src_port: u16) -> Self {
        self.src_port(src_port)
    }

    /// Set the destination port.
    pub fn dst_port(mut self, dst_port: u16) -> Self {
        self.dst_port = Some(dst_port);
        self
    }

    /// Set the destination port.
    ///
    /// This is a short alias for [`dst_port`](UdpBuilder::dst_port).
    pub fn dst(self, dst_port: u16) -> Self {
        self.dst_port(dst_port)
    }

    /// Set the UDP length field.
    ///
    /// Normally this should be omitted so the builder can derive it from the
    /// measured datagram length. If set, it must exactly match the generated
    /// header plus child length; use a `raw!(...)` child to add payload bytes.
    pub fn length(mut self, length: u16) -> Self {
        self.length = Some(length);
        self
    }

    /// Set the checksum field.
    ///
    /// If unset and an IPv4 parent exists, the checksum is calculated from the
    /// IPv4 pseudo-header and final UDP bytes.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum = Some(checksum);
        self
    }
}

impl CraftLayer for UdpBuilder {
    /// Return the UDP protocol marker used in crafted layer metadata.
    fn protocol(&self) -> &'static dyn crate::packet::layer::Protocol {
        &Udp
    }

    /// Measure the UDP datagram length and child offset.
    fn measure(
        &self,
        _context: CraftContext,
        child: Option<CraftChildPlan>,
    ) -> Result<CraftPlan, CraftError> {
        let child_len = child.map_or(0, |child| child.len());
        let generated_len = checked_add_len("udp", "length", Udp::MIN_LEN, child_len)?;
        let length = match self.length {
            Some(length) if length as usize == generated_len => length,
            Some(length) => {
                return Err(CraftError::InvalidField {
                    protocol: "udp",
                    field: "length",
                    value: length as usize,
                    reason: "must match generated header plus child length; use raw!(...) to add payload bytes",
                });
            }
            None => checked_u16_len("udp", "length", generated_len)?,
        };

        Ok(CraftPlan::new(Udp::MIN_LEN, length as usize))
    }

    /// Write the UDP header and checksum.
    ///
    /// Child bytes have already been written at the measured child offset.
    fn write(
        &self,
        context: CraftContext,
        plan: CraftPlan,
        _child: Option<CraftChild>,
        bytes: &mut [u8],
    ) -> Result<(), CraftError> {
        let length = checked_u16_len("udp", "length", plan.total_len())?;

        {
            let mut udp = UdpViewer::new(&mut bytes[..Udp::MIN_LEN]);
            udp.src_port_mut().set(self.src_port.unwrap_or_default());
            udp.dst_port_mut().set(self.dst_port.unwrap_or_default());
            udp.length_mut().set(length);
            udp.checksum_mut().set(0);
        }

        let checksum = self.checksum.unwrap_or_else(|| {
            context
                .ipv4
                .map(|ctx| UdpViewer::new(&bytes[..]).calculate_checksum_ipv4(ctx.src, ctx.dst))
                .unwrap_or_default()
        });
        UdpViewer::new(&mut bytes[..Udp::MIN_LEN])
            .checksum_mut()
            .set(checksum);

        Ok(())
    }
}

crate::impl_craft_layer_div!(UdpBuilder);

/// Create a UDP builder.
///
/// Fields map to [`UdpBuilder`] methods. A field without a value calls a
/// zero-argument method; a field with `: value` passes that value to the
/// method.
#[macro_export]
macro_rules! udp {
    () => {
        $crate::packet::layer::udp::UdpBuilder::new()
    };

    ($($field:ident $( : $value:expr )?),+ $(,)?) => {
        $crate::packet::layer::udp::UdpBuilder::new()
            $(.$field($($value)?))+
    };
}
