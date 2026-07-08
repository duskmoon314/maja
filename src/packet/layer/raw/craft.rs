//! Raw payload crafting.
//!
//! Raw is a terminal pseudo-layer. It writes caller-provided bytes directly
//! into the final packet buffer and cannot contain another layer.

use super::Raw;
use crate::packet::craft::{
    CraftChild, CraftChildPlan, CraftContext, CraftError, CraftLayer, CraftPlan,
};

/// Builder for raw payload bytes.
#[derive(Debug, Clone, Default)]
pub struct RawBuilder {
    bytes: Vec<u8>,
}

impl RawBuilder {
    /// Create an empty raw payload builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a raw payload builder from an owned byte vector.
    ///
    /// This moves the vector into the builder, avoiding an intermediate copy
    /// before the final packet buffer is written.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Append payload bytes by copying them into the builder.
    ///
    /// This is the common path for borrowed byte slices. Prefer
    /// [`from_vec`](RawBuilder::from_vec) when the payload is already owned.
    pub fn copy_from(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.bytes.extend_from_slice(bytes.as_ref());
        self
    }
}

impl CraftLayer for RawBuilder {
    /// Return the raw protocol marker used in crafted layer metadata.
    fn protocol(&self) -> &'static dyn crate::packet::layer::Protocol {
        &Raw
    }

    /// Measure the terminal raw payload length.
    ///
    /// Returning an error for a child preserves Raw as a terminal layer.
    fn measure(
        &self,
        _context: CraftContext,
        child: Option<CraftChildPlan>,
    ) -> Result<CraftPlan, CraftError> {
        if child.is_some() {
            return Err(CraftError::RawMustBeTerminal);
        }

        Ok(CraftPlan::new(self.bytes.len(), self.bytes.len()))
    }

    /// Copy raw payload bytes into the final packet buffer.
    fn write(
        &self,
        _context: CraftContext,
        _plan: CraftPlan,
        _child: Option<CraftChild>,
        bytes: &mut [u8],
    ) -> Result<(), CraftError> {
        bytes.copy_from_slice(&self.bytes);
        Ok(())
    }
}

crate::impl_craft_layer_div!(RawBuilder);

/// Create a raw payload builder.
///
/// `raw!(bytes)` copies payload bytes into a terminal raw layer. Named fields
/// map to [`RawBuilder`] methods. A field without a value calls a zero-argument
/// method; a field with `: value` passes that value to the method.
#[macro_export]
macro_rules! raw {
    () => {
        $crate::packet::layer::raw::RawBuilder::new()
    };

    (owned: $value:expr $(,)?) => {
        $crate::packet::layer::raw::RawBuilder::from_vec($value)
    };

    ($payload:expr $(,)?) => {
        $crate::packet::layer::raw::RawBuilder::new().copy_from($payload)
    };

    ($($field:ident $( : $value:expr )?),+ $(,)?) => {
        $crate::packet::layer::raw::RawBuilder::new()
            $(.$field($($value)?))+
    };
}
