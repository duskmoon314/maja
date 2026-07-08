//! Raw unparsed packet bytes.
//!
//! `Raw` is a terminal pseudo-layer used when bytes remain but the parser
//! either does not recognize the next protocol or stops because of
//! `ParseOptions::max_depth`. It has no wire header of its own; the layer range
//! points directly at the remaining bytes.

use crate::packet::layer::{Protocol, ProtocolExt};

pub mod craft;
pub use craft::RawBuilder;

/// Raw unparsed data LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Raw;

impl Protocol for Raw {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "[Raw] {} bytes", bytes.len())
    }
}

impl ProtocolExt for Raw {
    type Viewer<'a> = RawViewer<&'a [u8]>;
    type ViewerMut<'a> = RawViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut crate::packet::ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        ctx.parse_raw(offset);
        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        RawViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        RawViewer::new(bytes)
    }
}

/// Raw unparsed packet bytes.
pub struct RawViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> RawViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Create a new raw bytes viewer.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the raw bytes.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// Get the raw byte length.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    /// Return whether there are no raw bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes().is_empty()
    }
}

impl<T> RawViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get mutable raw bytes.
    #[inline]
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl<T> core::fmt::Debug for RawViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Raw")
            .field("len", &self.len())
            .field("bytes", &self.bytes())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_viewer() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let raw = RawViewer::new(&data);

        assert_eq!(raw.bytes(), &data);
        assert_eq!(raw.len(), 4);
        assert!(!raw.is_empty());
    }
}
