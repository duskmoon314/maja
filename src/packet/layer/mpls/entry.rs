//! MPLS label stack entry parsing.

use crate::{
    field_spec,
    packet::utils::field::{FieldMut, FieldRef},
};

field_spec!(LabelSpec, u32, u32, 0xFFFF_F000, 12);
field_spec!(TrafficClassSpec, u8, u32, 0x0000_0E00, 9);
field_spec!(BottomOfStackSpec, u8, u32, 0x0000_0100, 8);
field_spec!(TtlSpec, u8, u32, 0x0000_00FF);

/// MPLS label stack entry.
pub struct MplsEntry<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> MplsEntry<T>
where
    T: AsRef<[u8]>,
{
    /// MPLS label stack entry length.
    pub const LEN: usize = 4;

    /// Field range of the full stack entry: 0..4
    const FIELD_ENTRY: core::ops::Range<usize> = 0..4;

    /// Create a new MPLS label stack entry viewer.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the MPLS label.
    #[inline]
    pub fn label(&self) -> FieldRef<'_, LabelSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ENTRY])
    }

    /// Get the accessor of the traffic class field.
    #[inline]
    pub fn traffic_class(&self) -> FieldRef<'_, TrafficClassSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ENTRY])
    }

    /// Get the accessor of the bottom-of-stack field.
    #[inline]
    pub fn bottom_of_stack(&self) -> FieldRef<'_, BottomOfStackSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ENTRY])
    }

    /// Get the accessor of the time-to-live field.
    #[inline]
    pub fn ttl(&self) -> FieldRef<'_, TtlSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ENTRY])
    }
}

impl<T> MplsEntry<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the MPLS label.
    #[inline]
    pub fn label_mut(&mut self) -> FieldMut<'_, LabelSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ENTRY])
    }

    /// Get the mutable accessor of the traffic class field.
    #[inline]
    pub fn traffic_class_mut(&mut self) -> FieldMut<'_, TrafficClassSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ENTRY])
    }

    /// Get the mutable accessor of the bottom-of-stack field.
    #[inline]
    pub fn bottom_of_stack_mut(&mut self) -> FieldMut<'_, BottomOfStackSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ENTRY])
    }

    /// Get the mutable accessor of the time-to-live field.
    #[inline]
    pub fn ttl_mut(&mut self) -> FieldMut<'_, TtlSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ENTRY])
    }
}

impl<T> core::fmt::Debug for MplsEntry<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MplsEntry")
            .field("label", &self.label().get())
            .field("traffic_class", &self.traffic_class().get())
            .field("bottom_of_stack", &self.bottom_of_stack().get())
            .field("ttl", &self.ttl().get())
            .finish()
    }
}

/// Iterator over MPLS label stack entries.
#[derive(Debug, Clone)]
pub struct MplsEntries<'a> {
    bytes: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> MplsEntries<'a> {
    /// Create a new MPLS label stack iterator.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for MplsEntries<'a> {
    type Item = MplsEntry<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset + MplsEntry::<&[u8]>::LEN > self.bytes.len() {
            return None;
        }

        let start = self.offset;
        self.offset += MplsEntry::<&[u8]>::LEN;
        let entry = MplsEntry::new(&self.bytes[start..start + MplsEntry::<&[u8]>::LEN]);
        if entry.bottom_of_stack().get() != 0 {
            self.done = true;
        }
        Some(entry)
    }
}
