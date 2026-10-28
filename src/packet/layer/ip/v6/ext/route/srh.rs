//! Typed payload of the IPv6 Segment Routing header (Routing type 4)
//! ([RFC 8754 section 2](https://www.rfc-editor.org/rfc/rfc8754.html#section-2)).
//!
//! The Segment Routing header (SRH) replaces the source route with a segment
//! list and its own TLV area. The segment list is encoded starting from the
//! last segment of the path: the first address is the final destination, and
//! the packet visits the remaining addresses in reverse order of the list.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Next Header   |  Hdr Ext Len  | Routing Type  | Segments Left |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Last Entry   |     Flags     |              Tag              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |            Segment List[0] (128-bit IPv6 address)             |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                                                               |
//!                               ...
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |            Segment List[n] (128-bit IPv6 address)             |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! //                                                             //
//! //         Optional Type Length Value objects (variable)       //
//! //                                                             //
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use super::{Ipv6RouteAddrs, Ipv6RouteAddrsMut};
use crate::{
    field_spec,
    packet::utils::field::{FieldMut, FieldRef},
};

field_spec!(SrhLastEntrySpec, u8, u8);
field_spec!(SrhFlagsSpec, u8, u8);
field_spec!(SrhTagSpec, u16, u16);

/// Decoded Segment Routing header payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Srh<T> {
    data: T,
}

impl<T: AsRef<[u8]>> Ipv6Srh<T> {
    /// Field range of the last entry: 0..1
    const FIELD_LAST_ENTRY: core::ops::Range<usize> = 0..1;
    /// Field range of the flags: 1..2
    const FIELD_FLAGS: core::ops::Range<usize> = 1..2;
    /// Field range of the tag: 2..4
    const FIELD_TAG: core::ops::Range<usize> = 2..4;
    /// Length of the SRH fields in front of the segment list.
    const FIXED_LEN: usize = 4;

    pub(crate) fn parse(data: T) -> Option<Self> {
        (data.as_ref().len() >= Self::FIXED_LEN).then_some(Self { data })
    }

    /// Get the inner raw data.
    pub fn inner(&self) -> &T {
        &self.data
    }

    /// Get the accessor of the index of the last element of the segment list.
    #[inline]
    pub fn last_entry(&self) -> FieldRef<'_, SrhLastEntrySpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_LAST_ENTRY])
    }

    /// Get the accessor of the flags.
    #[inline]
    pub fn flags(&self) -> FieldRef<'_, SrhFlagsSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS])
    }

    /// Get the accessor of the tag.
    #[inline]
    pub fn tag(&self) -> FieldRef<'_, SrhTagSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TAG])
    }

    /// Return the length of the segment list in octets, as declared by the
    /// last entry field and clamped to the available bytes.
    pub fn segment_list_len(&self) -> usize {
        let declared = (usize::from(self.last_entry().get()) + 1) * 16;
        let available = self.data.as_ref().len() - Self::FIXED_LEN;

        declared.min(available - available % 16)
    }

    /// Iterate over the segment list, starting from the last segment of the path.
    pub fn segments(&self) -> Ipv6RouteAddrs<'_> {
        let start = Self::FIXED_LEN;

        Ipv6RouteAddrs::new(&self.data.as_ref()[start..start + self.segment_list_len()])
    }

    /// Return the TLV bytes after the segment list, including padding.
    pub fn tlvs(&self) -> &[u8] {
        let start = Self::FIXED_LEN + self.segment_list_len();

        &self.data.as_ref()[start..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ipv6Srh<T> {
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get the mutable accessor of the index of the last element of the segment
    /// list.
    #[inline]
    pub fn last_entry_mut(&mut self) -> FieldMut<'_, SrhLastEntrySpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_LAST_ENTRY])
    }

    /// Get the mutable accessor of the flags.
    #[inline]
    pub fn flags_mut(&mut self) -> FieldMut<'_, SrhFlagsSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS])
    }

    /// Get the mutable accessor of the tag.
    #[inline]
    pub fn tag_mut(&mut self) -> FieldMut<'_, SrhTagSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TAG])
    }

    /// Iterate mutably over the segment list, starting from the last segment of
    /// the path.
    pub fn segments_mut(&mut self) -> Ipv6RouteAddrsMut<'_> {
        let start = Self::FIXED_LEN;
        let len = self.segment_list_len();
        let (_, rest) = self.data.as_mut().split_at_mut(start);

        Ipv6RouteAddrsMut::new(&mut rest[..len])
    }

    /// Return the mutable TLV bytes after the segment list, including padding.
    pub fn tlvs_mut(&mut self) -> &mut [u8] {
        let start = Self::FIXED_LEN + self.segment_list_len();
        let (_, rest) = self.data.as_mut().split_at_mut(start);

        rest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv6Addr;

    /// Last entry 1 (two segments), tag 0x1234, and two TLV octets.
    fn srh_bytes() -> Vec<u8> {
        let mut data = vec![0x01, 0x02, 0x12, 0x34];
        data.extend_from_slice(&"2001:db8:4::2".parse::<Ipv6Addr>().unwrap().octets());
        data.extend_from_slice(&"2001:db8:4::1".parse::<Ipv6Addr>().unwrap().octets());
        data.extend_from_slice(&[0x04, 0x02]); // padding TLV, truncated on purpose

        data
    }

    #[test]
    fn srh_decodes_fields_segments_and_tlvs() {
        let bytes = srh_bytes();
        let srh = Ipv6Srh::parse(&bytes).expect("srh");

        assert_eq!(srh.last_entry().get(), 1);
        assert_eq!(srh.flags().get(), 0x02);
        assert_eq!(srh.tag().get(), 0x1234);
        assert_eq!(srh.segment_list_len(), 32);
        assert_eq!(
            srh.segments().collect::<Vec<_>>(),
            vec![
                "2001:db8:4::2".parse::<Ipv6Addr>().unwrap(),
                "2001:db8:4::1".parse::<Ipv6Addr>().unwrap(),
            ]
        );
        assert_eq!(srh.tlvs(), &[0x04, 0x02]);
    }

    #[test]
    fn srh_needs_the_fixed_fields() {
        assert!(Ipv6Srh::parse(&[0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn srh_fields_segments_and_tlvs_can_be_rewritten() {
        let mut bytes = srh_bytes();
        {
            let mut srh = Ipv6Srh::parse(&mut bytes[..]).expect("srh");

            // 段列表与 TLV 先写（此时 last entry 仍是 1，列表长 32 字节），
            // 最后再改 last entry，免得中途改变后面两项的位置。
            srh.segments_mut()
                .next()
                .expect("one segment")
                .set("2001:db8:4::9".parse::<Ipv6Addr>().unwrap());
            srh.tlvs_mut()[0] = 0x05;

            srh.last_entry_mut().set(0);
            srh.flags_mut().set(0);
            srh.tag_mut().set(0xbeef);
        }

        assert_eq!(&bytes[..4], &[0x00, 0x00, 0xbe, 0xef]);
        let rewritten = "2001:db8:4::9".parse::<Ipv6Addr>().unwrap().octets();
        assert_eq!(&bytes[4..20], &rewritten[..]);
        assert_eq!(bytes[36], 0x05);
    }
}
