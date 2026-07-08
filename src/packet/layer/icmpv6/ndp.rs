//! ICMPv6 Neighbor Discovery Protocol message body viewers.

use core::net::Ipv6Addr;

use crate::{field_spec, packet::utils::field::FieldRef};

field_spec!(U8Spec, u8, u8);
field_spec!(U16Spec, u16, u16);
field_spec!(U32Spec, u32, u32);
field_spec!(Ipv6AddrSpec, Ipv6Addr, u128);

/// Minimum Router Solicitation body length after the common ICMPv6 header.
pub(super) const ROUTER_SOLICITATION_MIN_LEN: usize = 4;
/// Minimum Router Advertisement body length after the common ICMPv6 header.
pub(super) const ROUTER_ADVERTISEMENT_MIN_LEN: usize = 12;
/// Minimum Neighbor Solicitation body length after the common ICMPv6 header.
pub(super) const NEIGHBOR_SOLICITATION_MIN_LEN: usize = 20;
/// Minimum Neighbor Advertisement body length after the common ICMPv6 header.
pub(super) const NEIGHBOR_ADVERTISEMENT_MIN_LEN: usize = 20;
/// Minimum Redirect body length after the common ICMPv6 header.
pub(super) const REDIRECT_MIN_LEN: usize = 36;

/// ICMPv6 NDP message-specific body view.
#[derive(Debug)]
pub enum Icmpv6NdpViewer<'a> {
    /// Router Solicitation.
    RouterSolicitation(Icmpv6RouterSolicitationViewer<&'a [u8]>),
    /// Router Advertisement.
    RouterAdvertisement(Icmpv6RouterAdvertisementViewer<&'a [u8]>),
    /// Neighbor Solicitation.
    NeighborSolicitation(Icmpv6NeighborSolicitationViewer<&'a [u8]>),
    /// Neighbor Advertisement.
    NeighborAdvertisement(Icmpv6NeighborAdvertisementViewer<&'a [u8]>),
    /// Redirect.
    Redirect(Icmpv6RedirectViewer<&'a [u8]>),
}

/// ICMPv6 Router Solicitation body.
pub struct Icmpv6RouterSolicitationViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6RouterSolicitationViewer<T>
where
    T: AsRef<[u8]>,
{
    const FIELD_RESERVED: core::ops::Range<usize> = 0..4;

    /// Create a new Router Solicitation body viewer.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the reserved field.
    pub fn reserved(&self) -> FieldRef<'_, U32Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RESERVED])
    }

    /// Get NDP options bytes.
    pub fn options(&self) -> &[u8] {
        ndp_options(self.data.as_ref(), ROUTER_SOLICITATION_MIN_LEN)
    }
}

/// ICMPv6 Router Advertisement body.
pub struct Icmpv6RouterAdvertisementViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6RouterAdvertisementViewer<T>
where
    T: AsRef<[u8]>,
{
    const FIELD_CURRENT_HOP_LIMIT: core::ops::Range<usize> = 0..1;
    const FIELD_FLAGS: core::ops::Range<usize> = 1..2;
    const FIELD_ROUTER_LIFETIME: core::ops::Range<usize> = 2..4;
    const FIELD_REACHABLE_TIME: core::ops::Range<usize> = 4..8;
    const FIELD_RETRANS_TIMER: core::ops::Range<usize> = 8..12;

    /// Create a new Router Advertisement body viewer.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the current hop limit.
    pub fn current_hop_limit(&self) -> FieldRef<'_, U8Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_CURRENT_HOP_LIMIT])
    }

    /// Get the flags byte.
    pub fn flags(&self) -> FieldRef<'_, U8Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS])
    }

    /// Get the router lifetime.
    pub fn router_lifetime(&self) -> FieldRef<'_, U16Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ROUTER_LIFETIME])
    }

    /// Get the reachable time.
    pub fn reachable_time(&self) -> FieldRef<'_, U32Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_REACHABLE_TIME])
    }

    /// Get the retransmission timer.
    pub fn retrans_timer(&self) -> FieldRef<'_, U32Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RETRANS_TIMER])
    }

    /// Get NDP options bytes.
    pub fn options(&self) -> &[u8] {
        ndp_options(self.data.as_ref(), ROUTER_ADVERTISEMENT_MIN_LEN)
    }
}

/// ICMPv6 Neighbor Solicitation body.
pub struct Icmpv6NeighborSolicitationViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6NeighborSolicitationViewer<T>
where
    T: AsRef<[u8]>,
{
    const FIELD_RESERVED: core::ops::Range<usize> = 0..4;
    const FIELD_TARGET_ADDR: core::ops::Range<usize> = 4..20;

    /// Create a new Neighbor Solicitation body viewer.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the reserved field.
    pub fn reserved(&self) -> FieldRef<'_, U32Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RESERVED])
    }

    /// Get the target address.
    pub fn target_addr(&self) -> FieldRef<'_, Ipv6AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TARGET_ADDR])
    }

    /// Get NDP options bytes.
    pub fn options(&self) -> &[u8] {
        ndp_options(self.data.as_ref(), NEIGHBOR_SOLICITATION_MIN_LEN)
    }
}

/// ICMPv6 Neighbor Advertisement body.
pub struct Icmpv6NeighborAdvertisementViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6NeighborAdvertisementViewer<T>
where
    T: AsRef<[u8]>,
{
    const FIELD_FLAGS_RESERVED: core::ops::Range<usize> = 0..4;
    const FIELD_TARGET_ADDR: core::ops::Range<usize> = 4..20;

    /// Create a new Neighbor Advertisement body viewer.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the flags and reserved field.
    pub fn flags_reserved(&self) -> FieldRef<'_, U32Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS_RESERVED])
    }

    /// Return whether the router flag is set.
    pub fn router(&self) -> bool {
        self.data.as_ref()[0] & 0x80 != 0
    }

    /// Return whether the solicited flag is set.
    pub fn solicited(&self) -> bool {
        self.data.as_ref()[0] & 0x40 != 0
    }

    /// Return whether the override flag is set.
    pub fn override_flag(&self) -> bool {
        self.data.as_ref()[0] & 0x20 != 0
    }

    /// Get the target address.
    pub fn target_addr(&self) -> FieldRef<'_, Ipv6AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TARGET_ADDR])
    }

    /// Get NDP options bytes.
    pub fn options(&self) -> &[u8] {
        ndp_options(self.data.as_ref(), NEIGHBOR_ADVERTISEMENT_MIN_LEN)
    }
}

/// ICMPv6 Redirect body.
pub struct Icmpv6RedirectViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> Icmpv6RedirectViewer<T>
where
    T: AsRef<[u8]>,
{
    const FIELD_RESERVED: core::ops::Range<usize> = 0..4;
    const FIELD_TARGET_ADDR: core::ops::Range<usize> = 4..20;
    const FIELD_DESTINATION_ADDR: core::ops::Range<usize> = 20..36;

    /// Create a new Redirect body viewer.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the reserved field.
    pub fn reserved(&self) -> FieldRef<'_, U32Spec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RESERVED])
    }

    /// Get the target address.
    pub fn target_addr(&self) -> FieldRef<'_, Ipv6AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TARGET_ADDR])
    }

    /// Get the destination address.
    pub fn destination_addr(&self) -> FieldRef<'_, Ipv6AddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_DESTINATION_ADDR])
    }

    /// Get NDP options bytes.
    pub fn options(&self) -> &[u8] {
        ndp_options(self.data.as_ref(), REDIRECT_MIN_LEN)
    }
}

macro_rules! impl_debug {
    ($name:ident) => {
        impl<T> core::fmt::Debug for $name<T>
        where
            T: AsRef<[u8]>,
        {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("bytes", &self.data.as_ref())
                    .finish()
            }
        }
    };
}

impl_debug!(Icmpv6RouterSolicitationViewer);
impl_debug!(Icmpv6RouterAdvertisementViewer);
impl_debug!(Icmpv6NeighborSolicitationViewer);
impl_debug!(Icmpv6NeighborAdvertisementViewer);
impl_debug!(Icmpv6RedirectViewer);

fn ndp_options(bytes: &[u8], start: usize) -> &[u8] {
    if bytes.len() <= start {
        &bytes[0..0]
    } else {
        &bytes[start..]
    }
}
