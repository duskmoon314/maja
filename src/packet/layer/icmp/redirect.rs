//! ICMPv4 redirect body viewer.

use core::net::Ipv4Addr;

use crate::{field_spec, packet::utils::field::FieldRef};

field_spec!(GatewayAddrSpec, Ipv4Addr, u32);

/// Minimum redirect body length after the common ICMP header.
pub(super) const MIN_LEN: usize = 4;

/// ICMPv4 redirect body.
pub struct IcmpRedirectViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> IcmpRedirectViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of gateway internet address: 0..4
    const FIELD_GATEWAY_ADDR: core::ops::Range<usize> = 0..4;

    /// Create a new ICMP redirect body viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get the gateway internet address.
    #[inline]
    pub fn gateway_addr(&self) -> FieldRef<'_, GatewayAddrSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_GATEWAY_ADDR])
    }

    /// Get the quoted invoking packet bytes.
    #[inline]
    pub fn quoted_packet(&self) -> &[u8] {
        if self.data.as_ref().len() <= MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[MIN_LEN..]
        }
    }
}

impl<T> core::fmt::Debug for IcmpRedirectViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IcmpRedirect")
            .field("gateway_addr", &self.gateway_addr().get())
            .field("quoted_packet", &self.quoted_packet())
            .finish()
    }
}
