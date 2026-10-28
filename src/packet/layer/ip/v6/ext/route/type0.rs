//! Typed payload of the IPv6 Routing type 0 header.
//!
//! The source route (type 0) payload starts with a four-octet reserved field and
//! is followed by the list of IPv6 addresses of the nodes a packet still has to
//! visit
//! ([RFC 2460 section 4.4](https://www.rfc-editor.org/rfc/rfc2460.html#section-4.4)):
//!
//! ```text
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Reserved                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           Address[1]                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ~                              ...                              ~
//! ```

use super::{Ipv6RouteAddrs, Ipv6RouteAddrsMut};

/// Reserved field in front of the address list.
const RESERVED_LEN: usize = 4;

/// Decoded Routing type 0 payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6RouteType0<T> {
    data: T,
}

impl<T: AsRef<[u8]>> Ipv6RouteType0<T> {
    pub(crate) fn parse(data: T) -> Option<Self> {
        (data.as_ref().len() >= RESERVED_LEN).then_some(Self { data })
    }

    /// Get the inner raw data.
    pub fn inner(&self) -> &T {
        &self.data
    }

    /// Iterate over the complete IPv6 addresses carried by this payload.
    pub fn addrs(&self) -> Ipv6RouteAddrs<'_> {
        Ipv6RouteAddrs::new(&self.data.as_ref()[RESERVED_LEN..])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ipv6RouteType0<T> {
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Iterate mutably over the complete IPv6 addresses carried by this payload.
    pub fn addrs_mut(&mut self) -> Ipv6RouteAddrsMut<'_> {
        Ipv6RouteAddrsMut::new(&mut self.data.as_mut()[RESERVED_LEN..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv6Addr;

    #[test]
    fn type0_skips_the_reserved_field() {
        let mut bytes = vec![0u8; RESERVED_LEN];
        bytes.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]); // padding

        let type0 = Ipv6RouteType0::parse(&bytes).expect("type 0 payload");
        assert_eq!(
            type0.addrs().collect::<Vec<_>>(),
            vec!["2001:db8::1".parse::<Ipv6Addr>().unwrap()]
        );
    }

    #[test]
    fn type0_needs_the_reserved_field() {
        assert!(Ipv6RouteType0::parse(&[0x00, 0x01, 0x02]).is_none());
    }

    #[test]
    fn type0_addrs_can_be_rewritten() {
        let mut bytes = vec![0u8; RESERVED_LEN];
        bytes.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());

        let mut type0 = Ipv6RouteType0::parse(&mut bytes[..]).expect("type 0 payload");
        type0
            .addrs_mut()
            .next()
            .expect("one address")
            .set("2001:db8::2".parse::<Ipv6Addr>().unwrap());

        let expected = "2001:db8::2".parse::<Ipv6Addr>().unwrap().octets();
        assert_eq!(&bytes[RESERVED_LEN..], &expected[..]);
    }
}
