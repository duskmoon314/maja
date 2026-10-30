//! Address pools of one family, backed by `(network, index)` arithmetic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use rand::{RngExt, rngs::StdRng};

/// Address family of a packet, an entry or a pool.
///
/// IPv4 and IPv6 never mix: the `from` and `to` of one entry must share a
/// family (there is no cross family mapping), so every pool holds one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Family {
    #[default]
    V4,
    V6,
}

impl Family {
    pub fn of_addr(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }

    pub fn of_net(net: &IpNet) -> Self {
        match net {
            IpNet::V4(_) => Family::V4,
            IpNet::V6(_) => Family::V6,
        }
    }

    /// Index into the per-family arrays of this crate.
    pub fn index(self) -> usize {
        match self {
            Family::V4 => 0,
            Family::V6 => 1,
        }
    }

    /// Number of bits of an address of this family.
    fn bits(self) -> u32 {
        match self {
            Family::V4 => 32,
            Family::V6 => 128,
        }
    }

    fn to_addr(self, value: u128) -> IpAddr {
        match self {
            Family::V4 => IpAddr::V4(Ipv4Addr::from(value as u32)),
            Family::V6 => IpAddr::V6(Ipv6Addr::from(value)),
        }
    }
}

/// Network address as an integer, so that both families share one code path.
pub fn net_base(net: &IpNet) -> u128 {
    match net {
        IpNet::V4(net) => u128::from(u32::from(net.network())),
        IpNet::V6(net) => u128::from(net.network()),
    }
}

/// A pool of addresses of one family, backed by `(network, index)` arithmetic
/// instead of a materialised list.
#[derive(Debug, Clone, Default)]
pub struct Pool {
    /// Networks with their cumulative host count.
    nets: Vec<(IpNet, u128)>,

    /// Total number of addresses.
    total: u128,
}

impl Pool {
    pub fn from_nets(nets: impl IntoIterator<Item = IpNet>) -> Self {
        let mut nets = nets.into_iter().collect::<Vec<_>>();
        nets.sort_by_key(|net| (Family::of_net(net).index(), net_base(net), net.prefix_len()));
        nets.dedup();

        // Saturated: a pool of several huge IPv6 prefixes (or `::/0` plus
        // another one) can hold more addresses than `u128` counts. The walk then
        // approximates the pool, as it already does for a single `::/0`.
        let mut total = 0u128;
        let mut cumulative = Vec::with_capacity(nets.len());
        for net in nets {
            total = total.saturating_add(host_count(&net));
            cumulative.push((net, total));
        }

        Pool {
            nets: cumulative,
            total,
        }
    }

    pub fn len(&self) -> u128 {
        self.total
    }

    /// Address at `index`, wrapping around when the pool is exhausted.
    pub fn addr_at(&self, index: u128) -> Option<IpAddr> {
        if self.total == 0 {
            return None;
        }

        let index = index % self.total;
        let pos = self
            .nets
            .partition_point(|(_, cumulative)| *cumulative <= index);
        let (net, cumulative) = &self.nets[pos];
        let start = cumulative - host_count(net);

        Some(host_at(net, index - start))
    }

    /// Random address from the pool.
    pub fn choose(&self, rng: &mut StdRng) -> Option<IpAddr> {
        if self.total == 0 {
            return None;
        }

        self.addr_at(rng.random_range(0..self.total))
    }
}

/// Number of addresses of a network, matching `IpNet::hosts`.
///
/// IPv4 keeps the network and broadcast address out of the pool, except for a
/// `/31` which keeps both. IPv6 has no broadcast address, so every address of
/// the prefix is in the pool. A `/0` IPv6 network is the whole space, which only
/// fits as an upper bound; the walk then misses a single address.
fn host_count(net: &IpNet) -> u128 {
    let host_bits = Family::of_net(net).bits() - u32::from(net.prefix_len());
    let total = 1u128.checked_shl(host_bits).unwrap_or(u128::MAX);

    match net {
        IpNet::V4(_) if host_bits > 1 => total - 2,
        _ => total,
    }
}

/// `index`-th address of a network, skipping IPv4's network address.
fn host_at(net: &IpNet, index: u128) -> IpAddr {
    let host_bits = Family::of_net(net).bits() - u32::from(net.prefix_len());
    let offset = match net {
        IpNet::V4(_) if host_bits > 1 => index.wrapping_add(1),
        _ => index,
    };

    Family::of_net(net).to_addr(net_base(net).wrapping_add(offset))
}

/// Keep the host bits of `addr`, replace the network part with `to`.
///
/// Returns `None` when the families differ; validation rejects mixed entries,
/// so this can only happen for a packet of the other family.
pub fn mask_map(to: IpNet, addr: IpAddr) -> Option<IpAddr> {
    match (to, addr) {
        (IpNet::V4(to), IpAddr::V4(addr)) => {
            Some(IpAddr::V4(to.network() | (addr & to.hostmask())))
        }
        (IpNet::V6(to), IpAddr::V6(addr)) => {
            Some(IpAddr::V6(to.network() | (addr & to.hostmask())))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts_to_pool(net: &str) -> (Pool, Vec<IpAddr>) {
        let net: IpNet = net.parse().unwrap();
        let hosts = match net {
            IpNet::V4(net) => net.hosts().map(IpAddr::V4).collect(),
            IpNet::V6(net) => net.hosts().map(IpAddr::V6).collect(),
        };
        let pool = Pool::from_nets([net]);

        (pool, hosts)
    }

    #[test]
    fn pool_matches_hosts_iterator() {
        let (pool, hosts) = hosts_to_pool("10.0.0.0/29");
        assert_eq!(pool.len() as usize, hosts.len());
        for (index, host) in hosts.iter().enumerate() {
            assert_eq!(pool.addr_at(index as u128), Some(*host));
        }
    }

    #[test]
    fn pool_matches_hosts_iterator_ipv6() {
        let (pool, hosts) = hosts_to_pool("2001:db8::/120");
        assert_eq!(pool.len() as usize, hosts.len());
        for (index, host) in hosts.iter().enumerate() {
            assert_eq!(pool.addr_at(index as u128), Some(*host));
        }
    }

    #[test]
    fn pools_of_several_networks_are_concatenated() {
        let pool = Pool::from_nets([
            "10.0.0.0/24".parse().unwrap(),
            "192.168.0.0/24".parse().unwrap(),
        ]);

        assert_eq!(pool.len(), 254 + 254);
        assert_eq!(pool.addr_at(0), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(pool.addr_at(253), Some("10.0.0.254".parse().unwrap()));
        assert_eq!(pool.addr_at(254), Some("192.168.0.1".parse().unwrap()));
    }

    #[test]
    fn a_pool_beyond_u128_saturates_instead_of_overflowing() {
        // `::/0` plus another huge IPv6 prefix: more addresses than `u128` counts.
        let pool = Pool::from_nets(["::/0".parse().unwrap(), "8000::/1".parse().unwrap()]);

        assert_eq!(pool.len(), u128::MAX);
    }
}
