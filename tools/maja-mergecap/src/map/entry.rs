//! Compiling `from -> to` rules and the stateless direct maps.

use std::net::IpAddr;

use anyhow::bail;
use ipnet::IpNet;
use rand::rngs::StdRng;

use super::{
    packet::{IpFamily, outer_ip_family, outer_ipv4_mut, outer_ipv6_mut},
    pool::{Family, Pool, mask_map},
};
use crate::config::{MapEntry, MapPolicy, MapShape, Target};

/// One compiled map entry: `from` is already an [`IpNet`] and the action carries
/// exactly the data its shape needs.
#[derive(Debug, Clone)]
pub struct CompiledEntry {
    pub from: Option<IpNet>,
    pub action: Action,
}

/// What a compiled entry does with an address inside its `from` scope.
#[derive(Debug, Clone)]
pub enum Action {
    /// `fixed`: rewrite to this address.
    Fixed(IpAddr),
    /// `mask`: copy the host bits into this network.
    Mask(IpNet),
    /// `pool`: hand out an address with this policy.
    Pool { pool: Pool, policy: MapPolicy },
}

impl CompiledEntry {
    /// Compile a validated entry; `default_policy` applies to a pool that does
    /// not name its own policy.
    pub fn compile(entry: &MapEntry, default_policy: MapPolicy) -> anyhow::Result<Self> {
        let action = match (entry.shape(), &entry.to) {
            (MapShape::Fixed, Target::Ip(ip)) => Action::Fixed(*ip),
            (MapShape::Mask, Target::Net(to)) => Action::Mask(*to),
            (MapShape::Pool, Target::Net(net)) => Action::Pool {
                pool: Pool::from_nets([*net]),
                policy: entry.policy.unwrap_or(default_policy),
            },
            (shape, target) => bail!("`{shape:?}` does not fit the target {target:?}"),
        };

        Ok(CompiledEntry {
            from: entry.from,
            action,
        })
    }

    /// Number of addresses of the pool (`0` for `fixed`/`mask`).
    pub fn pool_len(&self) -> u128 {
        match &self.action {
            Action::Pool { pool, .. } => pool.len(),
            Action::Fixed(_) | Action::Mask(_) => 0,
        }
    }
}

/// Sort entries so that the most specific `from` wins; a catch-all (`from` is
/// `None`) sorts last.
pub fn sort_entries(entries: &mut [CompiledEntry]) {
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.from.map_or(0u8, |net| net.prefix_len())));
}

// =============================== direct maps ===============================

/// Direct (per direction) rewriting: entries with a `from` network act as
/// rules, entries without one are pooled together per direction.
///
/// This is the stateless legacy path: it draws per packet and keeps no state.
pub struct DirectMaps {
    src: DirectionMap,
    dst: DirectionMap,
    rng: StdRng,
}

struct DirectionMap {
    /// Entries with a `from` network, longest prefix first.
    rules: Vec<CompiledEntry>,

    /// Merged pools of every entry *without* a `from` network, one per family:
    /// used when no rule matches, so several unscoped entries share one pool
    /// instead of only the first one being used.
    merged: [Pool; 2],
}

impl DirectMaps {
    pub fn new(
        src_map: &[MapEntry],
        ip_map: &[MapEntry],
        dst_map: &[MapEntry],
        rng: StdRng,
    ) -> anyhow::Result<Self> {
        let src: Vec<&MapEntry> = src_map.iter().chain(ip_map).collect();
        let dst: Vec<&MapEntry> = dst_map.iter().chain(ip_map).collect();

        Ok(DirectMaps {
            src: DirectionMap::new(&src)?,
            dst: DirectionMap::new(&dst)?,
            rng,
        })
    }

    /// Rewrite the source and destination of one packet.
    pub fn rewrite<T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        packet: &mut maja::packet::Packet<T>,
    ) -> bool {
        match outer_ip_family(packet) {
            Some(IpFamily::V4) => {
                let Some(mut ipv4) = outer_ipv4_mut(packet) else {
                    return false;
                };
                let mut changed = false;

                let src = IpAddr::V4(ipv4.src().get());
                if let Some(IpAddr::V4(ip)) = self.src.target(src, &mut self.rng) {
                    ipv4.src_mut().set(ip);
                    changed = true;
                }

                let dst = IpAddr::V4(ipv4.dst().get());
                if let Some(IpAddr::V4(ip)) = self.dst.target(dst, &mut self.rng) {
                    ipv4.dst_mut().set(ip);
                    changed = true;
                }

                changed
            }
            Some(IpFamily::V6) => {
                let Some(mut ipv6) = outer_ipv6_mut(packet) else {
                    return false;
                };
                let mut changed = false;

                let src = IpAddr::V6(ipv6.src().get());
                if let Some(IpAddr::V6(ip)) = self.src.target(src, &mut self.rng) {
                    ipv6.src_mut().set(ip);
                    changed = true;
                }

                let dst = IpAddr::V6(ipv6.dst().get());
                if let Some(IpAddr::V6(ip)) = self.dst.target(dst, &mut self.rng) {
                    ipv6.dst_mut().set(ip);
                    changed = true;
                }

                changed
            }
            None => false,
        }
    }
}

impl DirectionMap {
    fn new(entries: &[&MapEntry]) -> anyhow::Result<Self> {
        let mut rules = Vec::new();
        let mut merged: [Vec<IpNet>; 2] = [Vec::new(), Vec::new()];

        for entry in entries {
            let compiled = CompiledEntry::compile(entry, MapPolicy::Random)?;
            match compiled.from {
                Some(_) => rules.push(compiled),
                // Unscoped entries are pooled per family; validation already
                // made sure the entry itself is single family.
                None => {
                    let net = entry.to.net();
                    merged[Family::of_net(&net).index()].push(net);
                }
            }
        }
        sort_entries(&mut rules);

        Ok(DirectionMap {
            rules,
            merged: [
                Pool::from_nets(std::mem::take(&mut merged[0])),
                Pool::from_nets(std::mem::take(&mut merged[1])),
            ],
        })
    }

    /// New address of `addr`, or `None` when it stays unchanged.
    fn target(&mut self, addr: IpAddr, rng: &mut StdRng) -> Option<IpAddr> {
        if let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule.from.is_some_and(|from| from.contains(&addr)))
        {
            return match &rule.action {
                Action::Fixed(ip) => Some(*ip),
                Action::Mask(to) => mask_map(*to, addr),
                Action::Pool { pool, .. } => pool.choose(rng),
            };
        }

        self.merged[Family::of_addr(addr).index()].choose(rng)
    }
}

#[cfg(test)]
mod tests {
    use ipnet::Ipv4Net;
    use maja::prelude::*;

    use super::*;
    use crate::map::derived_rng;

    const CLIENT: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 168, 1, 10);
    const SERVER: std::net::Ipv4Addr = std::net::Ipv4Addr::new(203, 0, 113, 80);

    fn entry(from: Option<&str>, to: &str) -> MapEntry {
        MapEntry {
            from: from.map(|from| from.parse().unwrap()),
            to: Target::try_from(to.to_string()).unwrap(),
            shape: None,
            policy: None,
        }
    }

    fn maps(src: &[MapEntry], ip: &[MapEntry], dst: &[MapEntry]) -> DirectMaps {
        DirectMaps::new(src, ip, dst, derived_rng(1, 0)).unwrap()
    }

    fn addrs(packet: &CraftedPacket) -> (std::net::Ipv4Addr, std::net::Ipv4Addr) {
        let ipv4 = packet.nth_layer_viewer(Ipv4, -1).expect("ipv4 layer");
        (ipv4.src().get(), ipv4.dst().get())
    }

    fn tcp_packet(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr) -> CraftedPacket {
        (eth!() / ipv4!(src: src, dst: dst) / tcp!(src: 1234, dst: 80))
            .build()
            .unwrap()
    }

    #[test]
    fn direct_map_pools_are_merged_not_first_match() {
        let mut maps = maps(
            &[],
            &[],
            &[entry(None, "10.0.0.0/24"), entry(None, "10.0.1.0/24")],
        );

        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let mut packet = tcp_packet(CLIENT, SERVER);
            maps.rewrite(&mut packet);
            seen.insert(addrs(&packet).1);
        }

        assert!(
            seen.iter()
                .any(|ip| "10.0.0.0/24".parse::<Ipv4Net>().unwrap().contains(ip))
        );
        assert!(
            seen.iter()
                .any(|ip| "10.0.1.0/24".parse::<Ipv4Net>().unwrap().contains(ip))
        );
    }

    #[test]
    fn direct_map_rules_win_over_the_merged_pool() {
        let mut maps = maps(
            &[],
            &[],
            &[
                entry(Some("192.168.0.0/16"), "10.10.0.0/24"),
                entry(None, "10.20.0.0/24"),
            ],
        );

        for _ in 0..8 {
            // The rule is about the address being rewritten, here the destination.
            let mut packet = tcp_packet(SERVER, CLIENT);
            maps.rewrite(&mut packet);
            let (_, dst) = addrs(&packet);
            assert!(
                "10.10.0.0/24".parse::<Ipv4Net>().unwrap().contains(&dst),
                "{dst}"
            );
        }
    }

    #[test]
    fn direct_map_scoped_random_only_touches_its_scope() {
        let mut maps = maps(&[], &[], &[entry(Some("192.168.0.0/16"), "10.10.0.0/24")]);

        let mut inside = tcp_packet(SERVER, CLIENT);
        maps.rewrite(&mut inside);
        assert!(
            "10.10.0.0/24"
                .parse::<Ipv4Net>()
                .unwrap()
                .contains(&addrs(&inside).1)
        );

        let mut outside = tcp_packet(SERVER, std::net::Ipv4Addr::new(8, 8, 8, 8));
        maps.rewrite(&mut outside);
        assert_eq!(addrs(&outside).1, std::net::Ipv4Addr::new(8, 8, 8, 8));
    }
}
