//! The `flow_map` state: one target per key, with the four pool policies.

use std::{cell::RefCell, collections::HashMap, net::IpAddr, rc::Rc};

use anyhow::bail;
use ipnet::IpNet;
use log::warn;
use maja::packet::Packet;
use rand::{RngExt, rngs::StdRng};

use super::{
    entry::{Action, CompiledEntry, sort_entries},
    packet::{FragKey, PacketInfo, SessionId, Targets, addr_to_u128, apply_targets},
    pool::{Family, Pool, mask_map},
};
use crate::config::{FlowMap, MapKey, MapPolicy, MapSharing, ProtocolSpec};
use crate::map::MAP_RNG_SALT;

/// What one allocation is keyed by, taken from the `key` of the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Identity {
    /// Symmetric five-tuple of one connection.
    Session(SessionId),

    /// One fragmented datagram, grouped by its identification.
    Fragment(FragKey),

    /// One endpoint address.
    Address,
}

/// Key of one allocation inside one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AllocId {
    entry: u32,
    identity: Identity,
    addr: IpAddr,
}

/// Identity of one endpoint, from the key of the map and what the packet carries.
fn identity(key: MapKey, session: Option<SessionId>, fragment: Option<FragKey>) -> Identity {
    match key {
        MapKey::Address => Identity::Address,
        MapKey::Session => match (fragment, session) {
            // A fragment behind the first one carries no ports, so the
            // identification is what groups the datagram.
            (Some(fragment), _) => Identity::Fragment(fragment),
            (None, Some(session)) => Identity::Session(session),
            (None, None) => Identity::Address,
        },
    }
}

// ------------------------------- protocol set ------------------------------

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, Copy)]
struct ProtocolSet {
    any: bool,
    set: [bool; 256],
}

impl ProtocolSet {
    fn compile(spec: &ProtocolSpec) -> anyhow::Result<Self> {
        let names = spec.names();
        if names.is_empty() {
            bail!("`protocols` must not be empty");
        }

        let mut set = [false; 256];
        let mut any = false;
        for name in names {
            match name.to_ascii_lowercase().as_str() {
                "any" | "all" => any = true,
                "tcp" => set[IPPROTO_TCP as usize] = true,
                "udp" => set[IPPROTO_UDP as usize] = true,
                "icmp" => set[1] = true,
                "icmpv6" => set[IPPROTO_ICMPV6 as usize] = true,
                other => match other.parse::<u8>() {
                    Ok(number) => set[number as usize] = true,
                    Err(_) => bail!("unknown protocol {other:?} in `protocols`"),
                },
            }
        }

        Ok(ProtocolSet { any, set })
    }

    fn allows(&self, proto: u8) -> bool {
        self.any || self.set[proto as usize]
    }
}

// -------------------------------- flow config ------------------------------

/// The compiled `flow_map`, without any state.
#[derive(Debug, Clone)]
pub struct FlowCfg {
    key: MapKey,
    entries: Vec<CompiledEntry>,
    exclude: Vec<IpNet>,
    protocols: ProtocolSet,
    fragments: bool,
}

impl FlowCfg {
    /// Compile a validated map; the policy of the map is the default of the
    /// entries that do not name their own.
    pub fn compile(flow: &FlowMap) -> anyhow::Result<Self> {
        let mut entries: Vec<CompiledEntry> = flow
            .entries
            .iter()
            .map(|entry| CompiledEntry::compile(entry, flow.policy))
            .collect::<anyhow::Result<_>>()?;
        sort_entries(&mut entries);

        Ok(FlowCfg {
            key: flow.key,
            entries,
            exclude: flow.exclude.clone(),
            protocols: ProtocolSet::compile(&flow.protocols)?,
            fragments: flow.fragments,
        })
    }

    /// Whether any entry hashes instead of keeping state.
    pub fn uses_hash(&self) -> bool {
        self.entries.iter().any(|entry| {
            matches!(
                entry.action,
                Action::Pool {
                    policy: MapPolicy::Hash,
                    ..
                }
            )
        })
    }

    /// Whether any entry needs a table between packets.
    pub fn is_stateful(&self) -> bool {
        self.entries.iter().any(|entry| {
            matches!(
                entry.action,
                Action::Pool {
                    policy,
                    ..
                } if policy.is_stateful()
            )
        })
    }

    /// Longest `from` prefix first; the catch-all (if any) is last.
    fn classify(&self, addr: IpAddr) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.from.is_none_or(|net| net.contains(&addr)))
    }

    fn excluded(&self, addr: IpAddr) -> bool {
        self.exclude.iter().any(|net| net.contains(&addr))
    }

    /// Whether a fragmented datagram needs an alias, i.e. whether either of its
    /// endpoints draws per packet.
    fn needs_alias(&self, info: &PacketInfo) -> bool {
        [info.src, info.dst].into_iter().any(|addr| {
            self.classify(addr).is_some_and(|entry| {
                matches!(
                    self.entries[entry].action,
                    Action::Pool {
                        policy: MapPolicy::Random,
                        ..
                    }
                )
            })
        })
    }
}

// ------------------------------- allocation --------------------------------

/// Pseudo-random walk over `0..pool_len` that visits every index exactly once
/// before repeating, without materialising a permutation.
#[derive(Debug, Clone, Copy)]
struct Sequence {
    start: u128,
    step: u128,
    drawn: u128,
}

impl Sequence {
    fn new(rng: &mut StdRng, pool_len: u128) -> Self {
        if pool_len <= 1 {
            return Sequence {
                start: 0,
                step: 1,
                drawn: 0,
            };
        }

        // Pools that do not fit in 64 bits (an IPv6 prefix of `/64` or shorter)
        // can never be exhausted, so a plain walk from a random start is enough
        // and keeps `drawn * step` inside `u128`.
        if pool_len > u128::from(u64::MAX) {
            return Sequence {
                start: rng.random_range(0..pool_len),
                step: 1,
                drawn: 0,
            };
        }

        // A step that is coprime with the pool size walks the whole pool.
        let offset = rng.random_range(1..pool_len);
        let step = (1..pool_len)
            .map(|i| (offset + i) % pool_len)
            .find(|step| *step != 0 && gcd(*step, pool_len) == 1)
            .unwrap_or(1);

        Sequence {
            start: rng.random_range(0..pool_len),
            step,
            drawn: 0,
        }
    }

    /// Next index and whether the pool already wrapped around.
    fn next_index(&mut self, pool_len: u128) -> (u128, bool) {
        let drawn = self.drawn % pool_len;
        let index = self.start.wrapping_add(drawn * self.step) % pool_len;
        let wrapped = self.drawn >= pool_len;
        self.drawn = self.drawn.wrapping_add(1);

        (index, wrapped)
    }
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

/// Allocation table, its non-repeating walks and the fragment aliases of one
/// identity state.
pub struct AllocSlot {
    table: HashMap<AllocId, IpAddr>,
    sequences: Vec<Sequence>,
    rng: StdRng,
    warned_wrap: Vec<bool>,
}

impl AllocSlot {
    fn new(seed: u64, salt: u64, pool_lens: &[u128]) -> Self {
        let mut rng = super::derived_rng(seed, salt);
        AllocSlot {
            table: HashMap::new(),
            sequences: pool_lens
                .iter()
                .map(|pool_len| Sequence::new(&mut rng, *pool_len))
                .collect(),
            rng,
            warned_wrap: vec![false; pool_lens.len()],
        }
    }

    /// Draw once for this key and remember the address.
    fn sticky(&mut self, id: AllocId, pool: &Pool) -> Option<IpAddr> {
        if let Some(target) = self.table.get(&id) {
            return Some(*target);
        }

        let target = pool.choose(&mut self.rng)?;
        self.table.insert(id, target);

        Some(target)
    }

    /// Hand out an address no other key of this entry got yet.
    fn unique(&mut self, id: AllocId, pool: &Pool) -> Option<IpAddr> {
        if let Some(target) = self.table.get(&id) {
            return Some(*target);
        }

        let pool_len = pool.len();
        let entry = id.entry as usize;
        let (index, wrapped) = self.sequences[entry].next_index(pool_len);

        if wrapped
            && let Some(warned) = self.warned_wrap.get_mut(entry)
            && !*warned
        {
            *warned = true;
            warn!(
                "flow_map: target pool of entry {entry} is exhausted \
                 ({pool_len} addresses); reusing addresses, keys may merge"
            );
        }

        let target = pool.addr_at(index)?;
        self.table.insert(id, target);

        Some(target)
    }
}

/// One allocation state: either shared by every parallel group or one per group.
pub struct Allocation {
    slots: Vec<AllocSlot>,
    shared: bool,
}

impl Allocation {
    pub fn new(cfg: &FlowCfg, seed: u64, sharing: MapSharing, groups: usize) -> Self {
        let pool_lens: Vec<u128> = cfg.entries.iter().map(CompiledEntry::pool_len).collect();
        let groups = groups.max(1);

        match sharing {
            MapSharing::Shared => Allocation {
                slots: vec![AllocSlot::new(
                    seed,
                    MAP_RNG_SALT.wrapping_add(1),
                    &pool_lens,
                )],
                shared: true,
            },
            MapSharing::PerGroup => Allocation {
                slots: (0..groups)
                    .map(|group| {
                        AllocSlot::new(
                            seed,
                            MAP_RNG_SALT.wrapping_add(group as u64).wrapping_mul(2),
                            &pool_lens,
                        )
                    })
                    .collect(),
                shared: false,
            },
        }
    }

    /// The table of one parallel group.
    pub fn slot(&mut self, group: usize) -> &mut AllocSlot {
        if self.shared {
            &mut self.slots[0]
        } else {
            let index = group.min(self.slots.len() - 1);
            &mut self.slots[index]
        }
    }
}

/// Per-group state that is not part of an allocation table.
struct GroupState {
    rng: StdRng,
    fragments: HashMap<FragKey, Targets>,
}

// --------------------------------- the state -------------------------------

/// Session-level rewriting.
pub struct FlowState {
    cfg: FlowCfg,
    /// Seed of the stateless `hash` policy; the global seed, so a file's place in
    /// the merge cannot change its mapping.
    hash_seed: u64,
    groups: Vec<GroupState>,
    allocation: Option<Rc<RefCell<Allocation>>>,
    warned_unmatched: bool,
}

impl FlowState {
    pub fn new(
        cfg: FlowCfg,
        hash_seed: u64,
        file_seed: u64,
        groups: usize,
        sharing: MapSharing,
        allocation: Option<Rc<RefCell<Allocation>>>,
    ) -> Self {
        let groups = groups.max(1);
        let allocation = allocation.or_else(|| {
            cfg.is_stateful().then(|| {
                Rc::new(RefCell::new(Allocation::new(
                    &cfg, file_seed, sharing, groups,
                )))
            })
        });

        FlowState {
            groups: (0..groups)
                .map(|group| GroupState {
                    rng: super::derived_rng(file_seed, MAP_RNG_SALT.wrapping_add(group as u64)),
                    fragments: HashMap::new(),
                })
                .collect(),
            cfg,
            hash_seed,
            allocation,
            warned_unmatched: false,
        }
    }

    /// Returns whether any address was rewritten.
    pub fn rewrite<T: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        packet: &mut Packet<T>,
        group: usize,
    ) -> bool {
        let Some(info) = PacketInfo::read(packet) else {
            return false;
        };

        if !self.cfg.protocols.allows(info.proto) {
            return false;
        }

        let targets = self.targets(group, &info);
        apply_targets(packet, targets);

        targets.src.is_some() || targets.dst.is_some()
    }

    /// Targets of one packet, with the fragment aliasing applied first.
    ///
    /// `hash` and the stateful policies key the datagram by its identification,
    /// so they need no alias; `random` draws per packet and keeps one draw per
    /// datagram in the cache of the group.
    fn targets(&mut self, group: usize, info: &PacketInfo) -> Targets {
        let Some(fragment) = info.fragment.filter(|_| self.cfg.fragments) else {
            return self.targets_for(group, info, None);
        };

        if !self.cfg.needs_alias(info) {
            return self.targets_for(group, info, Some(fragment));
        }

        if let Some(targets) = self.groups[group].fragments.get(&fragment).copied() {
            return targets;
        }

        let targets = self.targets_for(group, info, Some(fragment));
        self.groups[group].fragments.insert(fragment, targets);

        targets
    }

    /// Targets for both endpoints of one packet.
    fn targets_for(
        &mut self,
        group: usize,
        info: &PacketInfo,
        fragment: Option<FragKey>,
    ) -> Targets {
        let session = info.session();

        Targets {
            src: self.target_for(group, info.src, session, fragment),
            dst: self.target_for(group, info.dst, session, fragment),
        }
    }

    /// Target address of one endpoint, or `None` when it stays unchanged.
    fn target_for(
        &mut self,
        group: usize,
        addr: IpAddr,
        session: Option<SessionId>,
        fragment: Option<FragKey>,
    ) -> Option<IpAddr> {
        let FlowState {
            cfg,
            groups,
            allocation,
            hash_seed,
            warned_unmatched,
            ..
        } = self;

        if cfg.excluded(addr) {
            return None;
        }

        let Some(entry) = cfg.classify(addr) else {
            if !*warned_unmatched {
                *warned_unmatched = true;
                warn!("flow_map: no entry matches {addr}; leaving this address unchanged");
            }
            return None;
        };

        // `fixed` and `mask` need neither randomness nor state. A target of the
        // other family cannot happen for a validated entry.
        match &cfg.entries[entry].action {
            Action::Fixed(ip) => (Family::of_addr(*ip) == Family::of_addr(addr)).then_some(*ip),
            Action::Mask(to) => mask_map(*to, addr),
            Action::Pool { pool, policy } => {
                let policy = *policy;
                if pool.len() == 0 {
                    return None;
                }
                let identity = identity(cfg.key, session, fragment);

                match policy {
                    MapPolicy::Random => pool.choose(&mut groups[group].rng),
                    MapPolicy::Hash => {
                        let index = hash_index(*hash_seed, entry, addr, identity, pool.len());
                        pool.addr_at(index)
                    }
                    MapPolicy::Sticky | MapPolicy::Unique => {
                        let id = AllocId {
                            entry: entry as u32,
                            identity,
                            addr,
                        };
                        let slot = allocation
                            .as_ref()
                            .expect("a stateful policy has an allocation");
                        let mut slot = slot.borrow_mut();
                        let slot = slot.slot(group);

                        match policy {
                            MapPolicy::Sticky => slot.sticky(id, pool),
                            _ => slot.unique(id, pool),
                        }
                    }
                }
            }
        }
    }
}

/// Stateless hashed index, stable for the same identity.
fn hash_index(seed: u64, entry: usize, addr: IpAddr, identity: Identity, pool_len: u128) -> u128 {
    let mut hash = StableHash::new(seed).write(entry as u64);

    match identity {
        Identity::Session(session) => {
            hash = hash
                .write_u128(session.a().0)
                .write(u64::from(session.a().1))
                .write_u128(session.b().0)
                .write(u64::from(session.b().1))
                .write(u64::from(session.proto()));
        }
        Identity::Fragment(fragment) => {
            hash = hash
                .write_u128(addr_to_u128(fragment.src))
                .write_u128(addr_to_u128(fragment.dst))
                .write(u64::from(fragment.proto))
                .write(u64::from(fragment.id));
        }
        Identity::Address => hash = hash.write(u64::MAX),
    }

    u128::from(hash.write_u128(addr_to_u128(addr)).finish()) % pool_len
}

// ================================ hashing =================================

/// Deterministic hash used by [`MapPolicy::Hash`]; independent of `std`'s
/// `RandomState` so that it is reproducible across runs and platforms.
#[derive(Debug, Clone, Copy)]
struct StableHash(u64);

impl StableHash {
    fn new(seed: u64) -> Self {
        StableHash(seed ^ 0xcbf2_9ce4_8422_2325)
    }

    fn write(mut self, value: u64) -> Self {
        self.0 = super::splitmix64(self.0 ^ value.wrapping_mul(0x0000_0100_0000_01b3));
        self
    }

    fn write_u128(self, value: u128) -> Self {
        self.write((value >> 64) as u64).write(value as u64)
    }

    fn finish(self) -> u64 {
        super::splitmix64(self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, path::PathBuf};

    use maja::prelude::*;

    use super::*;
    use crate::{
        config::{AllocScope, InputFile, MapEntry, Target},
        map::{MapRuntime, Rewriter},
    };

    const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 80);

    fn entry(from: Option<&str>, to: &str, policy: Option<MapPolicy>) -> MapEntry {
        MapEntry {
            from: from.map(|from| from.parse().unwrap()),
            to: Target::try_from(to.to_string()).unwrap(),
            shape: None,
            policy,
        }
    }

    fn flow(policy: MapPolicy, entries: Vec<MapEntry>) -> FlowMap {
        FlowMap {
            policy,
            entries,
            ..Default::default()
        }
    }

    fn file(flow: FlowMap) -> InputFile<PathBuf> {
        InputFile {
            path: PathBuf::from("test.pcap"),
            flow_map: Some(flow),
            ..Default::default()
        }
    }

    fn make_rewriter(flow: FlowMap, file_seed: u64, groups: usize) -> Rewriter {
        let mut runtime = MapRuntime::new();
        Rewriter::new(&file(flow), &mut runtime, file_seed, 7, groups, true).unwrap()
    }

    fn tcp_packet(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> CraftedPacket {
        (eth!() / ipv4!(src: src, dst: dst) / tcp!(src: src_port, dst: dst_port) / raw!(b"payload"))
            .build()
            .unwrap()
    }

    fn addrs(packet: &CraftedPacket) -> (Ipv4Addr, Ipv4Addr) {
        let ipv4 = packet.nth_layer_viewer(Ipv4, -1).expect("ipv4 layer");
        (ipv4.src().get(), ipv4.dst().get())
    }

    fn unique_flow() -> FlowMap {
        flow(
            MapPolicy::Unique,
            vec![
                entry(Some("192.168.0.0/16"), "10.0.0.0/24", None),
                entry(Some("203.0.113.0/24"), "10.1.0.0/24", None),
            ],
        )
    }

    #[test]
    fn unique_is_stable_per_session_and_direction_independent() {
        let mut rewriter = make_rewriter(unique_flow(), 1, 1);

        let mut request = tcp_packet(CLIENT, SERVER, 40000, 80);
        rewriter.rewrite(&mut request, 0);
        let (src, dst) = addrs(&request);

        let mut retransmit = tcp_packet(CLIENT, SERVER, 40000, 80);
        rewriter.rewrite(&mut retransmit, 0);
        assert_eq!(addrs(&retransmit), (src, dst));

        // The reply direction reuses the same pair.
        let mut reply = tcp_packet(SERVER, CLIENT, 80, 40000);
        rewriter.rewrite(&mut reply, 0);
        assert_eq!(addrs(&reply), (dst, src));

        // A different session gets a different pair.
        let mut other = tcp_packet(CLIENT, SERVER, 40001, 80);
        rewriter.rewrite(&mut other, 0);
        assert_ne!(addrs(&other), (src, dst));
    }

    #[test]
    fn sticky_is_stable_but_does_not_promise_uniqueness() {
        let mut rewriter = make_rewriter(
            flow(
                MapPolicy::Sticky,
                vec![entry(Some("192.168.0.0/16"), "10.0.0.0/8", None)],
            ),
            1,
            1,
        );

        let mut packet = tcp_packet(CLIENT, SERVER, 40000, 80);
        rewriter.rewrite(&mut packet, 0);
        let mapped = addrs(&packet).0;

        for _ in 0..8 {
            let mut again = tcp_packet(CLIENT, SERVER, 40000, 80);
            rewriter.rewrite(&mut again, 0);
            assert_eq!(addrs(&again).0, mapped);
        }
    }

    #[test]
    fn address_key_keeps_one_identity_per_host() {
        let by_address = FlowMap {
            key: MapKey::Address,
            ..unique_flow()
        };
        let mut rewriter = make_rewriter(by_address, 1, 1);

        let mut first = tcp_packet(CLIENT, SERVER, 40000, 80);
        rewriter.rewrite(&mut first, 0);
        let (client, server) = addrs(&first);

        let mut second = tcp_packet(CLIENT, SERVER, 40001, 80);
        rewriter.rewrite(&mut second, 0);
        assert_eq!(addrs(&second), (client, server));

        // A session key, on the other hand, may hand out another address.
        let mut by_session = make_rewriter(unique_flow(), 1, 1);
        let mut first = tcp_packet(CLIENT, SERVER, 40000, 80);
        by_session.rewrite(&mut first, 0);
        let mut second = tcp_packet(CLIENT, SERVER, 40001, 80);
        by_session.rewrite(&mut second, 0);
        assert_ne!(addrs(&first).0, addrs(&second).0);
    }

    #[test]
    fn hash_is_stateless_and_uses_the_global_seed() {
        let map = flow(
            MapPolicy::Hash,
            vec![entry(Some("192.168.0.0/16"), "10.0.0.0/24", None)],
        );

        let mut first = make_rewriter(map.clone(), 1, 1);
        let mut packet = tcp_packet(CLIENT, SERVER, 40000, 80);
        first.rewrite(&mut packet, 0);
        let mapped = addrs(&packet).0;

        // A different file seed changes nothing: only the global seed counts.
        let mut second = make_rewriter(map.clone(), 99, 1);
        let mut again = tcp_packet(CLIENT, SERVER, 40000, 80);
        second.rewrite(&mut again, 0);
        assert_eq!(addrs(&again).0, mapped);

        // Another global seed changes the mapping.
        let mut runtime = MapRuntime::new();
        let mut other = Rewriter::new(&file(map), &mut runtime, 1, 8, 1, true).unwrap();
        let mut packet = tcp_packet(CLIENT, SERVER, 40000, 80);
        other.rewrite(&mut packet, 0);
        assert_ne!(addrs(&packet).0, mapped);
    }

    #[test]
    fn hash_honours_the_address_key() {
        let map = flow(
            MapPolicy::Hash,
            vec![entry(Some("192.168.0.0/16"), "10.0.0.0/24", None)],
        );

        // A session key hashes per connection.
        let mut by_session = make_rewriter(map.clone(), 1, 1);
        let mut first = tcp_packet(CLIENT, SERVER, 40000, 80);
        by_session.rewrite(&mut first, 0);
        let mut second = tcp_packet(CLIENT, SERVER, 40001, 80);
        by_session.rewrite(&mut second, 0);
        assert_ne!(addrs(&first).0, addrs(&second).0);

        // An address key hashes per host, so both connections agree.
        let by_address = FlowMap {
            key: MapKey::Address,
            ..map
        };
        let mut by_address = make_rewriter(by_address, 1, 1);
        let mut first = tcp_packet(CLIENT, SERVER, 40000, 80);
        by_address.rewrite(&mut first, 0);
        let mut second = tcp_packet(CLIENT, SERVER, 40001, 80);
        by_address.rewrite(&mut second, 0);
        assert_eq!(addrs(&first).0, addrs(&second).0);
    }

    #[test]
    fn stateful_policies_give_every_group_its_own_identity() {
        let mut rewriter = make_rewriter(unique_flow(), 1, 2);

        let mut group0 = tcp_packet(CLIENT, SERVER, 40000, 80);
        rewriter.rewrite(&mut group0, 0);
        let mut group1 = tcp_packet(CLIENT, SERVER, 40000, 80);
        rewriter.rewrite(&mut group1, 1);
        assert_ne!(addrs(&group0), addrs(&group1));

        let mut again = tcp_packet(CLIENT, SERVER, 40000, 80);
        rewriter.rewrite(&mut again, 0);
        assert_eq!(addrs(&again), addrs(&group0));
    }

    #[test]
    fn shared_sharing_makes_the_groups_identical() {
        let shared = FlowMap {
            sharing: Some(MapSharing::Shared),
            ..unique_flow()
        };
        let mut rewriter = make_rewriter(shared, 1, 2);

        let mut group0 = tcp_packet(CLIENT, SERVER, 40000, 80);
        rewriter.rewrite(&mut group0, 0);
        let mut group1 = tcp_packet(CLIENT, SERVER, 40000, 80);
        rewriter.rewrite(&mut group1, 1);
        assert_eq!(addrs(&group0), addrs(&group1));
    }

    #[test]
    fn global_scope_shares_one_table_between_files() {
        let global = FlowMap {
            alloc_scope: AllocScope::Global,
            ..unique_flow()
        };
        let mut runtime = MapRuntime::new();

        let mut first = Rewriter::new(&file(global.clone()), &mut runtime, 1, 7, 1, true).unwrap();
        let mut packet = tcp_packet(CLIENT, SERVER, 40000, 80);
        first.rewrite(&mut packet, 0);
        let mapped = addrs(&packet);

        // Another file with the same map reuses the table of the first one.
        let mut second = Rewriter::new(&file(global), &mut runtime, 2, 7, 1, true).unwrap();
        let mut packet = tcp_packet(CLIENT, SERVER, 40000, 80);
        second.rewrite(&mut packet, 0);
        assert_eq!(addrs(&packet), mapped);

        // A file scoped map starts a table of its own.
        let mut runtime = MapRuntime::new();
        let mut first = Rewriter::new(&file(unique_flow()), &mut runtime, 1, 7, 1, true).unwrap();
        let mut packet = tcp_packet(CLIENT, SERVER, 40000, 80);
        first.rewrite(&mut packet, 0);
        let file_scoped = addrs(&packet);
        let mut second = Rewriter::new(&file(unique_flow()), &mut runtime, 2, 7, 1, true).unwrap();
        let mut packet = tcp_packet(CLIENT, SERVER, 40000, 80);
        second.rewrite(&mut packet, 0);
        assert_ne!(addrs(&packet), file_scoped);
    }

    fn fragmented(identification: u16, fragment_offset: u16, more: bool) -> CraftedPacket {
        let flags = u8::from(more);
        (eth!()
            / ipv4!(
                src: CLIENT,
                dst: SERVER,
                identification: identification,
                flags: flags,
                fragment_offset: fragment_offset,
                protocol: IpProtocol::Tcp
            )
            / raw!(b"fragment"))
        .build()
        .unwrap()
    }

    #[test]
    fn fragments_share_one_target_per_group() {
        let mut rewriter = make_rewriter(unique_flow(), 1, 2);

        let mut first = (eth!()
            / ipv4!(src: CLIENT, dst: SERVER, identification: 7, flags: 1, protocol: IpProtocol::Tcp)
            / tcp!(src: 40000, dst: 80)
            / raw!(b"first"))
        .build()
        .unwrap();
        rewriter.rewrite(&mut first, 0);
        let expected = addrs(&first);

        let mut second = fragmented(7, 8, false);
        rewriter.rewrite(&mut second, 0);
        assert_eq!(addrs(&second), expected, "the datagram keeps its targets");

        // The other group must not inherit the aliases of the first one.
        let mut group1 = fragmented(7, 0, true);
        rewriter.rewrite(&mut group1, 1);
        assert_ne!(addrs(&group1), expected);
    }

    #[test]
    fn hashed_fragments_do_not_depend_on_the_arrival_order() {
        let map = flow(
            MapPolicy::Hash,
            vec![entry(Some("192.168.0.0/16"), "10.0.0.0/24", None)],
        );

        // The later fragment arrives first and decides.
        let mut rewriter = make_rewriter(map.clone(), 1, 1);
        let mut later = fragmented(9, 8, false);
        rewriter.rewrite(&mut later, 0);
        let expected = addrs(&later);

        let mut first = fragmented(9, 0, true);
        rewriter.rewrite(&mut first, 0);
        assert_eq!(addrs(&first), expected);

        // A fresh state gives the same result: nothing was remembered.
        let mut fresh = make_rewriter(map, 1, 1);
        let mut first = fragmented(9, 0, true);
        fresh.rewrite(&mut first, 0);
        assert_eq!(addrs(&first), expected);
    }

    #[test]
    fn exclude_and_protocol_filter_keep_addresses() {
        let tolerant = FlowMap {
            entries: vec![entry(Some("0.0.0.0/0"), "10.0.0.0/24", None)],
            protocols: ProtocolSpec::One("tcp".to_string()),
            ..Default::default()
        };
        let mut rewriter = make_rewriter(tolerant, 1, 1);

        // Broadcast destination is excluded by default.
        let mut broadcast = (eth!()
            / ipv4!(src: CLIENT, dst: Ipv4Addr::new(255, 255, 255, 255))
            / udp!(src: 68, dst: 67))
        .build()
        .unwrap();
        rewriter.rewrite(&mut broadcast, 0);
        assert_eq!(
            addrs(&broadcast),
            (CLIENT, Ipv4Addr::new(255, 255, 255, 255))
        );

        // UDP is not in the protocol filter.
        let mut udp = (eth!() / ipv4!(src: CLIENT, dst: SERVER) / udp!(src: 1, dst: 2))
            .build()
            .unwrap();
        rewriter.rewrite(&mut udp, 0);
        assert_eq!(addrs(&udp), (CLIENT, SERVER));

        let mut tcp = tcp_packet(CLIENT, SERVER, 1, 2);
        rewriter.rewrite(&mut tcp, 0);
        assert_ne!(addrs(&tcp), (CLIENT, SERVER));
    }

    #[test]
    fn unmatched_addresses_are_left_alone() {
        let map = flow(
            MapPolicy::Unique,
            vec![entry(Some("10.0.0.0/8"), "10.1.0.0/24", None)],
        );
        let mut rewriter = make_rewriter(map, 1, 1);

        let mut packet = tcp_packet(CLIENT, SERVER, 1, 2);
        rewriter.rewrite(&mut packet, 0);
        assert_eq!(addrs(&packet), (CLIENT, SERVER));
    }

    #[test]
    fn pool_wrap_reuses_addresses() {
        let map = flow(
            MapPolicy::Unique,
            vec![entry(Some("192.168.0.0/16"), "10.0.0.0/30", None)],
        );
        let mut rewriter = make_rewriter(map, 1, 1);

        // /30 has two usable hosts; the third key wraps around.
        let mut first = tcp_packet(CLIENT, SERVER, 1, 80);
        rewriter.rewrite(&mut first, 0);
        let mut second = tcp_packet(CLIENT, SERVER, 2, 80);
        rewriter.rewrite(&mut second, 0);
        let mut third = tcp_packet(CLIENT, SERVER, 3, 80);
        rewriter.rewrite(&mut third, 0);

        assert_ne!(addrs(&first).0, addrs(&second).0);
        assert_eq!(addrs(&third).0, addrs(&first).0);
    }

    #[test]
    fn v6_protocol_behind_an_extension_header_is_reported() {
        // Ethernet + IPv6 (next header: Hop-by-Hop) + Hop-by-Hop (next: TCP).
        let mut frame = vec![
            0x33, 0x33, 0x00, 0x00, 0x00, 0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x00,
        ];
        frame.extend_from_slice(&(8u16 + 20).to_be_bytes());
        frame.push(0); // hop-by-hop
        frame.push(0x40);
        frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        frame.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]); // next: TCP
        frame.extend_from_slice(&[0x30, 0x39, 0x00, 0x50]); // ports
        frame.extend_from_slice(&[0; 16]);

        let mut packet = Packet::new(frame.as_slice());
        packet.parse::<Eth>(Default::default());

        let info = PacketInfo::read(&packet).expect("packet info");
        assert_eq!(info.proto, 6, "the protocol behind the chain is TCP");
    }
}
