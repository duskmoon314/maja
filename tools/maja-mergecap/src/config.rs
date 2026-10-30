use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

use clap::{ArgAction, Args, Parser};
use glob::glob;
use log::{error, warn};
use serde::Deserialize;

// ============================== map entries ===============================

/// Shape of the target of one [`MapEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MapShape {
    /// Rewrite to the target address.
    Fixed,

    /// Hand out an address of the target pool.
    Pool,

    /// Copy the host bits of the source address into the target network.
    Mask,
}

/// How a pool hands out addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MapPolicy {
    /// Draw per packet, without any state (the pre-`flow_map` behaviour).
    Random,

    /// Draw once per key and remember it; different keys may collide.
    Sticky,

    /// Hand out a different address per key until the pool is exhausted.
    #[default]
    Unique,

    /// Derive the address from the key without any state; collisions are
    /// possible and the result does not depend on the packet order.
    Hash,
}

impl MapPolicy {
    /// Whether the policy keeps a table between packets.
    pub fn is_stateful(self) -> bool {
        matches!(self, MapPolicy::Sticky | MapPolicy::Unique)
    }
}

/// What identifies an allocated target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MapKey {
    /// Symmetric five-tuple: both directions of a connection share one target.
    #[default]
    Session,

    /// Endpoint address: one original address maps to one target.
    Address,
}

/// How the allocation of the parallel groups is shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MapSharing {
    /// One table per parallel group, so the groups become different clients.
    PerGroup,

    /// One table for every group.
    Shared,
}

/// Scope of the allocation table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllocScope {
    /// One allocation table per input file.
    #[default]
    File,

    /// One allocation table shared by every input file of the merge.
    Global,
}

/// Target of one [`MapEntry`]: a single Ip or a pool.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum Target {
    /// A single address.
    Ip(IpAddr),

    /// A pool of addresses.
    Net(ipnet::IpNet),
}

impl Target {
    /// Network covered by the target: a single Ip is a `/32` or `/128`.
    pub fn net(&self) -> ipnet::IpNet {
        match self {
            Target::Ip(ip) => ipnet::IpNet::from(*ip),
            Target::Net(net) => *net,
        }
    }
}

impl TryFrom<String> for Target {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Target::Ip(ip));
        }
        if let Ok(net) = value.parse::<ipnet::IpNet>() {
            return Ok(Target::Net(net));
        }
        Err(format!(
            "invalid map target {value:?}: expected an Ip or an IpNet"
        ))
    }
}

/// One `from -> to` entry of a map (`ip_map`, `src_ip_map`, `dst_ip_map` or
/// [`FlowMap`]).
///
/// The shape is inferred from `to` unless it is written out: a single address is
/// [`MapShape::Fixed`], a network is [`MapShape::Pool`]. `policy` only applies to
/// a pool, and only entries of a [`FlowMap`] may set it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapEntry {
    /// Address scope of this rule; `None` means any address (catch-all).
    #[serde(default)]
    pub from: Option<ipnet::IpNet>,

    /// Target address or pool.
    pub to: Target,

    /// Shape of the target; inferred from `to` when absent.
    #[serde(default)]
    pub shape: Option<MapShape>,

    /// Pool policy of this entry; defaults to the policy of the map.
    #[serde(default)]
    pub policy: Option<MapPolicy>,
}

impl MapEntry {
    /// Shape after applying the inference from `to`.
    pub fn shape(&self) -> MapShape {
        self.shape.unwrap_or(match self.to {
            Target::Ip(_) => MapShape::Fixed,
            Target::Net(_) => MapShape::Pool,
        })
    }

    /// Parse one map entry, shared by the direct maps and `flow_map`.
    ///
    /// ```text
    /// <from>=><to>   pool, policy of the map
    /// <from>-><to>   mask
    /// <net>          any -> pool
    /// <ip>           any -> fixed
    /// <from>:<to>    mask, the IPv4 only legacy spelling
    /// ```
    ///
    /// `->` and `=>` work for both families; `:` cannot separate two IPv6
    /// networks because the addresses themselves contain colons, so it is only
    /// accepted when both sides parse as IPv4 networks.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty map entry".to_string());
        }

        // The separators are tried longest and most specific first.
        if let Some((from, to)) = s.split_once("=>") {
            return Ok(MapEntry {
                from: Some(parse_net(from.trim(), s)?),
                to: Target::try_from(to.trim().to_string())?,
                shape: Some(MapShape::Pool),
                policy: None,
            });
        }
        if let Some((from, to)) = s.split_once("->") {
            return Ok(MapEntry {
                from: Some(parse_net(from.trim(), s)?),
                to: Target::try_from(to.trim().to_string())?,
                shape: Some(MapShape::Mask),
                policy: None,
            });
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(MapEntry {
                from: None,
                to: Target::Ip(ip),
                shape: Some(MapShape::Fixed),
                policy: None,
            });
        }
        if let Ok(net) = s.parse::<ipnet::IpNet>() {
            return Ok(MapEntry {
                from: None,
                to: Target::Net(net),
                shape: Some(MapShape::Pool),
                policy: None,
            });
        }
        if let Some((from, to)) = s.split_once(':') {
            return Ok(MapEntry {
                from: Some(parse_net(from.trim(), s)?),
                to: Target::try_from(to.trim().to_string())?,
                shape: Some(MapShape::Mask),
                policy: None,
            });
        }

        Err(format!(
            "invalid map entry {s:?}: expected `<ip>`, `<net>`, `<from>=><to>` or `<from>-><to>`"
        ))
    }
}

fn parse_net(value: &str, whole: &str) -> Result<ipnet::IpNet, String> {
    value
        .parse::<ipnet::IpNet>()
        .map_err(|e| format!("invalid FROM IpNet in {whole:?}: {e}"))
}

// ================================ flow map =================================

/// How the protocol of a packet is filtered for `flow_map`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ProtocolSpec {
    /// A single protocol name or `any`, or a comma separated list.
    One(String),

    /// A list of protocol names.
    List(Vec<String>),
}

impl ProtocolSpec {
    /// Default is `tcp` plus `udp`.
    pub fn default_tcp_udp() -> Self {
        ProtocolSpec::List(vec!["tcp".to_string(), "udp".to_string()])
    }

    /// Names in this spec.
    pub fn names(&self) -> Vec<String> {
        match self {
            ProtocolSpec::One(s) => s
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect(),
            ProtocolSpec::List(list) => list.iter().map(|p| p.trim().to_string()).collect(),
        }
    }
}

/// Address mapping that keeps one target per key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FlowMap {
    /// What an allocation is keyed by.
    pub key: MapKey,

    /// How a pool hands out addresses; entries may override it.
    pub policy: MapPolicy,

    /// Scope of the allocation table.
    pub alloc_scope: AllocScope,

    /// How the parallel groups share the allocation; defaults to `per-group`
    /// for a session key and to `shared` for an address key.
    pub sharing: Option<MapSharing>,

    /// `from -> to` rules.
    pub entries: Vec<MapEntry>,

    /// Addresses that are never rewritten.
    pub exclude: Vec<ipnet::IpNet>,

    /// Protocols that take part in the mapping.
    pub protocols: ProtocolSpec,

    /// Keep all fragments of one datagram on the same target.
    pub fragments: bool,
}

impl Default for FlowMap {
    fn default() -> Self {
        FlowMap {
            key: MapKey::default(),
            policy: MapPolicy::default(),
            alloc_scope: AllocScope::default(),
            sharing: None,
            entries: Vec::new(),
            exclude: default_exclude(),
            protocols: ProtocolSpec::default_tcp_udp(),
            fragments: true,
        }
    }
}

impl FlowMap {
    /// Sharing of the allocation, with the default for the key applied.
    pub fn sharing(&self) -> MapSharing {
        self.sharing.unwrap_or(match self.key {
            MapKey::Session => MapSharing::PerGroup,
            MapKey::Address => MapSharing::Shared,
        })
    }
}

fn default_exclude() -> Vec<ipnet::IpNet> {
    vec![
        // IPv4 multicast and limited broadcast.
        "224.0.0.0/4".parse().expect("valid multicast net"),
        "255.255.255.255/32"
            .parse()
            .expect("valid limited broadcast"),
        // IPv6 multicast.
        "ff00::/8".parse().expect("valid multicast net"),
    ]
}

// =============================== input file ================================

/// Config for one input file.
///
/// Every field is optional so that the CLI and a config file can be merged
/// field by field (see [`Config::bitor`]); defaults are applied by the
/// accessors below.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InputFile<P: AsRef<Path>> {
    /// The path / glob pattern to the input file.
    pub path: P,

    /// The start time offset of each group of the input file in seconds.
    ///
    /// If erase_timestamp == true, the start time should be positive to arrange
    /// the packets in the output file.
    ///
    /// If erase_timestamp == false, the start time can be negative to shift the
    /// packets to its past.
    ///
    /// Defaults to `[0]`.
    pub start_time: Option<Vec<i32>>,

    /// The number of times to repeat the input file in one group. Defaults to 1.
    pub repeat: Option<u32>,

    /// The interval in nanoseconds between two repeats inside one group.
    /// Defaults to one second.
    pub repeat_interval: Option<u64>,

    /// The number of parallel groups to create from the input file. Defaults
    /// to 1.
    pub parallel: Option<u32>,

    /// Jitter in nanoseconds spread over the parallel groups. Each group gets
    /// one constant offset; group 0 keeps the original timeline. Defaults to 0.
    pub parallel_jitter: Option<u64>,

    /// Direct map applied to both source and destination.
    ///
    /// Entries with a `from` network act as rules (longest prefix first) and
    /// entries without one are pooled together per direction.
    pub ip_map: Option<Vec<MapEntry>>,

    /// Direct map applied to the source only.
    pub src_ip_map: Option<Vec<MapEntry>>,

    /// Direct map applied to the destination only.
    pub dst_ip_map: Option<Vec<MapEntry>>,

    /// Address mapping that keeps one target per key. Mutually exclusive with
    /// the direct maps.
    pub flow_map: Option<FlowMap>,
}

impl<P: AsRef<Path> + Default> Default for InputFile<P> {
    fn default() -> Self {
        InputFile {
            path: Default::default(),
            start_time: None,
            repeat: None,
            repeat_interval: None,
            parallel: None,
            parallel_jitter: None,
            ip_map: None,
            src_ip_map: None,
            dst_ip_map: None,
            flow_map: None,
        }
    }
}

impl<P: AsRef<Path>> InputFile<P> {
    /// Default start time when the field is absent.
    pub const DEFAULT_START_TIME: &'static [i32] = &[0];

    /// Default repeat interval in nanoseconds.
    pub const DEFAULT_REPEAT_INTERVAL_NS: u64 = 1_000_000_000;

    /// Start time offsets, with the default applied.
    pub fn start_time(&self) -> &[i32] {
        self.start_time
            .as_deref()
            .unwrap_or(Self::DEFAULT_START_TIME)
    }

    /// Repeat count, with the default applied.
    pub fn repeat(&self) -> u32 {
        self.repeat.unwrap_or(1)
    }

    /// Repeat interval in nanoseconds, with the default applied.
    pub fn repeat_interval_ns(&self) -> i64 {
        self.repeat_interval
            .unwrap_or(Self::DEFAULT_REPEAT_INTERVAL_NS) as i64
    }

    /// Parallel group count, with the default applied.
    pub fn parallel(&self) -> u32 {
        self.parallel.unwrap_or(1)
    }

    /// Parallel jitter in nanoseconds, with the default applied.
    pub fn parallel_jitter_ns(&self) -> u64 {
        self.parallel_jitter.unwrap_or(0)
    }

    /// Direct map for both directions.
    pub fn ip_map(&self) -> &[MapEntry] {
        self.ip_map.as_deref().unwrap_or(&[])
    }

    /// Direct map for the source address.
    pub fn src_ip_map(&self) -> &[MapEntry] {
        self.src_ip_map.as_deref().unwrap_or(&[])
    }

    /// Direct map for the destination address.
    pub fn dst_ip_map(&self) -> &[MapEntry] {
        self.dst_ip_map.as_deref().unwrap_or(&[])
    }

    /// Copy this configuration onto another path type.
    pub fn map_path<Q: AsRef<Path>>(&self, path: Q) -> InputFile<Q> {
        InputFile {
            path,
            start_time: self.start_time.clone(),
            repeat: self.repeat,
            repeat_interval: self.repeat_interval,
            parallel: self.parallel,
            parallel_jitter: self.parallel_jitter,
            ip_map: self.ip_map.clone(),
            src_ip_map: self.src_ip_map.clone(),
            dst_ip_map: self.dst_ip_map.clone(),
            flow_map: self.flow_map.clone(),
        }
    }

    /// Validate this configuration after CLI / config file merging.
    pub fn validate(&self) -> anyhow::Result<()> {
        let path = self.path.as_ref().display().to_string();

        if self.start_time.as_ref().is_some_and(Vec::is_empty) {
            anyhow::bail!("{path}: `start_time` must not be empty");
        }
        if self.repeat == Some(0) {
            anyhow::bail!("{path}: `repeat` must be at least 1");
        }
        if self.parallel == Some(0) {
            anyhow::bail!("{path}: `parallel` must be at least 1");
        }
        if self.repeat_interval.is_some_and(|v| v > i64::MAX as u64) {
            anyhow::bail!("{path}: `repeat_interval` does not fit in nanoseconds");
        }
        if self.parallel_jitter.is_some_and(|v| v > i64::MAX as u64) {
            anyhow::bail!("{path}: `parallel_jitter` does not fit in nanoseconds");
        }

        if self.flow_map.is_some()
            && (!self.ip_map().is_empty()
                || !self.src_ip_map().is_empty()
                || !self.dst_ip_map().is_empty())
        {
            anyhow::bail!(
                "{path}: `flow_map` cannot be combined with `ip_map`/`src_ip_map`/`dst_ip_map`"
            );
        }

        for entry in self
            .src_ip_map()
            .iter()
            .chain(self.ip_map().iter())
            .chain(self.dst_ip_map().iter())
        {
            check_entry(entry, EntryContext::Direct, &path)?;
        }

        if let Some(flow) = &self.flow_map {
            check_flow_map(flow, &path)?;
        }

        Ok(())
    }
}

impl InputFile<String> {
    /// Parse the cli arguments into a [`InputFile`].
    ///
    /// ## Format
    ///
    /// ```text
    /// path[#s<start_time,..>][#r<repeat>][#p<parallel>][#j<ns>]
    ///     [#ip<ip_map,..>][#src<ip_map,..>][#dst<ip_map,..>][#flow<flow_entry,..>]
    /// ```
    ///
    /// Complex options (`repeat_interval`, the `flow_map` machinery)
    /// are only available in a config file.
    fn parse(s: &str) -> Result<InputFile<String>, clap::Error> {
        fn invalid(message: String) -> clap::Error {
            clap::Error::raw(clap::error::ErrorKind::InvalidValue, message)
        }

        /// Longest key first so that `src` wins over `s`.
        const KEYS: [&str; 8] = ["flow", "src", "dst", "ip", "s", "r", "p", "j"];

        let mut input_file = InputFile::<String>::default();

        let mut parts = s.split('#');
        input_file.path = parts
            .next()
            .expect("Input file path is required")
            .to_string();

        for part in parts.filter(|part| !part.is_empty()) {
            let Some(key) = KEYS.iter().find(|key| part.starts_with(**key)) else {
                return Err(invalid(format!("Invalid input file option: {part}")));
            };
            let value = &part[key.len()..];

            match *key {
                "src" => {
                    input_file.src_ip_map = Some(parse_entries(value).map_err(invalid)?);
                }
                "dst" => {
                    input_file.dst_ip_map = Some(parse_entries(value).map_err(invalid)?);
                }
                "ip" => {
                    input_file.ip_map = Some(parse_entries(value).map_err(invalid)?);
                }
                "flow" => {
                    input_file.flow_map = Some(FlowMap {
                        entries: parse_entries(value).map_err(invalid)?,
                        ..Default::default()
                    });
                }
                "s" => {
                    input_file.start_time = Some(
                        value
                            .split(',')
                            .map(|v| {
                                v.trim()
                                    .parse::<i32>()
                                    .map_err(|e| invalid(format!("Invalid start time {v:?}: {e}")))
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                }
                "r" => {
                    input_file.repeat =
                        Some(value.trim().parse::<u32>().map_err(|e| {
                            invalid(format!("Invalid repeat value {value:?}: {e}"))
                        })?);
                }
                "p" => {
                    input_file.parallel =
                        Some(value.trim().parse::<u32>().map_err(|e| {
                            invalid(format!("Invalid parallel value {value:?}: {e}"))
                        })?);
                }
                "j" => {
                    input_file.parallel_jitter =
                        Some(value.trim().parse::<u64>().map_err(|e| {
                            invalid(format!("Invalid parallel jitter {value:?}: {e}"))
                        })?);
                }
                _ => unreachable!("all keys are handled"),
            }
        }

        Ok(input_file)
    }

    /// Expand the glob pattern into concrete input files.
    pub fn expand_glob(self) -> anyhow::Result<Vec<InputFile<PathBuf>>> {
        let mut expanded_files = Vec::new();

        for entry in glob(&self.path)? {
            match entry {
                Ok(path) => expanded_files.push(self.map_path(path)),
                Err(e) => error!("Error reading glob entry: {e}"),
            }
        }

        Ok(expanded_files)
    }
}

impl<P: AsRef<Path>> std::ops::BitOr for InputFile<P> {
    type Output = InputFile<P>;

    /// Field wise merge: a value given on the command line wins over the value
    /// of the config file entry with the same path.
    fn bitor(self, rhs: Self) -> Self::Output {
        InputFile {
            path: self.path,
            start_time: self.start_time.or(rhs.start_time),
            repeat: self.repeat.or(rhs.repeat),
            repeat_interval: self.repeat_interval.or(rhs.repeat_interval),
            parallel: self.parallel.or(rhs.parallel),
            parallel_jitter: self.parallel_jitter.or(rhs.parallel_jitter),
            ip_map: self.ip_map.or(rhs.ip_map),
            src_ip_map: self.src_ip_map.or(rhs.src_ip_map),
            dst_ip_map: self.dst_ip_map.or(rhs.dst_ip_map),
            flow_map: self.flow_map.or(rhs.flow_map),
        }
    }
}

// ====================== entry parsing / validation =======================

/// Parse a comma separated list of map entries (used by `#ip`/`#src`/`#dst`
/// and `#flow`).
fn parse_entries(value: &str) -> Result<Vec<MapEntry>, String> {
    value
        .split(',')
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(MapEntry::parse)
        .collect()
}

/// Where an entry is used, which decides what is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryContext {
    /// `ip_map` / `src_ip_map` / `dst_ip_map`: stateless and per packet.
    Direct,

    /// Entries of a `flow_map`.
    Flow,
}

/// Whether two networks belong to the same address family.
fn same_family(a: &ipnet::IpNet, b: &ipnet::IpNet) -> bool {
    matches!(
        (a, b),
        (ipnet::IpNet::V4(_), ipnet::IpNet::V4(_)) | (ipnet::IpNet::V6(_), ipnet::IpNet::V6(_))
    )
}

/// Validate one map entry of either kind.
fn check_entry(entry: &MapEntry, context: EntryContext, path: &str) -> anyhow::Result<()> {
    // IPv4 and IPv6 never mix: a `from` network and a target of different
    // families would have to translate between address families.
    let to = entry.to.net();
    if let Some(from) = entry.from
        && !same_family(&from, &to)
    {
        anyhow::bail!(
            "{path}: {from} and {to} are of different address families, \
             cross family mapping is not supported"
        );
    }

    match entry.shape() {
        MapShape::Fixed => {
            if !matches!(entry.to, Target::Ip(_)) {
                anyhow::bail!(
                    "{path}: `fixed` needs a single Ip target, got {:?}",
                    entry.to
                );
            }
        }
        MapShape::Pool => {
            if !matches!(entry.to, Target::Net(_)) {
                anyhow::bail!("{path}: `pool` needs a network target, got {:?}", entry.to);
            }
        }
        MapShape::Mask => {
            let Some(from) = entry.from else {
                anyhow::bail!(
                    "{path}: `mask` needs a `from` network and a network target, got {entry:?}"
                );
            };
            if !matches!(entry.to, Target::Net(_)) {
                anyhow::bail!(
                    "{path}: `mask` needs a `from` network and a network target, got {entry:?}"
                );
            }
            if to.prefix_len() < from.prefix_len() {
                warn!(
                    "{path}: {from}->{to} maps host bits into a smaller network; \
                     different source addresses may collide (use `=>` for unique allocation)"
                );
            }
        }
    }

    // A policy picks an address out of a pool, so it only applies to one.
    if entry.policy.is_some() {
        if context == EntryContext::Direct {
            anyhow::bail!(
                "{path}: `policy` only applies to `flow_map`; \
                 `ip_map`/`src_ip_map`/`dst_ip_map` are stateless"
            );
        }
        if entry.shape() != MapShape::Pool {
            anyhow::bail!(
                "{path}: `policy` only applies to a pool, but this entry is {:?}",
                entry.shape()
            );
        }
    }

    Ok(())
}

fn check_flow_map(flow: &FlowMap, path: &str) -> anyhow::Result<()> {
    if flow.entries.is_empty() {
        anyhow::bail!("{path}: `flow_map` needs at least one entry");
    }

    let mut catch_all = [0usize; 2];
    for entry in flow.entries.iter().filter(|entry| entry.from.is_none()) {
        let family = match entry.to.net() {
            ipnet::IpNet::V4(_) => 0,
            ipnet::IpNet::V6(_) => 1,
        };
        catch_all[family] += 1;
    }
    for (family, count) in ["IPv4", "IPv6"].into_iter().zip(catch_all) {
        if count > 1 {
            anyhow::bail!(
                "{path}: `flow_map` has {count} {family} catch-all entries; \
                 they cannot be told apart, please give each entry a `from` network"
            );
        }
    }

    for entry in &flow.entries {
        check_entry(entry, EntryContext::Flow, path)?;
    }

    // What the entries actually do, after their own overrides.
    let mut keyed = 0usize;
    let mut stateful = 0usize;
    for entry in &flow.entries {
        if entry.shape() != MapShape::Pool {
            continue;
        }
        let policy = entry.policy.unwrap_or(flow.policy);
        if policy != MapPolicy::Random {
            keyed += 1;
        }
        if policy.is_stateful() {
            stateful += 1;
        }
    }

    if flow.key == MapKey::Address && keyed == 0 {
        anyhow::bail!(
            "{path}: `key` cannot matter here: every pool entry draws per packet; \
             give one of them `sticky`, `unique` or `hash`"
        );
    }
    if flow.alloc_scope == AllocScope::Global && stateful == 0 {
        anyhow::bail!("{path}: `alloc_scope` cannot matter here: no entry keeps a table");
    }
    if flow.sharing.is_some() && stateful == 0 {
        anyhow::bail!("{path}: `sharing` cannot matter here: no entry keeps a table");
    }

    Ok(())
}

// ================================ merge args ===============================

#[derive(Debug, Clone, Default, Args, Deserialize)]
pub struct MergeArgs {
    /// Whether to erase the timestamps of the packets in the output file
    #[arg(short, long, action = ArgAction::SetTrue)]
    pub erase_timestamp: Option<bool>,

    /// The snap len of the output file
    #[arg(long)]
    pub snap_len: Option<u32>,

    /// The precision of the timestamp
    #[arg(long, action = ArgAction::SetTrue)]
    pub nanosecond: Option<bool>,

    /// Whether to keep sub-second precision when erasing timestamps
    ///
    /// If erase_timestamp and this option are both true, the first packet's
    /// timestamps will be set to start_time + sub-second precision of the
    /// original timestamp.
    ///
    /// If erase_timestamp is true and this option is false, the first packet's
    /// timestamps will be set to start_time.
    ///
    /// If erase_timestamp is false, this option has no effect.
    #[arg(long, action = ArgAction::SetTrue)]
    pub keep_subsecond: Option<bool>,

    /// The number of input files to merge in a single pass.
    ///
    /// This is useful when merging a large number of input files
    #[arg(long)]
    pub batch_size: Option<usize>,

    /// Seed for the random address mapping.
    ///
    /// The seed of input file `i` is derived from this value. Without a seed
    /// the random number generator is seeded from the operating system.
    #[arg(long)]
    pub seed: Option<u64>,

    /// Do not recompute the IPv4 header and TCP/UDP checksums after rewriting
    /// addresses.
    #[arg(long = "no-fix-checksum", action = ArgAction::SetFalse)]
    pub fix_checksum: Option<bool>,
}

impl MergeArgs {
    /// Whether checksums should be recomputed after rewriting addresses.
    pub fn fix_checksum(&self) -> bool {
        self.fix_checksum.unwrap_or(true)
    }
}

impl std::ops::BitOr for MergeArgs {
    type Output = MergeArgs;

    fn bitor(self, rhs: Self) -> Self::Output {
        // `or` gives "explicitly given wins" because a missing flag is `None`
        // for both `SetTrue` and `SetFalse` actions.
        MergeArgs {
            erase_timestamp: self.erase_timestamp.or(rhs.erase_timestamp),
            snap_len: self.snap_len.or(rhs.snap_len),
            nanosecond: self.nanosecond.or(rhs.nanosecond),
            keep_subsecond: self.keep_subsecond.or(rhs.keep_subsecond),
            batch_size: self.batch_size.or(rhs.batch_size),
            seed: self.seed.or(rhs.seed),
            fix_checksum: self.fix_checksum.or(rhs.fix_checksum),
        }
    }
}

// ================================== config =================================

/// Merge the command line input files into the config file ones by path.
fn merge_input_files(
    cli: Vec<InputFile<String>>,
    config: Vec<InputFile<String>>,
) -> Vec<InputFile<String>> {
    if cli.is_empty() {
        return config;
    }

    let mut merged = config;
    for cli_file in cli {
        match merged.iter().position(|file| file.path == cli_file.path) {
            Some(pos) => {
                let config_file = merged.remove(pos);
                merged.insert(pos, cli_file | config_file);
            }
            None => merged.push(cli_file),
        }
    }

    merged
}

#[derive(Debug, Clone, Args, Deserialize)]
pub struct Config {
    /// The input files to merge
    ///
    /// Format: `path[#s<start_time,..>][#r<repeat>][#p<parallel>][#j<ns>][#ip<ip_map,..>][#src<ip_map,..>][#dst<ip_map,..>][#flow<flow_entry,..>]`
    #[arg(value_parser = InputFile::parse)]
    pub input_files: Vec<InputFile<String>>,

    /// The output file to write the merged packets to
    #[arg(short, long)]
    pub output_file: Option<PathBuf>,

    #[command(flatten)]
    #[serde(flatten)]
    pub merge_args: MergeArgs,
}

impl std::ops::BitOr for Config {
    type Output = Config;

    fn bitor(self, rhs: Self) -> Self::Output {
        Config {
            input_files: merge_input_files(self.input_files, rhs.input_files),
            output_file: self.output_file.or(rhs.output_file),
            merge_args: self.merge_args | rhs.merge_args,
        }
    }
}

/// A config file: one object, or an array of objects merged in order.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ConfigFile {
    Single(Config),
    Multiple(Vec<Config>),
}

#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about)]
pub struct Cli {
    /// The config file to use
    #[arg(short, long, value_name = "FILE")]
    pub config_file: Option<PathBuf>,

    #[command(flatten)]
    pub config: Config,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(from: &str, to: &str) -> MapEntry {
        MapEntry {
            from: Some(from.parse().unwrap()),
            to: Target::try_from(to.to_string()).unwrap(),
            shape: None,
            policy: None,
        }
    }

    fn flow(entries: Vec<MapEntry>) -> FlowMap {
        FlowMap {
            entries,
            ..Default::default()
        }
    }

    fn file(flow: Option<FlowMap>) -> InputFile<String> {
        InputFile {
            path: "a.pcap".to_string(),
            flow_map: flow,
            ..Default::default()
        }
    }

    #[test]
    fn cli_flags_do_not_mask_json_flags() {
        let cli = MergeArgs {
            erase_timestamp: Some(false),
            nanosecond: Some(false),
            keep_subsecond: Some(false),
            seed: Some(7),
            fix_checksum: Some(false),
            snap_len: Some(96),
            batch_size: Some(128),
        };
        // The config file says the opposite of the command line.
        let json: MergeArgs = serde_json::from_str(
            r#"{ "erase_timestamp": true, "nanosecond": true, "keep_subsecond": true,
                 "seed": 9, "fix_checksum": true, "snap_len": 128, "batch_size": 8 }"#,
        )
        .unwrap();

        let merged = cli | json;
        // The command line wins field by field.
        assert_eq!(merged.erase_timestamp, Some(false));
        assert_eq!(merged.nanosecond, Some(false));
        assert_eq!(merged.keep_subsecond, Some(false));
        assert_eq!(merged.seed, Some(7));
        assert_eq!(merged.fix_checksum, Some(false));
        assert_eq!(merged.snap_len, Some(96));
        assert_eq!(merged.batch_size, Some(128));
    }

    #[test]
    fn parse_cli_suffixes() {
        let file = InputFile::parse("a.pcap#s0,10#r2#p3#j1000").unwrap();

        assert_eq!(file.path, "a.pcap");
        assert_eq!(file.start_time, Some(vec![0, 10]));
        assert_eq!(file.repeat, Some(2));
        assert_eq!(file.parallel, Some(3));
        assert_eq!(file.parallel_jitter, Some(1000));
    }

    #[test]
    fn entry_shapes_are_inferred_from_the_target() {
        let map = parse_entries(
            "10.0.0.5,10.0.0.0/24,192.168.0.0/16=>10.1.0.0/24,10.2.0.0/16->10.3.0.0/16",
        )
        .unwrap();

        assert_eq!(map.len(), 4);
        assert_eq!(map[0].shape(), MapShape::Fixed);
        assert_eq!(map[0].from, None);
        assert_eq!(map[1].shape(), MapShape::Pool);
        assert_eq!(map[1].from, None);
        assert_eq!(map[2].shape(), MapShape::Pool);
        assert_eq!(map[2].policy, None);
        assert_eq!(map[3].shape(), MapShape::Mask);
        assert_eq!(map[3].from, Some("10.2.0.0/16".parse().unwrap()));
    }

    #[test]
    fn the_colon_separator_is_ipv4_only() {
        let mask = MapEntry::parse("192.168.0.0/16:10.1.0.0/16").unwrap();
        assert_eq!(mask.shape(), MapShape::Mask);

        assert!(MapEntry::parse("2001:db8::/32=>2001:db8:1::/48").is_ok());
        assert!(MapEntry::parse("2001:db8::/32:2001:db8:1::/48").is_err());
        assert!(MapEntry::parse("nonsense").is_err());
    }

    #[test]
    fn a_flow_entry_takes_the_policy_from_the_map() {
        let file = InputFile::parse("a.pcap#flow192.168.0.0/16=>10.0.0.0/24,10.0.0.0/8").unwrap();
        let flow = file.flow_map.unwrap();

        assert_eq!(flow.entries.len(), 2);
        assert_eq!(flow.entries[0].policy, None);
        assert_eq!(flow.entries[1].policy, None);
        assert_eq!(flow.policy, MapPolicy::Unique);
        assert!(flow.fragments);
    }

    #[test]
    fn validation_rejects_a_policy_in_a_direct_map() {
        let mut pool = entry("10.0.0.0/8", "10.9.0.0/16");
        pool.policy = Some(MapPolicy::Unique);

        let file = InputFile {
            path: "a.pcap".to_string(),
            dst_ip_map: Some(vec![pool]),
            ..Default::default()
        };
        let err = file.validate().unwrap_err();
        assert!(
            err.to_string().contains("only applies to `flow_map`"),
            "{err}"
        );
    }

    #[test]
    fn validation_rejects_cross_family_entries() {
        let entry = entry("10.0.0.0/8", "2001:db8::/48");
        let err = file(Some(flow(vec![entry]))).validate().unwrap_err();
        assert!(
            err.to_string().contains("different address families"),
            "{err}"
        );
    }

    #[test]
    fn validation_rejects_policy_combinations_that_do_nothing() {
        let entries = vec![entry("10.0.0.0/8", "10.1.0.0/24")];

        let random_by_address = FlowMap {
            policy: MapPolicy::Random,
            key: MapKey::Address,
            ..flow(entries.clone())
        };
        assert!(file(Some(random_by_address)).validate().is_err());

        let hash_global = FlowMap {
            policy: MapPolicy::Hash,
            alloc_scope: AllocScope::Global,
            ..flow(entries.clone())
        };
        assert!(file(Some(hash_global)).validate().is_err());

        let random_shared = FlowMap {
            policy: MapPolicy::Random,
            sharing: Some(MapSharing::Shared),
            ..flow(entries.clone())
        };
        assert!(file(Some(random_shared)).validate().is_err());

        let sticky_global = FlowMap {
            policy: MapPolicy::Sticky,
            alloc_scope: AllocScope::Global,
            ..flow(entries)
        };
        assert!(file(Some(sticky_global)).validate().is_ok());
    }

    #[test]
    fn validation_rejects_empty_and_degenerate_loops() {
        let empty_start = InputFile {
            path: "a.pcap".to_string(),
            start_time: Some(Vec::new()),
            ..Default::default()
        };
        assert!(empty_start.validate().is_err());

        let no_repeat = InputFile {
            path: "a.pcap".to_string(),
            repeat: Some(0),
            ..Default::default()
        };
        assert!(no_repeat.validate().is_err());

        let no_parallel = InputFile {
            path: "a.pcap".to_string(),
            parallel: Some(0),
            ..Default::default()
        };
        assert!(no_parallel.validate().is_err());
    }

    #[test]
    fn json_entries_infer_the_shape_and_reject_unknown_fields() {
        let flow: FlowMap = serde_json::from_str(
            r#"{
                "entries": [
                    { "from": "192.168.0.0/16", "to": "10.0.0.0/24" },
                    { "from": "10.1.0.0/16", "to": "10.2.0.0/24", "policy": "sticky" },
                    { "to": "10.9.9.9" }
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(flow.policy, MapPolicy::Unique);
        assert_eq!(flow.entries[0].shape(), MapShape::Pool);
        assert_eq!(flow.entries[1].policy, Some(MapPolicy::Sticky));
        assert_eq!(flow.entries[2].shape(), MapShape::Fixed);

        assert!(
            serde_json::from_str::<FlowMap>(r#"{ "entries": [], "mode": "session" }"#).is_err()
        );
        assert!(
            serde_json::from_str::<MapEntry>(r#"{ "to": "10.0.0.0/24", "mode": "unique" }"#)
                .is_err()
        );
    }

    #[test]
    fn input_files_merge_by_path() {
        let config = vec![InputFile {
            path: "a.pcap".to_string(),
            parallel: Some(2),
            repeat: Some(3),
            ..Default::default()
        }];
        let cli = vec![InputFile {
            path: "a.pcap".to_string(),
            parallel: Some(1),
            ..Default::default()
        }];

        let merged = merge_input_files(cli, config);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].parallel, Some(1), "the command line wins");
        assert_eq!(merged[0].repeat, Some(3), "the config file keeps the rest");
    }
}
