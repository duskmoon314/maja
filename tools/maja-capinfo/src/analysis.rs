use std::collections::{HashMap, HashSet};

use itertools::Itertools;
use maja::packet::flow::FlowIdSymmetric;

use crate::metadata::PacketMetadata;

/// Packet and byte totals updated one packet at a time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunningTrafficStats {
    pub count: u64,
    pub bytes: u64,
}

impl RunningTrafficStats {
    fn update(&mut self, bytes: u32) {
        self.count += 1;
        self.bytes += bytes as u64;
    }
}

/// Length statistics updated without retaining individual packet lengths.
///
/// ## Algorithm
///
/// - Mean: `\bar{x_n} = \bar{x_{n-1}} + (x_n - \bar{x_{n-1}}) / n`
/// - Variance:
///   - `M_{2,n} = M_{2,n-1} + (x_n - \bar{x_{n-1}}) * (x_n - \bar{x_n})`
///   - `Var_n = M_{2,n} / (n - 1)`
///
/// _Ref: https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance_
#[derive(Debug, Clone)]
pub struct RunningLengthStats {
    count: u64,
    mean: f64,
    m_2: f64,
    min: u32,
    max: u32,
}

impl Default for RunningLengthStats {
    fn default() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m_2: 0.0,
            min: u32::MAX,
            max: u32::MIN,
        }
    }
}

impl RunningLengthStats {
    fn update(&mut self, value: u32) {
        self.count += 1;

        let delta = value as f64 - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value as f64 - self.mean;
        self.m_2 += delta * delta2;

        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    pub fn variance(&self, ddof: u64) -> f64 {
        if self.count <= ddof {
            0.0
        } else {
            self.m_2 / (self.count - ddof) as f64
        }
    }

    pub fn std_dev(&self, ddof: u64) -> f64 {
        self.variance(ddof).sqrt()
    }

    pub fn min(&self) -> u32 {
        if self.count == 0 { 0 } else { self.min }
    }

    pub fn max(&self) -> u32 {
        if self.count == 0 { 0 } else { self.max }
    }
}

/// Exact statistics accumulated while packets are read from one capture.
///
/// Per-key maps provide both unique counts and top-traffic candidates. Their
/// memory use is proportional to the number of distinct keys, not packet count.
#[derive(Debug)]
pub struct Stats {
    pub total_packets: u64,
    pub total_l2_bytes: u64,
    pub total_l3_bytes: u64,
    pub empty_packets: u64,
    pub errors: u64,
    pub first_timestamp: Option<i64>,
    pub last_timestamp: Option<i64>,
    pub is_ordered: bool,
    pub lengths: RunningLengthStats,
    pub tcp_count: u64,
    pub udp_count: u64,
    pub flow_set: HashSet<FlowIdSymmetric>,
    src_ip_traffic: HashMap<u32, RunningTrafficStats>,
    dst_ip_traffic: HashMap<u32, RunningTrafficStats>,
    src_port_traffic: HashMap<u16, RunningTrafficStats>,
    dst_port_traffic: HashMap<u16, RunningTrafficStats>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            total_packets: 0,
            total_l2_bytes: 0,
            total_l3_bytes: 0,
            empty_packets: 0,
            errors: 0,
            first_timestamp: None,
            last_timestamp: None,
            is_ordered: true,
            lengths: RunningLengthStats::default(),
            tcp_count: 0,
            udp_count: 0,
            flow_set: HashSet::new(),
            src_ip_traffic: HashMap::new(),
            dst_ip_traffic: HashMap::new(),
            src_port_traffic: HashMap::new(),
            dst_port_traffic: HashMap::new(),
        }
    }
}

impl Stats {
    pub fn update_with_packet(&mut self, timestamp: i64, length: u32) {
        self.total_packets += 1;
        self.total_l2_bytes += length as u64;

        if self.last_timestamp.is_some_and(|last| timestamp < last) {
            self.is_ordered = false;
        }

        self.first_timestamp = self
            .first_timestamp
            .map_or(timestamp, |first| first.min(timestamp))
            .into();
        self.last_timestamp = self
            .last_timestamp
            .map_or(timestamp, |last| last.max(timestamp))
            .into();
    }

    pub fn update_with_metadata(&mut self, metadata: &PacketMetadata) {
        let src_ip = metadata.src_ip4.unwrap_or(0);
        let dst_ip = metadata.dst_ip4.unwrap_or(0);
        let src_port = metadata.src_port.unwrap_or(0);
        let dst_port = metadata.dst_port.unwrap_or(0);

        self.lengths.update(metadata.length);
        self.src_ip_traffic
            .entry(src_ip)
            .or_default()
            .update(metadata.length);
        self.dst_ip_traffic
            .entry(dst_ip)
            .or_default()
            .update(metadata.length);
        self.src_port_traffic
            .entry(src_port)
            .or_default()
            .update(metadata.length);
        self.dst_port_traffic
            .entry(dst_port)
            .or_default()
            .update(metadata.length);

        match metadata.ip_proto {
            Some(6) => self.tcp_count += 1,
            Some(17) => self.udp_count += 1,
            _ => {}
        }
    }

    pub fn unique_src_ips(&self) -> usize {
        self.src_ip_traffic.len()
    }

    pub fn unique_dst_ips(&self) -> usize {
        self.dst_ip_traffic.len()
    }

    pub fn unique_src_ports(&self) -> usize {
        self.src_port_traffic.len()
    }

    pub fn unique_dst_ports(&self) -> usize {
        self.dst_port_traffic.len()
    }

    pub fn top_src_ips(&self, limit: usize) -> Vec<(u32, RunningTrafficStats)> {
        top_items(&self.src_ip_traffic, limit)
    }

    pub fn top_dst_ips(&self, limit: usize) -> Vec<(u32, RunningTrafficStats)> {
        top_items(&self.dst_ip_traffic, limit)
    }

    pub fn top_src_ports(&self, limit: usize) -> Vec<(u16, RunningTrafficStats)> {
        top_items(&self.src_port_traffic, limit)
    }

    pub fn top_dst_ports(&self, limit: usize) -> Vec<(u16, RunningTrafficStats)> {
        top_items(&self.dst_port_traffic, limit)
    }
}

fn top_items<K>(
    traffic: &HashMap<K, RunningTrafficStats>,
    limit: usize,
) -> Vec<(K, RunningTrafficStats)>
where
    K: Copy + Ord,
{
    traffic
        .iter()
        .map(|(&key, &stats)| (key, stats))
        .k_largest_by(limit, |(left_key, left), (right_key, right)| {
            left.count
                .cmp(&right.count)
                .then(left.bytes.cmp(&right.bytes))
                .then(right_key.cmp(left_key))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_stats_match_sample_statistics() {
        let mut stats = RunningLengthStats::default();
        for value in [2, 4, 4, 4, 5, 5, 7, 9] {
            stats.update(value);
        }

        assert_eq!(stats.mean(), 5.0);
        assert!((stats.std_dev(1) - 2.138_089_935).abs() < 1e-9);
        assert_eq!(stats.min(), 2);
        assert_eq!(stats.max(), 9);
    }

    #[test]
    fn empty_running_stats_are_zero() {
        let stats = RunningLengthStats::default();

        assert_eq!(stats.mean(), 0.0);
        assert_eq!(stats.variance(0), 0.0);
        assert_eq!(stats.std_dev(1), 0.0);
        assert_eq!(stats.min(), 0);
        assert_eq!(stats.max(), 0);
    }

    #[test]
    fn stats_are_ordered_until_a_timestamp_moves_backwards() {
        let mut stats = Stats::default();
        assert!(stats.is_ordered);

        stats.update_with_packet(2, 64);
        stats.update_with_packet(1, 64);
        assert!(!stats.is_ordered);
    }

    #[test]
    fn top_items_have_deterministic_ties() {
        let counts = HashMap::from([
            (
                3_u16,
                RunningTrafficStats {
                    count: 2,
                    bytes: 20,
                },
            ),
            (
                1_u16,
                RunningTrafficStats {
                    count: 2,
                    bytes: 30,
                },
            ),
            (
                2_u16,
                RunningTrafficStats {
                    count: 3,
                    bytes: 10,
                },
            ),
            (
                4_u16,
                RunningTrafficStats {
                    count: 2,
                    bytes: 30,
                },
            ),
        ]);

        assert_eq!(
            top_items(&counts, 2),
            vec![(2, counts[&2]), (1, counts[&1])]
        );
    }
}
