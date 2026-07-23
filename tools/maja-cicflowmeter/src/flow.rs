//! CICFlowMeter-compatible bidirectional flow feature extraction.
//!
//! The extractor intentionally keeps the feature engine independent from the
//! command-line tool. Capture readers provide [`PacketRecord`] values, and
//! this module turns parsed TCP/UDP packets into finite, CSV-ready rows.

use std::{collections::HashMap, net::IpAddr};

use maja::{
    capture::packet::PacketRecord,
    packet::{
        Packet,
        error::ParseError,
        layer::{
            ProtocolExt,
            ip::{v4::Ipv4, v6::Ipv6},
            tcp::{Tcp, TcpFlags},
            udp::Udp,
        },
    },
};

/// The canonical CICFlowMeter CSV header.
pub const CICFLOWMETER_HEADER: [&str; 85] = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Min",
    "Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWR Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Fwd Segment Size Avg",
    "Bwd Segment Size Avg",
    "Fwd Header Length.1",
    "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg",
    "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg",
    "Bwd Packet/Bulk Avg",
    "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "FWD Init Win Bytes",
    "Bwd Init Win Bytes",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "Label",
];

/// A parsed TCP or UDP packet used by the flow engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowPacket {
    /// Capture timestamp in nanoseconds since the Unix epoch.
    pub timestamp: i64,
    /// Source address.
    pub src_ip: IpAddr,
    /// Destination address.
    pub dst_ip: IpAddr,
    /// Source transport port.
    pub src_port: u16,
    /// Destination transport port.
    pub dst_port: u16,
    /// IP protocol number, normally 6 or 17.
    pub protocol: u8,
    /// Transport payload length in bytes.
    pub payload_bytes: u64,
    /// Transport header length in bytes.
    pub header_bytes: u64,
    /// TCP control flags. UDP packets have no flags.
    pub tcp_flags: TcpFlags,
    /// TCP window size, or zero for UDP.
    pub tcp_window: u16,
}

impl FlowPacket {
    /// Parse a capture record into a TCP/UDP flow packet.
    pub fn from_record(record: &PacketRecord<'_>) -> Result<Option<Self>, ParseError> {
        let bytes = record.data.as_ref();
        let mut packet = Packet::new(bytes);
        packet.try_parse_with_link_type(record.link_type, Default::default())?;

        let layers = packet.layers();
        let Some((transport_index, transport)) = layers
            .iter()
            .enumerate()
            .rev()
            .find(|(_, layer)| layer.is(Tcp) || layer.is(Udp))
        else {
            return Ok(None);
        };
        let Some(network) = layers[..transport_index]
            .iter()
            .rev()
            .find(|layer| layer.is(Ipv4) || layer.is(Ipv6))
        else {
            return Ok(None);
        };

        let (src_ip, dst_ip, ip_end) = if network.is(Ipv4) {
            let ip = Ipv4::view(network.bytes(bytes));
            let range = network.range();
            let total = usize::from(ip.total_length().get());
            (
                IpAddr::V4(ip.src().get()),
                IpAddr::V4(ip.dst().get()),
                range.start.saturating_add(total).min(bytes.len()),
            )
        } else {
            let ip = Ipv6::view(network.bytes(bytes));
            let range = network.range();
            let total = 40usize.saturating_add(usize::from(ip.payload_length().get()));
            (
                IpAddr::V6(ip.src().get()),
                IpAddr::V6(ip.dst().get()),
                range.start.saturating_add(total).min(bytes.len()),
            )
        };

        if transport.is(Tcp) {
            let tcp = Tcp::view(transport.bytes(bytes));
            let range = transport.range();
            let payload_bytes = ip_end.saturating_sub(range.end) as u64;
            return Ok(Some(Self {
                timestamp: record.timestamp,
                src_ip,
                dst_ip,
                src_port: tcp.src_port().get(),
                dst_port: tcp.dst_port().get(),
                protocol: 6,
                payload_bytes,
                header_bytes: tcp.header_len() as u64,
                tcp_flags: tcp.flags().get(),
                tcp_window: tcp.window_size().get(),
            }));
        }

        if transport.is(Udp) {
            let udp = Udp::view(transport.bytes(bytes));
            let range = transport.range();
            let datagram_len =
                usize::from(udp.length().get()).min(ip_end.saturating_sub(range.start));
            return Ok(Some(Self {
                timestamp: record.timestamp,
                src_ip,
                dst_ip,
                src_port: udp.src_port().get(),
                dst_port: udp.dst_port().get(),
                protocol: 17,
                payload_bytes: datagram_len.saturating_sub(8) as u64,
                header_bytes: 8,
                tcp_flags: TcpFlags::empty(),
                tcp_window: 0,
            }));
        }

        Ok(None)
    }
}

/// Direction-independent key used to find both halves of a flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Canonical first endpoint address.
    pub left_ip: IpAddr,
    /// Canonical first endpoint port.
    pub left_port: u16,
    /// Canonical second endpoint address.
    pub right_ip: IpAddr,
    /// Canonical second endpoint port.
    pub right_port: u16,
    /// IP protocol number.
    pub protocol: u8,
}

impl FlowKey {
    /// Construct a direction-independent key from a packet.
    pub fn from_packet(packet: &FlowPacket) -> Self {
        let left = (packet.src_ip, packet.src_port);
        let right = (packet.dst_ip, packet.dst_port);
        let (left_ip, left_port, right_ip, right_port) = if left <= right {
            (left.0, left.1, right.0, right.1)
        } else {
            (right.0, right.1, left.0, left.1)
        };
        Self {
            left_ip,
            left_port,
            right_ip,
            right_port,
            protocol: packet.protocol,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Statistics {
    values: Vec<f64>,
}

impl Statistics {
    fn add(&mut self, value: f64) {
        self.values.push(value);
    }
    fn count(&self) -> usize {
        self.values.len()
    }
    fn sum(&self) -> f64 {
        self.values.iter().sum()
    }
    fn min(&self) -> f64 {
        self.values.iter().copied().reduce(f64::min).unwrap_or(0.0)
    }
    fn max(&self) -> f64 {
        self.values.iter().copied().reduce(f64::max).unwrap_or(0.0)
    }
    fn mean(&self) -> f64 {
        if self.values.is_empty() {
            0.0
        } else {
            self.sum() / self.values.len() as f64
        }
    }
    fn variance(&self) -> f64 {
        if self.values.len() < 2 {
            return 0.0;
        }
        let mean = self.mean();
        self.values
            .iter()
            .map(|value| (value - mean).powi(2))
            .sum::<f64>()
            / (self.values.len() - 1) as f64
    }
    fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    timestamp: i64,
    payload_bytes: f64,
    flags: TcpFlags,
}

#[derive(Debug, Clone, Default)]
struct BulkState {
    start: Option<i64>,
    last: Option<i64>,
    packet_count: u64,
    size: u64,
    states: u64,
    total_packets: u64,
    total_bytes: u64,
    duration: i64,
}

impl BulkState {
    fn add(&mut self, packet: Sample, other_last: Option<i64>) {
        if packet.payload_bytes <= 0.0 {
            return;
        }
        let timestamp = packet.timestamp;
        let size = packet.payload_bytes as u64;
        if other_last
            .zip(self.start)
            .is_some_and(|(other, start)| other > start)
        {
            self.start = None;
        }
        if self.start.is_none()
            || self
                .last
                .is_some_and(|last| timestamp.saturating_sub(last) > 1_000_000_000)
        {
            self.start = Some(timestamp);
            self.last = Some(timestamp);
            self.packet_count = 1;
            self.size = size;
            return;
        }
        self.packet_count += 1;
        self.size += size;
        if self.packet_count == 4 {
            self.states += 1;
            self.total_packets += self.packet_count;
            self.total_bytes += self.size;
            self.duration += timestamp - self.start.unwrap_or(timestamp);
        } else if self.packet_count > 4 {
            self.total_packets += 1;
            self.total_bytes += size;
            self.duration += timestamp - self.last.unwrap_or(timestamp);
        }
        self.last = Some(timestamp);
    }

    fn avg_bytes(&self) -> f64 {
        if self.states == 0 {
            0.0
        } else {
            self.total_bytes as f64 / self.states as f64
        }
    }
    fn avg_packets(&self) -> f64 {
        if self.states == 0 {
            0.0
        } else {
            self.total_packets as f64 / self.states as f64
        }
    }
    fn avg_rate(&self) -> f64 {
        if self.duration <= 0 {
            0.0
        } else {
            self.total_bytes as f64 / (self.duration as f64 / 1_000_000_000.0)
        }
    }
}

/// A completed flow feature row.
#[derive(Debug, Clone)]
pub struct FlowFeatures {
    values: Vec<String>,
}

impl FlowFeatures {
    /// Return the values in canonical CSV order.
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Render the row with RFC 4180-compatible CSV quoting.
    pub fn to_csv(&self) -> String {
        self.values
            .iter()
            .map(|value| csv_quote(value))
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Debug, Clone)]
struct Flow {
    first: FlowPacket,
    last_timestamp: i64,
    activity_timeout_ns: i64,
    forward: Vec<Sample>,
    backward: Vec<Sample>,
    flow_lengths: Statistics,
    flow_iat: Statistics,
    forward_iat: Statistics,
    backward_iat: Statistics,
    active: Statistics,
    idle: Statistics,
    active_start: i64,
    active_end: i64,
    forward_headers: u64,
    backward_headers: u64,
    flag_counts: [u64; 8],
    forward_psh: u64,
    backward_psh: u64,
    forward_urg: u64,
    backward_urg: u64,
    initial_forward_window: u16,
    initial_backward_window: u16,
    active_forward_data: u64,
    min_forward_segment: u64,
    last_forward: Option<i64>,
    last_backward: Option<i64>,
    subflows: u64,
    forward_bulk: BulkState,
    backward_bulk: BulkState,
}

impl Flow {
    fn new(packet: FlowPacket, activity_timeout_ns: i64) -> Self {
        let mut flow = Self {
            first: packet.clone(),
            last_timestamp: packet.timestamp,
            activity_timeout_ns,
            forward: Vec::new(),
            backward: Vec::new(),
            flow_lengths: Statistics::default(),
            flow_iat: Statistics::default(),
            forward_iat: Statistics::default(),
            backward_iat: Statistics::default(),
            active: Statistics::default(),
            idle: Statistics::default(),
            active_start: packet.timestamp,
            active_end: packet.timestamp,
            forward_headers: 0,
            backward_headers: 0,
            flag_counts: [0; 8],
            forward_psh: 0,
            backward_psh: 0,
            forward_urg: 0,
            backward_urg: 0,
            initial_forward_window: 0,
            initial_backward_window: 0,
            active_forward_data: 0,
            min_forward_segment: 0,
            last_forward: None,
            last_backward: None,
            // A flow always contains its initial subflow; later gaps create more.
            subflows: 1,
            forward_bulk: BulkState::default(),
            backward_bulk: BulkState::default(),
        };
        flow.add(packet);
        flow
    }

    fn is_forward(&self, packet: &FlowPacket) -> bool {
        packet.src_ip == self.first.src_ip
            && packet.dst_ip == self.first.dst_ip
            && packet.src_port == self.first.src_port
            && packet.dst_port == self.first.dst_port
    }

    fn add(&mut self, packet: FlowPacket) {
        let forward = self.is_forward(&packet);
        let sample = Sample {
            timestamp: packet.timestamp,
            payload_bytes: packet.payload_bytes as f64,
            flags: packet.tcp_flags,
        };
        let gap = packet.timestamp.saturating_sub(self.last_timestamp);
        if !self.forward.is_empty() || !self.backward.is_empty() {
            self.flow_iat.add(ns_to_micros(gap));
            if gap > 1_000_000_000 {
                self.subflows += 1;
            }
            if gap > self.activity_timeout_ns {
                if self.active_end > self.active_start {
                    self.active
                        .add(ns_to_micros(self.active_end - self.active_start));
                }
                self.idle.add(ns_to_micros(gap));
                self.active_start = packet.timestamp;
            }
        }
        self.active_end = packet.timestamp;
        self.last_timestamp = packet.timestamp;
        self.flow_lengths.add(sample.payload_bytes);
        self.check_flags(packet.tcp_flags);

        if forward {
            if let Some(last) = self.last_forward {
                self.forward_iat
                    .add(ns_to_micros(packet.timestamp.saturating_sub(last)));
            }
            if self.forward.is_empty() {
                self.initial_forward_window = packet.tcp_window;
                self.min_forward_segment = packet.header_bytes;
            }
            self.last_forward = Some(packet.timestamp);
            self.forward_headers += packet.header_bytes;
            if packet.payload_bytes > 0 {
                self.active_forward_data += 1;
            }
            if packet.tcp_flags.contains(TcpFlags::PSH) {
                self.forward_psh += 1;
            }
            if packet.tcp_flags.contains(TcpFlags::URG) {
                self.forward_urg += 1;
            }
            if self.min_forward_segment == 0 {
                self.min_forward_segment = packet.header_bytes;
            } else {
                self.min_forward_segment = self.min_forward_segment.min(packet.header_bytes);
            }
            self.forward_bulk.add(sample, self.last_backward);
            self.forward.push(sample);
        } else {
            if let Some(last) = self.last_backward {
                self.backward_iat
                    .add(ns_to_micros(packet.timestamp.saturating_sub(last)));
            }
            if self.backward.is_empty() {
                self.initial_backward_window = packet.tcp_window;
            }
            self.last_backward = Some(packet.timestamp);
            self.backward_headers += packet.header_bytes;
            if packet.tcp_flags.contains(TcpFlags::PSH) {
                self.backward_psh += 1;
            }
            if packet.tcp_flags.contains(TcpFlags::URG) {
                self.backward_urg += 1;
            }
            self.backward_bulk.add(sample, self.last_forward);
            self.backward.push(sample);
        }
    }

    fn check_flags(&mut self, flags: TcpFlags) {
        for (index, flag) in [
            TcpFlags::FIN,
            TcpFlags::SYN,
            TcpFlags::RST,
            TcpFlags::PSH,
            TcpFlags::ACK,
            TcpFlags::URG,
            TcpFlags::CWR,
            TcpFlags::ECE,
        ]
        .into_iter()
        .enumerate()
        {
            if flags.contains(flag) {
                self.flag_counts[index] += 1;
            }
        }
    }

    fn has_both_fin(&self) -> bool {
        self.flag_counts[0] > 0
            && self.forward.iter().any(|p| p.flags.contains(TcpFlags::FIN))
            && self
                .backward
                .iter()
                .any(|p| p.flags.contains(TcpFlags::FIN))
    }
    fn finish(mut self, label: &str) -> FlowFeatures {
        if self.active_end > self.active_start {
            self.active
                .add(ns_to_micros(self.active_end - self.active_start));
        }
        let duration_ns = self.last_timestamp.saturating_sub(self.first.timestamp);
        let duration_us = duration_ns.max(0) / 1_000;
        let duration_s = duration_ns as f64 / 1_000_000_000.0;
        let packet_count = self.forward.len() + self.backward.len();
        let total_bytes = self.flow_lengths.sum();
        let fwd = &self.forward;
        let bwd = &self.backward;
        let fwd_stats = stats_for(fwd);
        let bwd_stats = stats_for(bwd);
        let fwd_iat = stat_values(&self.forward_iat, self.forward.len() > 1);
        let bwd_iat = stat_values(&self.backward_iat, self.backward.len() > 1);
        let flow_iat = stat_values(&self.flow_iat, true);
        let active = stat_values(&self.active, true);
        let idle = stat_values(&self.idle, true);
        let rate = |value: f64| {
            if duration_s > 0.0 {
                value / duration_s
            } else {
                0.0
            }
        };
        let timestamp = format_timestamp(self.first.timestamp);
        let flow_id = format!(
            "{}-{}-{}-{}-{}",
            self.first.src_ip,
            self.first.dst_ip,
            self.first.src_port,
            self.first.dst_port,
            self.first.protocol
        );
        let values = vec![
            flow_id,
            self.first.src_ip.to_string(),
            self.first.src_port.to_string(),
            self.first.dst_ip.to_string(),
            self.first.dst_port.to_string(),
            self.first.protocol.to_string(),
            timestamp,
            duration_us.to_string(),
            fwd.len().to_string(),
            bwd.len().to_string(),
            fmt(total_bytes_of(fwd)),
            fmt(total_bytes_of(bwd)),
            fmt(fwd_stats.2),
            fmt(fwd_stats.1),
            fmt(fwd_stats.0),
            fmt(fwd_stats.3),
            fmt(bwd_stats.2),
            fmt(bwd_stats.1),
            fmt(bwd_stats.0),
            fmt(bwd_stats.3),
            fmt(rate(total_bytes)),
            fmt(rate(packet_count as f64)),
            fmt(flow_iat.0),
            fmt(flow_iat.3),
            fmt(flow_iat.2),
            fmt(flow_iat.1),
            fmt(fwd_iat.4),
            fmt(fwd_iat.0),
            fmt(fwd_iat.3),
            fmt(fwd_iat.2),
            fmt(fwd_iat.1),
            fmt(bwd_iat.4),
            fmt(bwd_iat.0),
            fmt(bwd_iat.3),
            fmt(bwd_iat.2),
            fmt(bwd_iat.1),
            self.forward_psh.to_string(),
            self.backward_psh.to_string(),
            self.forward_urg.to_string(),
            self.backward_urg.to_string(),
            self.forward_headers.to_string(),
            self.backward_headers.to_string(),
            fmt(rate(fwd.len() as f64)),
            fmt(rate(bwd.len() as f64)),
            fmt(self.flow_lengths.min()),
            fmt(self.flow_lengths.max()),
            fmt(self.flow_lengths.mean()),
            fmt(self.flow_lengths.stddev()),
            fmt(self.flow_lengths.variance()),
            self.flag_counts[0].to_string(),
            self.flag_counts[1].to_string(),
            self.flag_counts[2].to_string(),
            self.flag_counts[3].to_string(),
            self.flag_counts[4].to_string(),
            self.flag_counts[5].to_string(),
            self.flag_counts[6].to_string(),
            self.flag_counts[7].to_string(),
            fmt(if fwd.is_empty() {
                0.0
            } else {
                bwd.len() as f64 / fwd.len() as f64
            }),
            fmt(if packet_count == 0 {
                0.0
            } else {
                total_bytes / packet_count as f64
            }),
            fmt(if fwd.is_empty() {
                0.0
            } else {
                total_bytes_of(fwd) / fwd.len() as f64
            }),
            fmt(if bwd.is_empty() {
                0.0
            } else {
                total_bytes_of(bwd) / bwd.len() as f64
            }),
            self.forward_headers.to_string(),
            fmt(self.forward_bulk.avg_bytes()),
            fmt(self.forward_bulk.avg_packets()),
            fmt(self.forward_bulk.avg_rate()),
            fmt(self.backward_bulk.avg_bytes()),
            fmt(self.backward_bulk.avg_packets()),
            fmt(self.backward_bulk.avg_rate()),
            fmt(if self.subflows == 0 {
                0.0
            } else {
                fwd.len() as f64 / self.subflows as f64
            }),
            fmt(if self.subflows == 0 {
                0.0
            } else {
                total_bytes_of(fwd) / self.subflows as f64
            }),
            fmt(if self.subflows == 0 {
                0.0
            } else {
                bwd.len() as f64 / self.subflows as f64
            }),
            fmt(if self.subflows == 0 {
                0.0
            } else {
                total_bytes_of(bwd) / self.subflows as f64
            }),
            self.initial_forward_window.to_string(),
            self.initial_backward_window.to_string(),
            self.active_forward_data.to_string(),
            self.min_forward_segment.to_string(),
            fmt(active.0),
            fmt(active.3),
            fmt(active.2),
            fmt(active.1),
            fmt(idle.0),
            fmt(idle.3),
            fmt(idle.2),
            fmt(idle.1),
            label.to_string(),
        ];
        debug_assert_eq!(values.len(), CICFLOWMETER_HEADER.len());
        FlowFeatures { values }
    }
}

/// Streaming flow generator with timeout and TCP termination handling.
#[derive(Debug)]
pub struct FlowGenerator {
    flows: HashMap<FlowKey, Flow>,
    flow_timeout_ns: i64,
    activity_timeout_ns: i64,
}

impl Default for FlowGenerator {
    fn default() -> Self {
        Self::new(120_000_000_000, 5_000_000_000)
    }
}

impl FlowGenerator {
    /// Create a generator with the CICFlowMeter defaults of 120 seconds and 5 seconds.
    pub fn new(flow_timeout_ns: i64, activity_timeout_ns: i64) -> Self {
        Self {
            flows: HashMap::new(),
            flow_timeout_ns,
            activity_timeout_ns,
        }
    }

    /// Add a packet and return all rows closed by this packet.
    pub fn add(&mut self, packet: FlowPacket, label: &str) -> Vec<FlowFeatures> {
        let key = FlowKey::from_packet(&packet);
        let mut completed = Vec::new();
        let mut flow = self.flows.remove(&key);
        if flow.as_ref().is_some_and(|existing| {
            packet.timestamp.saturating_sub(existing.last_timestamp) > self.flow_timeout_ns
        }) {
            let old = flow.take().expect("flow exists");
            if old.forward.len() + old.backward.len() > 1 {
                completed.push(old.finish(label));
            }
        }
        if let Some(mut existing) = flow {
            let is_rst = packet.tcp_flags.contains(TcpFlags::RST);
            existing.add(packet);
            let is_closed = is_rst || existing.has_both_fin();
            if is_closed {
                if existing.forward.len() + existing.backward.len() > 1 {
                    completed.push(existing.finish(label));
                }
            } else {
                self.flows.insert(key, existing);
            }
        } else {
            self.flows
                .insert(key, Flow::new(packet, self.activity_timeout_ns));
        }
        completed
    }

    /// Finish all currently open flows.
    pub fn finish(self, label: &str) -> Vec<FlowFeatures> {
        let mut rows: Vec<_> = self
            .flows
            .into_values()
            .filter(|flow| flow.forward.len() + flow.backward.len() > 1)
            .map(|flow| flow.finish(label))
            .collect();
        rows.sort_by(|left, right| {
            left.values
                .get(6)
                .cmp(&right.values.get(6))
                .then_with(|| left.values.first().cmp(&right.values.first()))
        });
        rows
    }
}

fn stats_for(samples: &[Sample]) -> (f64, f64, f64, f64) {
    let mut stats = Statistics::default();
    for sample in samples {
        stats.add(sample.payload_bytes);
    }
    (stats.mean(), stats.min(), stats.max(), stats.stddev())
}

fn stat_values(stats: &Statistics, enabled: bool) -> (f64, f64, f64, f64, f64) {
    if !enabled || stats.count() == 0 {
        (0.0, 0.0, 0.0, 0.0, 0.0)
    } else {
        (
            stats.mean(),
            stats.min(),
            stats.max(),
            stats.stddev(),
            stats.sum(),
        )
    }
}

fn total_bytes_of(samples: &[Sample]) -> f64 {
    samples.iter().map(|sample| sample.payload_bytes).sum()
}
fn format_timestamp(timestamp: i64) -> String {
    temporal_rs::Instant::try_new(i128::from(timestamp))
        .and_then(|instant| instant.to_ixdtf_string(None, Default::default()))
        .map(|value| value.to_string())
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
fn ns_to_micros(value: i64) -> f64 {
    value.max(0) as f64 / 1_000.0
}
fn fmt(value: f64) -> String {
    if value == 0.0 {
        "0".to_string()
    } else if value.is_finite() {
        value.to_string()
    } else {
        "0".to_string()
    }
}
fn csv_quote(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maja::capture::{link_type::LinkType, packet::PacketRecord};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn packet(ts: i64, src_port: u16, dst_port: u16, bytes: u64, flags: TcpFlags) -> FlowPacket {
        FlowPacket {
            timestamp: ts,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            protocol: 6,
            payload_bytes: bytes,
            header_bytes: 20,
            tcp_flags: flags,
            tcp_window: 4096,
        }
    }

    fn reverse(mut packet: FlowPacket) -> FlowPacket {
        std::mem::swap(&mut packet.src_ip, &mut packet.dst_ip);
        std::mem::swap(&mut packet.src_port, &mut packet.dst_port);
        packet
    }

    #[test]
    fn schema_has_expected_width_and_label() {
        let mut generator = FlowGenerator::new(120_000_000_000, 5_000_000_000);
        let mut rows = generator.add(packet(0, 1234, 80, 10, TcpFlags::SYN), "NeedManualLabel");
        rows.extend(generator.add(
            reverse(packet(1_000_000, 1234, 80, 20, TcpFlags::ACK)),
            "NeedManualLabel",
        ));
        rows.extend(generator.finish("NeedManualLabel"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].values().len(), CICFLOWMETER_HEADER.len());
        assert_eq!(rows[0].values().last().unwrap(), "NeedManualLabel");
        assert!(
            rows[0]
                .values()
                .iter()
                .all(|value| !value.contains("NaN") && !value.contains("inf"))
        );
    }

    #[test]
    fn timeout_splits_flow_and_finishes_both_directions() {
        let mut generator = FlowGenerator::new(10, 5);
        assert!(
            generator
                .add(packet(0, 1, 2, 1, TcpFlags::empty()), "x")
                .is_empty()
        );
        assert!(
            generator
                .add(packet(1, 1, 2, 1, TcpFlags::empty()), "x")
                .is_empty()
        );
        let rows = generator.add(packet(12, 1, 2, 1, TcpFlags::empty()), "x");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            generator
                .add(reverse(packet(12, 1, 2, 1, TcpFlags::FIN)), "x")
                .len(),
            0
        );
        assert_eq!(
            generator.add(packet(13, 1, 2, 1, TcpFlags::FIN), "x").len(),
            1
        );
    }

    #[test]
    fn subflow_averages_include_initial_subflow() {
        let mut generator = FlowGenerator::new(120_000_000_000, 5_000_000_000);
        generator.add(packet(0, 1234, 80, 10, TcpFlags::empty()), "x");
        generator.add(packet(1_000_000, 1234, 80, 20, TcpFlags::empty()), "x");
        let rows = generator.finish("x");
        let row = &rows[0];
        let column = |name| {
            CICFLOWMETER_HEADER
                .iter()
                .position(|column| *column == name)
                .expect("column exists")
        };

        assert_eq!(row.values()[column("Subflow Fwd Packets")], "2");
        assert_eq!(row.values()[column("Subflow Fwd Bytes")], "30");
        assert_eq!(row.values()[column("Subflow Bwd Packets")], "0");
        assert_eq!(row.values()[column("Subflow Bwd Bytes")], "0");
    }

    #[test]
    fn subflow_averages_use_each_split() {
        let mut generator = FlowGenerator::new(120_000_000_000, 5_000_000_000);
        generator.add(packet(0, 1234, 80, 10, TcpFlags::empty()), "x");
        generator.add(packet(1_000_000_001, 1234, 80, 20, TcpFlags::empty()), "x");
        let rows = generator.finish("x");
        let row = &rows[0];
        let column = |name| {
            CICFLOWMETER_HEADER
                .iter()
                .position(|column| *column == name)
                .expect("column exists")
        };

        assert_eq!(row.values()[column("Subflow Fwd Packets")], "1");
        assert_eq!(row.values()[column("Subflow Fwd Bytes")], "15");
    }

    #[test]
    fn timestamp_is_iso_utc_with_fractional_precision() {
        let mut generator = FlowGenerator::new(120_000_000_000, 5_000_000_000);
        generator.add(packet(1_234_567_890, 1234, 80, 10, TcpFlags::empty()), "x");
        generator.add(packet(1_235_567_890, 1234, 80, 20, TcpFlags::empty()), "x");
        let row = &generator.finish("x")[0];
        let timestamp = &row.values()[6];

        assert!(timestamp.starts_with("1970-01-01T00:00:01.23456789"));
        assert!(timestamp.ends_with('Z'));
    }

    #[test]
    fn from_record_pairs_inner_transport_with_inner_ip() {
        let mut bytes = Vec::new();

        // Outer Ethernet + IPv4 + UDP carrying VXLAN.
        bytes.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00]);
        bytes.extend_from_slice(&[
            0x45, 0, 0, 0x6e, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
        ]);
        bytes.extend_from_slice(&[0x30, 0x39, 0x12, 0xb5, 0, 0x5a, 0, 0]);
        bytes.extend_from_slice(&[0x08, 0, 0, 0, 0, 0, 1, 0]);

        // Inner Ethernet + IPv6 + TCP.
        bytes.extend_from_slice(&[12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 0x86, 0xdd]);
        bytes.extend_from_slice(&[
            0x60, 0, 0, 0, 0, 0x14, 6, 64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]);
        bytes.extend_from_slice(&[
            0x04, 0xd2, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x10, 0, 0, 0, 0, 0,
        ]);

        let record = PacketRecord::new(123, bytes.len() as u32, bytes, LinkType::Ethernet);
        let flow = FlowPacket::from_record(&record)
            .expect("VXLAN packet should parse")
            .expect("inner TCP flow should be found");

        assert_eq!(
            flow.src_ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(
            flow.dst_ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
        );
        assert_eq!(flow.src_port, 1234);
        assert_eq!(flow.dst_port, 443);
        assert_eq!(flow.protocol, 6);
    }
}
