use std::{io::Write, net::IpAddr, path::Path, time::Duration};

use clap::ValueEnum;
use maja::capture::{CaptureFormat, interface::Interface};
use serde::Serialize;

use crate::{
    analysis::{RunningTrafficStats, Stats},
    metadata::{DumpFormat, DumpResult},
};

/// Output encoding for the capture summary report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    /// Human-readable terminal report.
    #[default]
    Text,
    /// JSON object, or JSON Lines for multiple captures.
    Json,
    /// Standalone TOML, or an array of tables for multiple captures.
    Toml,
    /// YAML document stream.
    Yaml,
}

impl ReportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::Json => "json",
            Self::Toml => "toml",
            Self::Yaml => "yaml",
        }
    }
}

/// Complete report for one capture.
#[derive(Debug, Serialize)]
pub struct CaptureReport {
    /// Version of the tool
    pub version: &'static str,

    /// Input file metadata
    pub file: FileReport,

    /// Captured packet statistics
    pub packet_statistics: PacketStatistics,

    /// Aggregated statistics derived from successfully parsed packet metadata
    pub aggregated_statistics: AggregatedStatistics,

    /// Top-k statistics for endpoints and ports
    pub top_statistics: TopStatistics,

    /// Optional metadata export information, if a dump was requested
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_export: Option<MetadataExport>,
}

/// Input file metadata
#[derive(Debug, Serialize)]
pub struct FileReport {
    /// Path to the capture file
    pub path: String,

    /// Capture file's format
    pub capture_format: CaptureFormat,

    /// Size of the capture file in bytes
    pub size_bytes: u64,

    /// Time taken to process the capture file in seconds
    pub processing_time_seconds: f64,

    /// List of capture interfaces
    pub interfaces: Vec<Interface>,
}

/// Captured packet statistics
#[derive(Debug, Serialize)]
pub struct PacketStatistics {
    /// Total number of packets extracted from the capture file
    pub total_packets: u64,
    /// Total number of bytes at the link layer (L2)
    pub total_l2_bytes: u64,
    /// Average length of packets at the link layer (L2) in bytes
    pub average_l2_length_bytes: f64,
    /// Total number of bytes at the network layer (L3), e.g. IP packets
    pub total_l3_bytes: u64,
    /// Average length of packets at the network layer (L3) in bytes
    pub average_l3_length_bytes: f64,
    /// Total number of packets that were empty (zero-length)
    pub empty_packets: u64,
    /// Total number of packets that had errors during extraction
    pub errors: u64,
    /// Whether the capture file's packets were in chronological order
    pub ordered: bool,
    /// Timestamp of the first packet in nanoseconds since the Unix epoch, if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_packet_timestamp_ns: Option<i64>,
    /// Timestamp of the last packet in nanoseconds since the Unix epoch, if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_packet_timestamp_ns: Option<i64>,
    /// Duration of the capture in seconds, derived from the first and last packet timestamps
    pub duration_seconds: f64,
    /// The Average number of packets per second, derived from the total packets and duration
    pub packets_per_second: f64,
    /// The Average number of bytes per second, derived from the total L2 bytes and duration
    pub bytes_per_second: f64,
}

/// Exact statistics derived from successfully parsed packet metadata.
#[derive(Debug, Serialize)]
pub struct AggregatedStatistics {
    /// Online distribution summary for original packet lengths.
    pub length: LengthStatistics,
    /// Count of unique source IP addresses observed in the capture.
    pub unique_src_ips: usize,
    /// Count of unique destination IP addresses observed in the capture.
    pub unique_dst_ips: usize,
    /// Count of TCP packets observed in the capture.
    pub tcp_packets: u64,
    /// Count of UDP packets observed in the capture.
    pub udp_packets: u64,
    /// Count of unique source transport ports observed in the capture.
    pub unique_src_ports: usize,
    /// Count of unique destination transport ports observed in the capture.
    pub unique_dst_ports: usize,
    /// Count of unique symmetric flows observed in the capture.
    ///
    /// TCP and UDP use 5-tuples; other IP protocols use 3-tuples containing
    /// the source address, destination address, and protocol.
    pub unique_flows: usize,
}

/// Online distribution summary for original packet lengths.
#[derive(Debug, Serialize)]
pub struct LengthStatistics {
    pub mean_bytes: f64,
    pub sample_std_dev_bytes: f64,
    pub min_bytes: u32,
    pub max_bytes: u32,
}

/// Highest-traffic endpoint and port records for each direction.
#[derive(Debug, Serialize)]
pub struct TopStatistics {
    pub limit: usize,
    pub src_ips: Vec<IpTraffic>,
    pub dst_ips: Vec<IpTraffic>,
    pub src_ports: Vec<PortTraffic>,
    pub dst_ports: Vec<PortTraffic>,
}

/// Packet and byte totals associated with an IP address.
#[derive(Debug, Serialize)]
pub struct IpTraffic {
    pub address: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Packet and byte totals associated with a transport port.
#[derive(Debug, Serialize)]
pub struct PortTraffic {
    pub port: u16,
    pub packets: u64,
    pub bytes: u64,
}

/// Metadata dump artifact associated with a capture report.
#[derive(Debug, Serialize)]
pub struct MetadataExport {
    pub path: String,
    pub format: DumpFormat,
    pub elapsed_seconds: f64,
}

/// TOML wrapper used because TOML has no multi-document stream syntax.
#[derive(Serialize)]
struct ReportCollection<'a> {
    reports: &'a [CaptureReport],
}

impl CaptureReport {
    pub fn new(
        file: FileReport,
        stats: &Stats,
        top_k: usize,
        dump_result: Option<DumpResult>,
    ) -> Self {
        let duration_seconds = match (stats.first_timestamp, stats.last_timestamp) {
            (Some(first), Some(last)) => (last as i128 - first as i128) as f64 / 1_000_000_000.0,
            _ => 0.0,
        };

        Self {
            version: env!("CARGO_PKG_VERSION"),
            file,
            packet_statistics: PacketStatistics {
                total_packets: stats.total_packets,
                total_l2_bytes: stats.total_l2_bytes,
                average_l2_length_bytes: average(stats.total_l2_bytes, stats.total_packets),
                total_l3_bytes: stats.total_l3_bytes,
                average_l3_length_bytes: average(stats.total_l3_bytes, stats.total_packets),
                empty_packets: stats.empty_packets,
                errors: stats.errors,
                ordered: stats.is_ordered,
                first_packet_timestamp_ns: stats.first_timestamp,
                last_packet_timestamp_ns: stats.last_timestamp,
                duration_seconds,
                packets_per_second: rate(stats.total_packets, duration_seconds),
                bytes_per_second: rate(stats.total_l2_bytes, duration_seconds),
            },
            aggregated_statistics: AggregatedStatistics {
                length: LengthStatistics {
                    mean_bytes: stats.lengths.mean(),
                    sample_std_dev_bytes: stats.lengths.std_dev(1),
                    min_bytes: stats.lengths.min(),
                    max_bytes: stats.lengths.max(),
                },
                unique_src_ips: stats.unique_src_ips(),
                unique_dst_ips: stats.unique_dst_ips(),
                tcp_packets: stats.tcp_count,
                udp_packets: stats.udp_count,
                unique_src_ports: stats.unique_src_ports(),
                unique_dst_ports: stats.unique_dst_ports(),
                unique_flows: stats.flow_set.len(),
            },
            top_statistics: TopStatistics {
                limit: top_k,
                src_ips: ip_traffic(stats.top_src_ips(top_k)),
                dst_ips: ip_traffic(stats.top_dst_ips(top_k)),
                src_ports: port_traffic(stats.top_src_ports(top_k)),
                dst_ports: port_traffic(stats.top_dst_ports(top_k)),
            },
            metadata_export: dump_result.map(|result| MetadataExport {
                path: result.path.display().to_string(),
                format: result.format,
                elapsed_seconds: result.elapsed.as_secs_f64(),
            }),
        }
    }

    fn render_text(&self, mut writer: impl Write) -> anyhow::Result<()> {
        let humanize = human_format::Formatter::new();

        writeln!(writer, "{}", "=".repeat(70))?;
        writeln!(writer, "File:               {}", self.file.path)?;
        writeln!(writer, "  Format:           {}", self.file.capture_format)?;
        writeln!(
            writer,
            "  Size:             {}B",
            humanize.format(self.file.size_bytes as f64)
        )?;
        writeln!(
            writer,
            "  Processing Time:  {:.6} s",
            self.file.processing_time_seconds
        )?;
        writeln!(writer, "  Interfaces:")?;
        for (index, interface) in self.file.interfaces.iter().enumerate() {
            writeln!(
                writer,
                "    #{:<15}LinkType = {}, SnapLen = {}, Resolution = {}",
                index, interface.link_type, interface.snap_len, interface.resolution
            )?;
        }

        let packets = &self.packet_statistics;
        writeln!(writer, "\nPacket Statistics:")?;
        writeln!(
            writer,
            "  Total Packets:    {}",
            humanize.format(packets.total_packets as f64)
        )?;
        writeln!(
            writer,
            "  Total L2 Bytes:   {}B",
            humanize.format(packets.total_l2_bytes as f64)
        )?;
        writeln!(
            writer,
            "    Avg L2 Length:  {:.2}B",
            packets.average_l2_length_bytes
        )?;
        writeln!(
            writer,
            "  Total L3 Bytes:   {}B",
            humanize.format(packets.total_l3_bytes as f64)
        )?;
        writeln!(
            writer,
            "    Avg L3 Length:  {:.2}B",
            packets.average_l3_length_bytes
        )?;
        writeln!(writer, "  Empty Packets:    {}", packets.empty_packets)?;
        writeln!(writer, "  Errors:           {}", packets.errors)?;
        writeln!(writer, "  Ordered:          {}", packets.ordered)?;

        match (
            packets.first_packet_timestamp_ns,
            packets.last_packet_timestamp_ns,
        ) {
            (Some(first), Some(last)) => {
                writeln!(
                    writer,
                    "  First packet:     {} ({first})",
                    format_timestamp(first)?
                )?;
                writeln!(
                    writer,
                    "  Last packet:      {} ({last})",
                    format_timestamp(last)?
                )?;
                let first = temporal_rs::Instant::try_new(first as i128)?;
                let last = temporal_rs::Instant::try_new(last as i128)?;
                writeln!(
                    writer,
                    "  Duration:         {}",
                    last.since(&first, Default::default())?
                )?;
            }
            _ => {
                writeln!(writer, "  First packet:     N/A")?;
                writeln!(writer, "  Last packet:      N/A")?;
                writeln!(writer, "  Duration:         N/A")?;
            }
        }
        writeln!(
            writer,
            "  Throughput:       {}pps, {}Bps",
            humanize.format(packets.packets_per_second),
            humanize.format(packets.bytes_per_second)
        )?;

        let aggregated = &self.aggregated_statistics;
        writeln!(writer, "\nAggregated Statistics:")?;
        writeln!(
            writer,
            "  Length:           {:.2} (± {:.2}) [{}, {}] Bytes",
            aggregated.length.mean_bytes,
            aggregated.length.sample_std_dev_bytes,
            aggregated.length.min_bytes,
            aggregated.length.max_bytes
        )?;
        writeln!(writer, "  Unique SRC IP:    {}", aggregated.unique_src_ips)?;
        writeln!(writer, "  Unique DST IP:    {}", aggregated.unique_dst_ips)?;
        writeln!(writer, "  TCP Count:        {}", aggregated.tcp_packets)?;
        writeln!(writer, "  UDP Count:        {}", aggregated.udp_packets)?;
        writeln!(
            writer,
            "  Unique SRC Ports: {}",
            aggregated.unique_src_ports
        )?;
        writeln!(
            writer,
            "  Unique DST Ports: {}",
            aggregated.unique_dst_ports
        )?;
        writeln!(writer, "  Unique flows:     {}", aggregated.unique_flows)?;

        let top = &self.top_statistics;
        let ip_column_width = traffic_key_width(
            top.src_ips
                .iter()
                .chain(&top.dst_ips)
                .map(|value| value.address.as_str()),
        );
        writeln!(writer, "\nTop{} Statistics:", top.limit)?;
        writeln!(writer, "  Top {} SRC IPs:", top.limit)?;
        for value in &top.src_ips {
            write_traffic_line(
                &mut writer,
                &humanize,
                &value.address,
                ip_column_width,
                value.packets,
                value.bytes,
            )?;
        }
        writeln!(writer, "  Top {} DST IPs:", top.limit)?;
        for value in &top.dst_ips {
            write_traffic_line(
                &mut writer,
                &humanize,
                &value.address,
                ip_column_width,
                value.packets,
                value.bytes,
            )?;
        }
        writeln!(writer, "  Top {} SRC Ports:", top.limit)?;
        for value in &top.src_ports {
            write_traffic_line(
                &mut writer,
                &humanize,
                &value.port.to_string(),
                15,
                value.packets,
                value.bytes,
            )?;
        }
        writeln!(writer, "  Top {} DST Ports:", top.limit)?;
        for value in &top.dst_ports {
            write_traffic_line(
                &mut writer,
                &humanize,
                &value.port.to_string(),
                15,
                value.packets,
                value.bytes,
            )?;
        }

        if let Some(export) = &self.metadata_export {
            writeln!(writer, "\nExport Statistics:")?;
            writeln!(writer, "  Output File: {}", export.path)?;
            writeln!(writer, "  Format:                  {:>12?}", export.format)?;
            writeln!(
                writer,
                "  Elapsed Time:   {:>12.6} s",
                export.elapsed_seconds
            )?;
        }
        writeln!(writer, "{}", "=".repeat(70))?;
        Ok(())
    }
}

impl FileReport {
    pub fn new(
        file_path: &Path,
        capture_format: CaptureFormat,
        file_size: u64,
        processing_time: Duration,
        interfaces: &[Interface],
    ) -> Self {
        Self {
            path: file_path.display().to_string(),
            capture_format,
            size_bytes: file_size,
            processing_time_seconds: processing_time.as_secs_f64(),
            interfaces: interfaces.to_vec(),
        }
    }
}

pub fn write_reports(
    mut writer: impl Write,
    reports: &[CaptureReport],
    format: ReportFormat,
) -> anyhow::Result<()> {
    if reports.is_empty() {
        return Ok(());
    }

    match format {
        ReportFormat::Text => {
            for report in reports {
                report.render_text(&mut writer)?;
            }
        }
        ReportFormat::Json if reports.len() == 1 => {
            serde_json::to_writer_pretty(&mut writer, &reports[0])?;
            writeln!(writer)?;
        }
        ReportFormat::Json => {
            for report in reports {
                serde_json::to_writer(&mut writer, report)?;
                writeln!(writer)?;
            }
        }
        ReportFormat::Toml if reports.len() == 1 => {
            writer.write_all(toml::to_string_pretty(&reports[0])?.as_bytes())?;
        }
        ReportFormat::Toml => {
            writer.write_all(toml::to_string_pretty(&ReportCollection { reports })?.as_bytes())?;
        }
        ReportFormat::Yaml => {
            for report in reports {
                writeln!(writer, "---")?;
                yaml_serde::to_writer(&mut writer, report)?;
            }
        }
    }
    Ok(())
}

fn average(total: u64, count: u64) -> f64 {
    if count == 0 {
        0.0
    } else {
        total as f64 / count as f64
    }
}

fn rate(total: u64, duration_seconds: f64) -> f64 {
    if duration_seconds <= 0.0 {
        0.0
    } else {
        total as f64 / duration_seconds
    }
}

fn ip_traffic(values: Vec<(IpAddr, RunningTrafficStats)>) -> Vec<IpTraffic> {
    values
        .into_iter()
        .map(|(address, traffic)| IpTraffic {
            address: address.to_string(),
            packets: traffic.count,
            bytes: traffic.bytes,
        })
        .collect()
}

fn port_traffic(values: Vec<(u16, RunningTrafficStats)>) -> Vec<PortTraffic> {
    values
        .into_iter()
        .map(|(port, traffic)| PortTraffic {
            port,
            packets: traffic.count,
            bytes: traffic.bytes,
        })
        .collect()
}

fn format_timestamp(timestamp_ns: i64) -> anyhow::Result<String> {
    Ok(temporal_rs::Instant::try_new(timestamp_ns as i128)?
        .to_zoned_date_time_iso(temporal_rs::TimeZone::utc())?
        .to_string())
}

fn write_traffic_line(
    writer: &mut impl Write,
    humanize: &human_format::Formatter,
    key: &str,
    key_width: usize,
    packets: u64,
    bytes: u64,
) -> std::io::Result<()> {
    writeln!(
        writer,
        "    {key:<key_width$} {:>8}pkts, {:>8}B",
        humanize.format(packets as f64),
        humanize.format(bytes as f64)
    )
}

fn traffic_key_width<'a>(keys: impl Iterator<Item = &'a str>) -> usize {
    keys.map(str::len).max().unwrap_or(15).max(15)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maja::capture::{interface::Resolution, link_type::LinkType};

    fn sample_report(path: &str) -> CaptureReport {
        let mut stats = Stats::default();
        stats.update_with_packet(1_000_000_000, 64);
        stats.update_with_packet(2_000_000_000, 128);

        CaptureReport::new(
            FileReport::new(
                Path::new(path),
                CaptureFormat::Pcap,
                256,
                Duration::from_millis(5),
                &[Interface {
                    link_type: LinkType::Ethernet,
                    snap_len: 65_535,
                    resolution: Resolution::PowerOfTen(9),
                }],
            ),
            &stats,
            10,
            None,
        )
    }

    fn serialized(reports: &[CaptureReport], format: ReportFormat) -> anyhow::Result<String> {
        let mut output = Vec::new();
        write_reports(&mut output, reports, format)?;
        Ok(String::from_utf8(output)?)
    }

    #[test]
    fn structured_formats_are_parseable() -> anyhow::Result<()> {
        let reports = [sample_report("one.pcap"), sample_report("two.pcap")];

        let json = serialized(&reports, ReportFormat::Json)?;
        let json_reports = json
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(json_reports.len(), 2);
        assert_eq!(json_reports[0]["file"]["capture_format"], "Pcap");
        assert_eq!(
            json_reports[0]["file"]["interfaces"][0],
            serde_json::json!({
                "link_type": "Ethernet",
                "snap_len": 65_535,
                "resolution": { "PowerOfTen": 9 },
            })
        );

        let toml = toml::from_str::<toml::Value>(&serialized(&reports, ReportFormat::Toml)?)?;
        assert_eq!(toml["reports"].as_array().map(Vec::len), Some(2));

        let yaml = serialized(&reports, ReportFormat::Yaml)?;
        let yaml_documents = yaml
            .split("---")
            .filter(|document| !document.trim().is_empty())
            .map(yaml_serde::from_str::<yaml_serde::Value>)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(yaml_documents.len(), 2);
        Ok(())
    }

    #[test]
    fn single_json_report_is_pretty() -> anyhow::Result<()> {
        let json = serialized(&[sample_report("capture.pcap")], ReportFormat::Json)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;

        assert_eq!(parsed["version"], env!("CARGO_PKG_VERSION"));
        assert!(json.contains("\n  \"version\": "));
        Ok(())
    }

    #[test]
    fn single_toml_report_is_standalone() -> anyhow::Result<()> {
        let toml = serialized(&[sample_report("capture.pcap")], ReportFormat::Toml)?;
        let parsed = toml::from_str::<toml::Value>(&toml)?;

        assert_eq!(parsed["version"].as_str(), Some(env!("CARGO_PKG_VERSION")));
        assert!(parsed.get("reports").is_none());
        Ok(())
    }

    #[test]
    fn empty_report_has_finite_zero_rates() -> anyhow::Result<()> {
        let report = CaptureReport::new(
            FileReport::new(
                Path::new("empty.pcap"),
                CaptureFormat::Pcap,
                24,
                Duration::ZERO,
                &[],
            ),
            &Stats::default(),
            10,
            None,
        );
        let reports = [report];
        let json = serialized(&reports, ReportFormat::Json)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;

        assert_eq!(parsed["packet_statistics"]["average_l2_length_bytes"], 0.0);
        assert_eq!(parsed["packet_statistics"]["packets_per_second"], 0.0);
        assert_eq!(parsed["aggregated_statistics"]["length"]["min_bytes"], 0);
        let text = serialized(&reports, ReportFormat::Text)?;
        assert!(text.contains("First packet:     N/A"));
        assert!(!text.contains("NaN"));
        Ok(())
    }

    #[test]
    fn traffic_key_width_expands_for_ipv6() {
        let longest = "3ffe:501:410:0:2c0:dfff:fe47:33e";
        assert_eq!(traffic_key_width(["192.0.2.1"].into_iter()), 15);
        assert_eq!(
            traffic_key_width([longest, "2001:db8::1"].into_iter()),
            longest.len()
        );
    }
}
