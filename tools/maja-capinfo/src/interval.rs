use std::{
    collections::{BTreeMap, HashSet},
    io::Write,
    num::NonZeroU64,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use maja::packet::flow::FlowIdSymmetric;
use polars::prelude::*;

use crate::{
    analysis::flow_id,
    metadata::{DumpFormat, PacketMetadata},
};

/// Exact statistics for one nonempty, epoch-aligned time interval.
#[derive(Debug, Default)]
struct IntervalBucket {
    total_packets: u64,
    total_l2_bytes: u64,
    src_ips: HashSet<u32>,
    dst_ips: HashSet<u32>,
    flows: HashSet<FlowIdSymmetric>,
}

/// Read-only summary of one completed interval bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntervalSnapshot {
    pub start_timestamp_ns: i64,
    pub end_timestamp_ns_exclusive: i64,
    pub total_packets: u64,
    pub total_l2_bytes: u64,
    pub unique_src_ips: usize,
    pub unique_dst_ips: usize,
    pub unique_flows: usize,
}

/// Exact time-bucket accumulator updated during the capture's packet pass.
///
/// Buckets are aligned to Unix epoch boundaries and stored by start timestamp,
/// so snapshots remain chronological even when capture packets are unordered.
/// Empty intervals are not materialized.
#[derive(Debug)]
pub struct IntervalStats {
    interval_ns: NonZeroU64,
    buckets: BTreeMap<i64, IntervalBucket>,
}

impl IntervalStats {
    pub fn new(interval_ns: NonZeroU64) -> Self {
        Self {
            interval_ns,
            buckets: BTreeMap::new(),
        }
    }

    pub fn interval_ns(&self) -> u64 {
        self.interval_ns.get()
    }

    pub fn update_with_packet(&mut self, timestamp: i64, length: u32) {
        let bucket = self.bucket_mut(timestamp);
        bucket.total_packets += 1;
        bucket.total_l2_bytes += u64::from(length);
    }

    pub fn update_with_metadata(&mut self, metadata: &PacketMetadata) {
        let bucket = self.bucket_mut(metadata.timestamp);
        bucket.src_ips.insert(metadata.src_ip4.unwrap_or(0));
        bucket.dst_ips.insert(metadata.dst_ip4.unwrap_or(0));
        if let Some(flow) = flow_id(metadata) {
            bucket.flows.insert(flow);
        }
    }

    pub fn snapshots(&self) -> impl Iterator<Item = IntervalSnapshot> + '_ {
        let interval_ns = self.interval_ns.get() as i64;
        self.buckets
            .iter()
            .map(move |(&start, bucket)| IntervalSnapshot {
                start_timestamp_ns: start,
                end_timestamp_ns_exclusive: start.saturating_add(interval_ns),
                total_packets: bucket.total_packets,
                total_l2_bytes: bucket.total_l2_bytes,
                unique_src_ips: bucket.src_ips.len(),
                unique_dst_ips: bucket.dst_ips.len(),
                unique_flows: bucket.flows.len(),
            })
    }

    fn bucket_mut(&mut self, timestamp: i64) -> &mut IntervalBucket {
        let interval_ns = self.interval_ns.get() as i64;
        let remainder = timestamp.rem_euclid(interval_ns);
        let start = timestamp.checked_sub(remainder).unwrap_or(i64::MIN);
        self.buckets.entry(start).or_default()
    }
}

/// Location and write time of a completed interval-statistics export.
pub struct IntervalExportResult {
    pub path: PathBuf,
    pub elapsed: Duration,
}

/// Write exact interval statistics to an atomic CSV or Parquet artifact.
pub fn write_interval_stats(
    stats: &IntervalStats,
    output_path: PathBuf,
    format: DumpFormat,
) -> anyhow::Result<IntervalExportResult> {
    let start = Instant::now();
    let interval_seconds = stats.interval_ns() as f64 / 1_000_000_000.0;

    let mut start_timestamp_ns = Vec::new();
    let mut end_timestamp_ns_exclusive = Vec::new();
    let mut total_packets = Vec::new();
    let mut total_l2_bytes = Vec::new();
    let mut packets_per_second = Vec::new();
    let mut bytes_per_second = Vec::new();
    let mut unique_src_ips = Vec::new();
    let mut unique_dst_ips = Vec::new();
    let mut unique_flows = Vec::new();

    for bucket in stats.snapshots() {
        start_timestamp_ns.push(bucket.start_timestamp_ns);
        end_timestamp_ns_exclusive.push(bucket.end_timestamp_ns_exclusive);
        total_packets.push(bucket.total_packets);
        total_l2_bytes.push(bucket.total_l2_bytes);
        packets_per_second.push(bucket.total_packets as f64 / interval_seconds);
        bytes_per_second.push(bucket.total_l2_bytes as f64 / interval_seconds);
        unique_src_ips.push(u64::try_from(bucket.unique_src_ips)?);
        unique_dst_ips.push(u64::try_from(bucket.unique_dst_ips)?);
        unique_flows.push(u64::try_from(bucket.unique_flows)?);
    }

    let mut dataframe = df!(
        "start_timestamp_ns" => start_timestamp_ns,
        "end_timestamp_ns_exclusive" => end_timestamp_ns_exclusive,
        "total_packets" => total_packets,
        "total_l2_bytes" => total_l2_bytes,
        "packets_per_second" => packets_per_second,
        "bytes_per_second" => bytes_per_second,
        "unique_src_ips" => unique_src_ips,
        "unique_dst_ips" => unique_dst_ips,
        "unique_flows" => unique_flows,
    )?;

    let directory = output_directory(&output_path);
    std::fs::create_dir_all(directory)?;
    let mut tempfile = tempfile::NamedTempFile::new_in(directory)?;
    match format {
        DumpFormat::Csv => {
            CsvWriter::new(&mut tempfile)
                .include_header(true)
                .finish(&mut dataframe)?;
        }
        DumpFormat::Parquet => {
            ParquetWriter::new(&mut tempfile).finish(&mut dataframe)?;
        }
    }
    tempfile.flush()?;
    tempfile.persist(&output_path)?;

    Ok(IntervalExportResult {
        path: output_path,
        elapsed: start.elapsed(),
    })
}

fn output_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, net::Ipv4Addr};

    fn stats() -> IntervalStats {
        let mut stats = IntervalStats::new(NonZeroU64::new(1_000_000_000).unwrap());
        stats.update_with_packet(1_100_000_000, 64);
        stats.update_with_packet(1_900_000_000, 128);
        stats
    }

    #[test]
    fn interval_stats_are_epoch_aligned_and_chronological() {
        let mut stats = IntervalStats::new(NonZeroU64::new(1_000_000_000).unwrap());
        for (timestamp, length) in [
            (3_000_000_000, 300),
            (1_900_000_000, 100),
            (1_100_000_000, 200),
        ] {
            stats.update_with_packet(timestamp, length);
        }

        assert_eq!(
            stats.snapshots().collect::<Vec<_>>(),
            vec![
                IntervalSnapshot {
                    start_timestamp_ns: 1_000_000_000,
                    end_timestamp_ns_exclusive: 2_000_000_000,
                    total_packets: 2,
                    total_l2_bytes: 300,
                    unique_src_ips: 0,
                    unique_dst_ips: 0,
                    unique_flows: 0,
                },
                IntervalSnapshot {
                    start_timestamp_ns: 3_000_000_000,
                    end_timestamp_ns_exclusive: 4_000_000_000,
                    total_packets: 1,
                    total_l2_bytes: 300,
                    unique_src_ips: 0,
                    unique_dst_ips: 0,
                    unique_flows: 0,
                },
            ]
        );
    }

    #[test]
    fn interval_stats_count_unique_endpoints_and_symmetric_flows() {
        let mut stats = IntervalStats::new(NonZeroU64::new(1_000_000_000).unwrap());
        for metadata in [
            PacketMetadata {
                timestamp: 1,
                src_ip4: Some(u32::from(Ipv4Addr::new(192, 0, 2, 1))),
                dst_ip4: Some(u32::from(Ipv4Addr::new(198, 51, 100, 2))),
                ip_proto: Some(6),
                src_port: Some(1_234),
                dst_port: Some(80),
                ..Default::default()
            },
            PacketMetadata {
                timestamp: 2,
                src_ip4: Some(u32::from(Ipv4Addr::new(198, 51, 100, 2))),
                dst_ip4: Some(u32::from(Ipv4Addr::new(192, 0, 2, 1))),
                ip_proto: Some(6),
                src_port: Some(80),
                dst_port: Some(1_234),
                ..Default::default()
            },
        ] {
            stats.update_with_packet(metadata.timestamp, 64);
            stats.update_with_metadata(&metadata);
        }

        let bucket = stats.snapshots().next().unwrap();
        assert_eq!(bucket.unique_src_ips, 2);
        assert_eq!(bucket.unique_dst_ips, 2);
        assert_eq!(bucket.unique_flows, 1);
    }

    #[test]
    fn writes_csv_interval_statistics() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("intervals.csv");
        write_interval_stats(&stats(), path.clone(), DumpFormat::Csv)?;

        let contents = std::fs::read_to_string(path)?;
        assert!(contents.starts_with("start_timestamp_ns,end_timestamp_ns_exclusive"));
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.contains("1000000000,2000000000,2,192,2.0,192.0"));
        Ok(())
    }

    #[test]
    fn writes_parquet_interval_statistics() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("intervals.parquet");
        write_interval_stats(&stats(), path.clone(), DumpFormat::Parquet)?;

        let dataframe = ParquetReader::new(File::open(path)?).finish()?;
        assert_eq!(dataframe.height(), 1);
        assert_eq!(dataframe.column("total_packets")?.u64()?.get(0), Some(2));
        Ok(())
    }
}
