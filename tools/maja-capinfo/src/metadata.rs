use std::{
    fs::File,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use clap::ValueEnum;
use polars::prelude::*;
use serde::Serialize;
use tempfile::TempPath;

/// File formats supported by the per-packet metadata export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DumpFormat {
    /// Comma-separated values with one header row.
    Csv,
    /// Apache Parquet.
    Parquet,
}

impl DumpFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Parquet => "parquet",
        }
    }
}

/// Metadata extracted from one successfully parsed packet.
#[derive(Debug, Default)]
pub struct PacketMetadata {
    pub timestamp: i64,
    pub length: u32,
    pub eth_type: u16,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub ip_proto: Option<u8>,
    pub tos: Option<u8>,
    pub ttl: Option<u8>,
    pub total_length: Option<u16>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u8>,
    pub tcp_window: Option<u16>,
    pub tcp_data_offset: Option<u8>,
    pub udp_length: Option<u16>,
    pub ipv6_payload_length: Option<u16>,
}

/// Column-oriented packet buffer converted into one Polars `DataFrame` batch.
///
/// Its vectors never exceed the configured batch size.
#[derive(Debug, Default)]
struct PacketMetadataBatch {
    timestamp: Vec<i64>,
    length: Vec<u32>,
    eth_type: Vec<u16>,
    src_ip: Vec<Option<String>>,
    dst_ip: Vec<Option<String>>,
    src_ip4: Vec<Option<u32>>,
    dst_ip4: Vec<Option<u32>>,
    src_ip6: Vec<Option<u128>>,
    dst_ip6: Vec<Option<u128>>,
    ip_proto: Vec<u8>,
    tos: Vec<u8>,
    ttl: Vec<u8>,
    total_length: Vec<u16>,
    src_port: Vec<u16>,
    dst_port: Vec<u16>,
    tcp_flags: Vec<u8>,
    tcp_window: Vec<u16>,
    tcp_data_offset: Vec<u8>,
    udp_length: Vec<u16>,
    ipv6_payload_length: Vec<u16>,
    /// Whether the numeric `*_ip4`/`*_ip6` columns are populated and exported.
    numeric_ip: bool,
}

impl PacketMetadataBatch {
    fn with_capacity(capacity: usize, numeric_ip: bool) -> Self {
        let numeric_capacity = if numeric_ip { capacity } else { 0 };
        Self {
            timestamp: Vec::with_capacity(capacity),
            length: Vec::with_capacity(capacity),
            eth_type: Vec::with_capacity(capacity),
            src_ip: Vec::with_capacity(capacity),
            dst_ip: Vec::with_capacity(capacity),
            src_ip4: Vec::with_capacity(numeric_capacity),
            dst_ip4: Vec::with_capacity(numeric_capacity),
            src_ip6: Vec::with_capacity(numeric_capacity),
            dst_ip6: Vec::with_capacity(numeric_capacity),
            ip_proto: Vec::with_capacity(capacity),
            tos: Vec::with_capacity(capacity),
            ttl: Vec::with_capacity(capacity),
            total_length: Vec::with_capacity(capacity),
            src_port: Vec::with_capacity(capacity),
            dst_port: Vec::with_capacity(capacity),
            tcp_flags: Vec::with_capacity(capacity),
            tcp_window: Vec::with_capacity(capacity),
            tcp_data_offset: Vec::with_capacity(capacity),
            udp_length: Vec::with_capacity(capacity),
            ipv6_payload_length: Vec::with_capacity(capacity),
            numeric_ip,
        }
    }

    fn len(&self) -> usize {
        self.timestamp.len()
    }

    fn push(&mut self, metadata: PacketMetadata) {
        self.timestamp.push(metadata.timestamp);
        self.length.push(metadata.length);
        self.eth_type.push(metadata.eth_type);
        self.src_ip
            .push(metadata.src_ip.map(|address| address.to_string()));
        self.dst_ip
            .push(metadata.dst_ip.map(|address| address.to_string()));
        if self.numeric_ip {
            let (src_ip4, src_ip6) = numeric_ip(metadata.src_ip);
            let (dst_ip4, dst_ip6) = numeric_ip(metadata.dst_ip);
            self.src_ip4.push(src_ip4);
            self.dst_ip4.push(dst_ip4);
            self.src_ip6.push(src_ip6);
            self.dst_ip6.push(dst_ip6);
        }
        self.ip_proto.push(metadata.ip_proto.unwrap_or(0));
        self.tos.push(metadata.tos.unwrap_or(0));
        self.ttl.push(metadata.ttl.unwrap_or(0));
        self.total_length.push(metadata.total_length.unwrap_or(0));
        self.src_port.push(metadata.src_port.unwrap_or(0));
        self.dst_port.push(metadata.dst_port.unwrap_or(0));
        self.tcp_flags.push(metadata.tcp_flags.unwrap_or(0));
        self.tcp_window.push(metadata.tcp_window.unwrap_or(0));
        self.tcp_data_offset
            .push(metadata.tcp_data_offset.unwrap_or(0));
        self.udp_length.push(metadata.udp_length.unwrap_or(0));
        self.ipv6_payload_length
            .push(metadata.ipv6_payload_length.unwrap_or(0));
    }

    fn into_dataframe(self) -> PolarsResult<DataFrame> {
        let mut dataframe = df!(
            "timestamp" => self.timestamp,
            "length" => self.length,
            "eth_type" => self.eth_type,
            "src_ip" => self.src_ip,
            "dst_ip" => self.dst_ip,
            "ip_proto" => self.ip_proto,
            "tos" => self.tos,
            "ttl" => self.ttl,
            "total_length" => self.total_length,
            "src_port" => self.src_port,
            "dst_port" => self.dst_port,
            "tcp_flags" => self.tcp_flags,
            "tcp_window" => self.tcp_window,
            "tcp_data_offset" => self.tcp_data_offset,
            "udp_length" => self.udp_length,
            "ipv6_payload_length" => self.ipv6_payload_length,
        )?;

        if self.numeric_ip {
            dataframe.hstack_mut(&[
                Column::new("src_ip4".into(), self.src_ip4),
                Column::new("dst_ip4".into(), self.dst_ip4),
                Column::new("src_ip6".into(), self.src_ip6),
                Column::new("dst_ip6".into(), self.dst_ip6),
            ])?;
        }

        Ok(dataframe)
    }
}

/// Split an IP address into its numeric IPv4 (u32) or IPv6 (u128) form.
fn numeric_ip(address: Option<IpAddr>) -> (Option<u32>, Option<u128>) {
    match address {
        Some(IpAddr::V4(address)) => (Some(u32::from(address)), None),
        Some(IpAddr::V6(address)) => (None, Some(u128::from(address))),
        None => (None, None),
    }
}

/// Type-erased adapter over the Polars CSV and Parquet batched writers.
enum BatchWriter {
    Csv(Box<polars::io::csv::write::BatchedWriter<File>>),
    Parquet(Box<polars::io::parquet::write::BatchedWriter<File>>),
}

impl BatchWriter {
    fn write_batch(&mut self, dataframe: &DataFrame) -> PolarsResult<()> {
        match self {
            Self::Csv(writer) => writer.write_batch(dataframe),
            Self::Parquet(writer) => writer.write_batch(dataframe),
        }
    }

    fn finish(&mut self) -> PolarsResult<()> {
        match self {
            Self::Csv(writer) => writer.finish(),
            Self::Parquet(writer) => writer.finish().map(|_| ()),
        }
    }
}

/// Description and measured write time of a completed metadata export.
pub struct DumpResult {
    pub path: PathBuf,
    pub format: DumpFormat,
    pub elapsed: Duration,
}

/// Packet metadata exporter.
pub struct MetadataDumper {
    writer: BatchWriter,
    batch: PacketMetadataBatch,
    batch_size: usize,
    temp_path: TempPath,
    output_path: PathBuf,
    format: DumpFormat,
    elapsed: Duration,
}

impl MetadataDumper {
    pub fn new(
        output_path: PathBuf,
        format: DumpFormat,
        batch_size: usize,
        numeric_ip: bool,
    ) -> anyhow::Result<Self> {
        let output_directory = output_directory(&output_path);
        std::fs::create_dir_all(output_directory)?;

        let tempfile = tempfile::NamedTempFile::new_in(output_directory)?;
        let temp_path = tempfile.into_temp_path();
        let file = File::create(&temp_path)?;
        let schema = PacketMetadataBatch::with_capacity(0, numeric_ip)
            .into_dataframe()?
            .schema()
            .clone();
        let writer = match format {
            DumpFormat::Csv => BatchWriter::Csv(Box::new(
                CsvWriter::new(file).include_header(true).batched(&schema)?,
            )),
            DumpFormat::Parquet => {
                BatchWriter::Parquet(Box::new(ParquetWriter::new(file).batched(&schema)?))
            }
        };

        Ok(Self {
            writer,
            batch: PacketMetadataBatch::with_capacity(batch_size, numeric_ip),
            batch_size,
            temp_path,
            output_path,
            format,
            elapsed: Duration::ZERO,
        })
    }

    pub fn push(&mut self, metadata: PacketMetadata) -> anyhow::Result<()> {
        self.batch.push(metadata);
        if self.batch.len() == self.batch_size {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        if self.batch.len() == 0 {
            return Ok(());
        }

        let start = Instant::now();
        let numeric_ip = self.batch.numeric_ip;
        let batch = std::mem::replace(
            &mut self.batch,
            PacketMetadataBatch::with_capacity(self.batch_size, numeric_ip),
        );
        let dataframe = batch.into_dataframe()?;
        self.writer.write_batch(&dataframe)?;
        self.elapsed += start.elapsed();
        Ok(())
    }

    pub fn finish(mut self) -> anyhow::Result<DumpResult> {
        self.flush()?;
        let start = Instant::now();
        self.writer.finish()?;
        self.elapsed += start.elapsed();

        let Self {
            writer,
            temp_path,
            output_path,
            format,
            mut elapsed,
            ..
        } = self;
        drop(writer);

        let start = Instant::now();
        temp_path.persist(&output_path)?;
        elapsed += start.elapsed();

        Ok(DumpResult {
            path: output_path,
            format,
            elapsed,
        })
    }
}

fn output_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(timestamp: i64) -> PacketMetadata {
        PacketMetadata {
            timestamp,
            length: 64,
            src_ip: Some(IpAddr::V4(std::net::Ipv4Addr::from(timestamp as u32))),
            ..Default::default()
        }
    }

    #[test]
    fn relative_output_uses_current_directory() {
        assert_eq!(output_directory(Path::new("packets.csv")), Path::new("."));
    }

    #[test]
    fn csv_dumper_flushes_multiple_batches() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let output = dir.path().join("packets.csv");
        let mut dumper = MetadataDumper::new(output.clone(), DumpFormat::Csv, 2, false)?;
        for timestamp in 1..=5 {
            dumper.push(metadata(timestamp))?;
        }
        dumper.finish()?;

        let contents = std::fs::read_to_string(output)?;
        assert_eq!(contents.lines().count(), 6);
        assert_eq!(contents.matches("timestamp").count(), 1);
        Ok(())
    }

    #[test]
    fn parquet_dumper_flushes_multiple_batches() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let output = dir.path().join("packets.parquet");
        let mut dumper = MetadataDumper::new(output.clone(), DumpFormat::Parquet, 2, false)?;
        for timestamp in 1..=5 {
            dumper.push(metadata(timestamp))?;
        }
        dumper.finish()?;

        let dataframe = ParquetReader::new(File::open(output)?).finish()?;
        assert_eq!(dataframe.height(), 5);
        Ok(())
    }

    #[test]
    fn metadata_dump_uses_canonical_ipv6_addresses() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let output = dir.path().join("packets.csv");
        let mut dumper = MetadataDumper::new(output.clone(), DumpFormat::Csv, 1, false)?;
        dumper.push(PacketMetadata {
            timestamp: 1,
            src_ip: Some("2001:db8::1".parse()?),
            dst_ip: Some("::1".parse()?),
            tos: Some(42),
            ttl: Some(64),
            ..Default::default()
        })?;
        dumper.finish()?;

        let contents = std::fs::read_to_string(output)?;
        assert!(contents.contains("src_ip,dst_ip,ip_proto"));
        assert!(contents.contains("2001:db8::1,::1"));
        Ok(())
    }

    #[test]
    fn parquet_dump_preserves_missing_ips_as_null() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let output = dir.path().join("packets.parquet");
        let mut dumper = MetadataDumper::new(output.clone(), DumpFormat::Parquet, 1, false)?;
        dumper.push(PacketMetadata::default())?;
        dumper.finish()?;

        let dataframe = ParquetReader::new(File::open(output)?).finish()?;
        assert_eq!(dataframe.column("src_ip")?.str()?.get(0), None);
        assert_eq!(dataframe.column("dst_ip")?.str()?.get(0), None);
        Ok(())
    }

    #[test]
    fn numeric_ip_dump_appends_numeric_columns() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let output = dir.path().join("packets.csv");
        let mut dumper = MetadataDumper::new(output.clone(), DumpFormat::Csv, 1, true)?;
        dumper.push(PacketMetadata {
            timestamp: 1,
            src_ip: Some("1.2.3.4".parse()?),
            dst_ip: Some("2001:db8::1".parse()?),
            ..Default::default()
        })?;
        dumper.finish()?;

        let contents = std::fs::read_to_string(output)?;
        assert!(contents.contains("src_ip,dst_ip,ip_proto"));
        assert!(contents.contains("src_ip4,dst_ip4,src_ip6,dst_ip6"));
        // 1.2.3.4 as u32, then empty dst_ip4 and src_ip6, then 2001:db8::1 as u128
        assert!(contents.contains(&format!(
            "{},,,{}",
            u32::from(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            u128::from("2001:db8::1".parse::<std::net::Ipv6Addr>()?)
        )));
        Ok(())
    }

    #[test]
    fn numeric_ip_parquet_columns_use_unsigned_dtypes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let output = dir.path().join("packets.parquet");
        let mut dumper = MetadataDumper::new(output.clone(), DumpFormat::Parquet, 1, true)?;
        dumper.push(PacketMetadata {
            src_ip: Some("1.2.3.4".parse()?),
            dst_ip: Some("::1".parse()?),
            ..Default::default()
        })?;
        dumper.finish()?;

        let dataframe = ParquetReader::new(File::open(output)?).finish()?;
        assert_eq!(
            dataframe.column("src_ip4")?.u32()?.get(0),
            Some(u32::from(std::net::Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(dataframe.column("src_ip6")?.u128()?.get(0), None);
        assert_eq!(dataframe.column("dst_ip4")?.u32()?.get(0), None);
        assert_eq!(
            dataframe.column("dst_ip6")?.u128()?.get(0),
            Some(u128::from(std::net::Ipv6Addr::LOCALHOST))
        );
        Ok(())
    }
}
