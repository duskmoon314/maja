use std::{
    fs::File,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use clap::ValueEnum;
use polars::prelude::*;
use tempfile::TempPath;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DumpFormat {
    Csv,
    Parquet,
}

#[derive(Debug, Default)]
pub struct PacketMetadata {
    pub timestamp: i64,
    pub length: u32,
    pub eth_type: u16,
    pub src_ip4: Option<u32>,
    pub dst_ip4: Option<u32>,
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
}

#[derive(Debug, Default)]
struct PacketMetadataBatch {
    timestamp: Vec<i64>,
    length: Vec<u32>,
    eth_type: Vec<u16>,
    src_ip4: Vec<u32>,
    dst_ip4: Vec<u32>,
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
}

impl PacketMetadataBatch {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            timestamp: Vec::with_capacity(capacity),
            length: Vec::with_capacity(capacity),
            eth_type: Vec::with_capacity(capacity),
            src_ip4: Vec::with_capacity(capacity),
            dst_ip4: Vec::with_capacity(capacity),
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
        }
    }

    fn len(&self) -> usize {
        self.timestamp.len()
    }

    fn push(&mut self, metadata: PacketMetadata) {
        self.timestamp.push(metadata.timestamp);
        self.length.push(metadata.length);
        self.eth_type.push(metadata.eth_type);
        self.src_ip4.push(metadata.src_ip4.unwrap_or(0));
        self.dst_ip4.push(metadata.dst_ip4.unwrap_or(0));
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
    }

    fn into_dataframe(self) -> PolarsResult<DataFrame> {
        df!(
            "timestamp" => self.timestamp,
            "length" => self.length,
            "eth_type" => self.eth_type,
            "src_ip4" => self.src_ip4,
            "dst_ip4" => self.dst_ip4,
            "ip_proto" => self.ip_proto,
            "tos" => self.tos,
            "ttl" => self.ttl,
            "total_length" => self.total_length,
            "src_port" => self.src_port,
            "dst_port" => self.dst_port,
            "tcp_flags" => self.tcp_flags,
            "tcp_window" => self.tcp_window,
            "tcp_data_offset" => self.tcp_data_offset,
            "udp_length" => self.udp_length
        )
    }
}

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

pub struct DumpResult {
    pub path: PathBuf,
    pub format: DumpFormat,
    pub elapsed: Duration,
}

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
    ) -> anyhow::Result<Self> {
        let output_directory = output_directory(&output_path);
        std::fs::create_dir_all(output_directory)?;

        let tempfile = tempfile::NamedTempFile::new_in(output_directory)?;
        let temp_path = tempfile.into_temp_path();
        let file = File::create(&temp_path)?;
        let schema = PacketMetadataBatch::default()
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
            batch: PacketMetadataBatch::with_capacity(batch_size),
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
        let batch = std::mem::replace(
            &mut self.batch,
            PacketMetadataBatch::with_capacity(self.batch_size),
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
            src_ip4: Some(timestamp as u32),
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
        let mut dumper = MetadataDumper::new(output.clone(), DumpFormat::Csv, 2)?;
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
        let mut dumper = MetadataDumper::new(output.clone(), DumpFormat::Parquet, 2)?;
        for timestamp in 1..=5 {
            dumper.push(metadata(timestamp))?;
        }
        dumper.finish()?;

        let dataframe = ParquetReader::new(File::open(output)?).finish()?;
        assert_eq!(dataframe.height(), 5);
        Ok(())
    }
}
