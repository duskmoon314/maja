use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    fs::File,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use maja::{
    capture::{CaptureReader, SniffedReader, link_type::LinkType, packet::PacketRecord},
    packet::{
        Packet,
        layer::ip::v4::{Ipv4, Ipv4Viewer},
    },
};

mod config;
use config::Cli;
use rand::{rngs::StdRng, seq::IndexedRandom};

use crate::config::{ConfigFile, InputFile, MergeArgs};

fn main() -> anyhow::Result<()> {
    let logger = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .build();
    let level = logger.filter();
    let multi = indicatif::MultiProgress::new();
    indicatif_log_bridge::LogWrapper::new(multi.clone(), logger).try_init()?;
    log::set_max_level(level);

    let cli = Cli::parse();

    debug!("CLI: {cli:?}");

    if let Some(ref config_file) = cli.config_file {
        match config_file.extension() {
            Some(ext) if ext == "json" => {
                let config_file = std::fs::File::open(config_file)?;
                let config: ConfigFile = serde_json::from_reader(config_file)?;

                match config {
                    ConfigFile::Single(config) => {
                        let config = cli.config | config;

                        merge(config, &multi)?;
                    }
                    ConfigFile::Multiple(configs) => {
                        info!("Processing {} configs", configs.len());

                        for config in configs {
                            let config = cli.config.clone() | config;

                            merge(config, &multi)?;
                        }
                    }
                }
            }
            _ => {
                return Err(anyhow!("Unsupported config file format: {:?}", config_file));
            }
        }
    } else {
        merge(cli.config, &multi)?;
    }

    Ok(())
}

fn merge(config: config::Config, multi: &indicatif::MultiProgress) -> anyhow::Result<()> {
    let start = Instant::now();

    let output_path = config.output_file.clone().expect("Output file is required");

    let input_files: Vec<_> = config
        .input_files
        .clone()
        .into_iter()
        .flat_map(|i| i.expand_glob().ok())
        .flatten()
        .collect();

    merge_impl(&input_files, &output_path, &config.merge_args, multi)?;

    info!(
        "Merged {} input files into {} in {:.2?}",
        input_files.len(),
        output_path.display(),
        start.elapsed()
    );

    Ok(())
}

fn merge_impl(
    input_files: &[InputFile<PathBuf>],
    output_file: &PathBuf,
    merge_args: &config::MergeArgs,
    multi: &indicatif::MultiProgress,
) -> anyhow::Result<()> {
    let batch_size = merge_args.batch_size.unwrap_or(128);
    if input_files.len() < batch_size {
        // Merge all input files into the output file

        let pg_style = ProgressStyle::with_template(
            "{prefix:3} [{elapsed_precise}] {human_pos:>12} pkts    {msg}",
        )?;

        let write_pg = multi.add(ProgressBar::no_length());
        write_pg.set_style(pg_style.clone());
        write_pg.set_prefix("OUT");
        write_pg.set_message(output_file.display().to_string());
        write_pg.enable_steady_tick(Duration::from_secs(1));

        let mut output_file = std::fs::File::create(output_file)?;

        let total_streams: usize = input_files.iter().map(|f| f.parallel as usize).sum();
        let mut packet_heap: BinaryHeap<Reverse<(PacketRecord<'static>, usize)>> =
            BinaryHeap::with_capacity(total_streams);

        let mut readers = input_files
            .iter()
            .map(|input_file| {
                let pg = multi.add(ProgressBar::no_length());
                pg.set_style(pg_style.clone());
                pg.set_prefix("IN");
                pg.set_message(input_file.path.display().to_string());
                pg.enable_steady_tick(Duration::from_secs(1));

                PacketReader::from_input_file(input_file.clone(), pg, merge_args).unwrap_or_else(
                    |e| {
                        error!(
                            "Failed to create PacketReader for {}: {}",
                            input_file.path.display(),
                            e
                        );
                        panic!();
                    },
                )
            })
            .collect::<Vec<_>>();

        for (i, reader) in readers.iter_mut().enumerate() {
            if let Some(packets) = reader.next() {
                packet_heap.extend(packets.into_iter().map(|p| Reverse((p, i))));
            }
        }

        // We assume all input files have the same link type
        let link_type = packet_heap
            .peek()
            .map(|Reverse((p, _))| p.link_type)
            .unwrap_or(LinkType::Ethernet);

        let mut pcap_writer = maja::capture::format::pcap::PcapWriter::new(
            &mut output_file,
            false,
            merge_args.nanosecond.unwrap_or_default(),
            merge_args.snap_len.unwrap_or(65535),
            link_type,
        )?;

        while let Some(Reverse((packet, reader_index))) = packet_heap.pop() {
            pcap_writer.write_packet(&packet)?;
            write_pg.inc(1);

            // Pull next packet only if heap size drops below total_streams
            if packet_heap.len() < total_streams
                && let Some(packets) = readers[reader_index].next()
            {
                packet_heap.extend(packets.into_iter().map(|p| Reverse((p, reader_index))));
            }
        }

        pcap_writer.flush()?;
        write_pg.finish_with_message("Done");
    } else {
        let tmp_dir = tempfile::tempdir()?;

        let batches = input_files.chunks(batch_size);

        let mut tmp_files = Vec::new();

        for (i, batch) in batches.enumerate() {
            let tmp_file = tmp_dir.path().join(format!("batch_{i}.pcap"));

            merge_impl(batch, &tmp_file, merge_args, multi)?;
            tmp_files.push(tmp_file);
        }

        let tmp_files: Vec<_> = tmp_files
            .into_iter()
            .map(|p| InputFile {
                path: p,
                ..Default::default()
            })
            .collect();

        merge_impl(&tmp_files, output_file, merge_args, multi)?;
    }

    Ok(())
}

struct PacketReader {
    file: InputFile<PathBuf>,
    reader: SniffedReader<File>,

    current: u32,

    original_first_packet_time: Option<i64>,
    first_packet_time: Option<i64>,
    last_packet_time: i64,

    erase_timestamp: bool,
    keep_subsecond: bool,

    pg: ProgressBar,
    rng: StdRng,

    src_ip4_pool: Vec<Ipv4Addr>,
    dst_ip4_pool: Vec<Ipv4Addr>,
    src_ip_maps: Vec<(ipnet::IpNet, ipnet::IpNet)>,
    dst_ip_maps: Vec<(ipnet::IpNet, ipnet::IpNet)>,
}

impl PacketReader {
    fn from_input_file(
        file: InputFile<PathBuf>,
        pg: ProgressBar,
        merge_args: &MergeArgs,
    ) -> anyhow::Result<Self> {
        let reader = SniffedReader::open(&file.path)?;

        let rng = rand::make_rng();

        let src_ip4_pool = file
            .src_ip_map
            .iter()
            .chain(file.ip_map.iter())
            .filter_map(|m| match m {
                config::IpMap::Ip(IpAddr::V4(ip)) => Some(ipnet::Ipv4AddrRange::new(*ip, *ip)),
                config::IpMap::Net(ipnet::IpNet::V4(net)) => Some(net.hosts()),
                _ => None,
            })
            .flatten()
            .collect();

        let dst_ip4_pool = file
            .dst_ip_map
            .iter()
            .chain(file.ip_map.iter())
            .filter_map(|m| match m {
                config::IpMap::Ip(IpAddr::V4(ip)) => Some(ipnet::Ipv4AddrRange::new(*ip, *ip)),
                config::IpMap::Net(ipnet::IpNet::V4(net)) => Some(net.hosts()),
                _ => None,
            })
            .flatten()
            .collect();

        let mut src_ip_maps: Vec<_> = file
            .src_ip_map
            .iter()
            .chain(file.ip_map.iter())
            .filter_map(|m| match m {
                config::IpMap::Map(from, to) => Some((*from, *to)),
                _ => None,
            })
            .collect();
        src_ip_maps.sort_by_key(|(from, _)| u8::MAX - from.prefix_len());

        let mut dst_ip_maps: Vec<_> = file
            .dst_ip_map
            .iter()
            .chain(file.ip_map.iter())
            .filter_map(|m| match m {
                config::IpMap::Map(from, to) => Some((*from, *to)),
                _ => None,
            })
            .collect();
        dst_ip_maps.sort_by_key(|(from, _)| u8::MAX - from.prefix_len());

        Ok(Self {
            file,
            reader,
            current: 0,
            original_first_packet_time: None,
            first_packet_time: None,
            last_packet_time: 0,
            erase_timestamp: merge_args.erase_timestamp.unwrap_or(false),
            keep_subsecond: merge_args.keep_subsecond.unwrap_or(false),
            pg,
            rng,
            src_ip4_pool,
            dst_ip4_pool,
            src_ip_maps,
            dst_ip_maps,
        })
    }

    fn rewrite_ipv4(&mut self, ipv4: &mut Ipv4Viewer<&mut [u8]>) {
        // Handle source IP mapping
        let mut src_mapped = false;
        for (from_net, to_net) in &self.src_ip_maps {
            if let (ipnet::IpNet::V4(from_net), ipnet::IpNet::V4(to_net)) = (from_net, to_net) {
                let current_ip = ipv4.src().get();
                if from_net.contains(&current_ip) {
                    let to_network = to_net.network();
                    let to_hostmask = to_net.hostmask();
                    let host_part = current_ip & to_hostmask;
                    let new_ip = to_network | host_part;
                    ipv4.src_mut().set(new_ip);
                    src_mapped = true;
                    break;
                }
            }
        }

        // If not mapped, use random selection from src_ip_pool
        if !src_mapped && !self.src_ip4_pool.is_empty() {
            let src_ip = self.src_ip4_pool.choose(&mut self.rng).unwrap();
            ipv4.src_mut().set(*src_ip);
        }

        // Handle destination IP mapping
        let mut dst_mapped = false;
        for (from_net, to_net) in &self.dst_ip_maps {
            if let (ipnet::IpNet::V4(from_net), ipnet::IpNet::V4(to_net)) = (from_net, to_net) {
                let current_ip = ipv4.dst().get();
                if from_net.contains(&current_ip) {
                    let to_network = to_net.network();
                    let to_hostmask = to_net.hostmask();
                    let host_part = current_ip & to_hostmask;
                    let new_ip = to_network | host_part;
                    ipv4.dst_mut().set(new_ip);
                    dst_mapped = true;
                    break;
                }
            }
        }

        // If not mapped, use random selection from dst_ip_pool
        if !dst_mapped && !self.dst_ip4_pool.is_empty() {
            let dst_ip = self.dst_ip4_pool.choose(&mut self.rng).unwrap();
            ipv4.dst_mut().set(*dst_ip);
        }
    }
}

impl Iterator for PacketReader {
    type Item = Vec<PacketRecord<'static>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut packet = loop {
            match self.reader.next_packet() {
                Ok(Some(packet)) => {
                    break packet.to_owned();
                }
                Ok(None) => {
                    self.current += 1;

                    if self.current == self.file.start_time.len() as u32 * self.file.repeat {
                        self.pg
                            .finish_with_message(format!("{} done", self.file.path.display()));
                        return None;
                    }

                    // Start next group
                    self.reader =
                        SniffedReader::open(&self.file.path).expect("Failed to open input file");
                    self.first_packet_time = None;
                }
                Err(e) => {
                    error!(
                        "Error reading packet from {}: {}",
                        self.file.path.display(),
                        e
                    );
                    continue;
                }
            }
        };

        let timestamp = packet.timestamp;

        if let Some(first_packet_time) = self.first_packet_time {
            // Same group and same repeat subgroup
            // Calculate the time
            let current_packet_time = timestamp
                - self
                    .original_first_packet_time
                    .expect("Original first packet time should be set")
                + first_packet_time;
            packet.timestamp = current_packet_time;
        } else {
            // A new start of pcap
            self.original_first_packet_time = Some(timestamp);

            let new_timestamp;
            if self.current.is_multiple_of(self.file.repeat) {
                // A new group, use the related start time
                if self.erase_timestamp {
                    let base_time = self.file.start_time[(self.current / self.file.repeat) as usize]
                        as i64
                        * 1_000_000_000;

                    // If keep_subsecond, preserve the subsecond of the original timestamp
                    if self.keep_subsecond {
                        let subsec = timestamp % 1_000_000_000;
                        new_timestamp = base_time + subsec;
                    } else {
                        new_timestamp = base_time;
                    }
                } else {
                    new_timestamp = timestamp
                        + self.file.start_time[(self.current / self.file.repeat) as usize] as i64
                            * 1_000_000_000;
                }
            } else {
                // Same group, repeating with 1 second interval
                //
                // TODO: make this configurable
                new_timestamp = self.last_packet_time + 1_000_000_000;
            }

            self.first_packet_time = Some(new_timestamp);
            packet.timestamp = new_timestamp;
        }

        self.last_packet_time = packet.timestamp;
        self.pg.inc(1);

        let mut items = vec![packet; self.file.parallel as usize];

        if self.src_ip4_pool.is_empty()
            && self.dst_ip4_pool.is_empty()
            && self.src_ip_maps.is_empty()
            && self.dst_ip_maps.is_empty()
        {
            return Some(items);
        }

        for item in items.iter_mut() {
            let mut packet = Packet::new(item.data.to_mut());

            if let Err(err) = packet.try_parse_with_link_type(item.link_type, Default::default()) {
                warn!("{err}");
            }

            if let Some(mut ipv4) = packet.layer_viewer_mut(Ipv4) {
                self.rewrite_ipv4(&mut ipv4);
            }
        }

        Some(items)
    }
}
