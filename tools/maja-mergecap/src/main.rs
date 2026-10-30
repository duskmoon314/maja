use std::{
    collections::BinaryHeap,
    fs::File,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use maja::{
    capture::{CaptureReader, SniffedReader, link_type::LinkType, packet::PacketRecord},
    packet::Packet,
};
use rand::{RngExt, rngs::StdRng};

mod config;
mod map;

use config::{Cli, ConfigFile, InputFile, MergeArgs};
use map::{MapRuntime, Rewriter, derived_rng};

/// Salt used to derive the jitter rng from the per-file seed.
///
/// The second word of SHA-512's initial hash value (`frac(sqrt 3)`), so that
/// the jitter offsets come from a stream of their own and turning jitter on or
/// off leaves the address mapping untouched.
const JITTER_RNG_SALT: u64 = 0xbb67_ae85_84ca_a73b;

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

    let Some(output_path) = config.output_file.clone() else {
        return Err(anyhow!(
            "no output file: pass `-o <FILE>` or set `output_file`"
        ));
    };

    let input_files: Vec<_> = {
        let mut input_files = Vec::new();
        for input_file in &config.input_files {
            let expanded = input_file.clone().expand_glob()?;
            if expanded.is_empty() {
                warn!("{}: no input file matches this pattern", input_file.path);
            }
            input_files.extend(expanded);
        }

        input_files
    };

    for input_file in &input_files {
        input_file
            .validate()
            .with_context(|| format!("invalid configuration of {:?}", input_file.path))?;
    }

    // One seed for the whole run: the `hash` policy and a `global` allocation
    // scope must not depend on which file a packet came from.
    let global_seed = match config.merge_args.seed {
        Some(seed) => seed,
        None => rand::make_rng::<StdRng>().random(),
    };

    let mut runtime = MapRuntime::new();
    merge_impl(
        &input_files,
        &output_path,
        &config.merge_args,
        global_seed,
        0,
        &mut runtime,
        multi,
    )?;

    info!(
        "Merged {} input files into {} in {:.2?}",
        input_files.len(),
        output_path.display(),
        start.elapsed()
    );

    Ok(())
}

/// `first_index` is the position of `input_files[0]` in the whole merge, so that a
/// batched merge derives the same per-file seed as an unbatched one.
fn merge_impl(
    input_files: &[InputFile<PathBuf>],
    output_file: &PathBuf,
    merge_args: &config::MergeArgs,
    global_seed: u64,
    first_index: usize,
    runtime: &mut MapRuntime,
    multi: &indicatif::MultiProgress,
) -> anyhow::Result<()> {
    let batch_size = merge_args.batch_size.unwrap_or(128);
    if input_files.len() <= batch_size {
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

        let mut readers = input_files
            .iter()
            .enumerate()
            .map(|(index, input_file)| {
                let pg = multi.add(ProgressBar::no_length());
                pg.set_style(pg_style.clone());
                pg.set_prefix("IN");
                pg.set_message(input_file.path.display().to_string());
                pg.enable_steady_tick(Duration::from_secs(1));

                PacketReader::from_input_file(
                    input_file.clone(),
                    first_index + index,
                    merge_args,
                    global_seed,
                    runtime,
                    pg,
                )
                .with_context(|| format!("failed to read {}", input_file.path.display()))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        // We assume all input files have the same link type
        let link_type = readers
            .first()
            .map(|reader| reader.link_type())
            .unwrap_or(LinkType::Ethernet);

        let mut pcap_writer = maja::capture::format::pcap::PcapWriter::new(
            &mut output_file,
            false,
            merge_args.nanosecond.unwrap_or_default(),
            merge_args.snap_len.unwrap_or(65535),
            link_type,
        )?;

        // Each reader yields one batch per input packet holding the packets of
        // every parallel group; those share their base timestamp but may be
        // spread by the parallel jitter.
        let mut streams: Vec<_> = readers
            .iter_mut()
            .map(|reader| {
                reader.map(|batch| {
                    batch
                        .into_iter()
                        .map(|packet| (packet.timestamp, packet))
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        merge_batches(&mut streams, |packet| {
            pcap_writer.write_packet(&packet)?;
            write_pg.inc(1);

            Ok(())
        })?;

        pcap_writer.flush()?;
        write_pg.finish_with_message("Done");
    } else {
        // Batching only helps if each round strictly reduces the number of
        // files to merge; batch_size 1 would recurse forever.
        if batch_size < 2 {
            return Err(anyhow!(
                "batch size must be at least 2 when merging more files than the batch size"
            ));
        }

        let tmp_dir = tempfile::tempdir()?;

        let batches = input_files.chunks(batch_size);

        let mut tmp_files = Vec::new();

        for (i, batch) in batches.enumerate() {
            let tmp_file = tmp_dir.path().join(format!("batch_{i}.pcap"));

            // The per-file start times and the erased timeline have to be applied
            // here, so the batch file holds the final timeline.
            merge_impl(
                batch,
                &tmp_file,
                merge_args,
                global_seed,
                first_index + i * batch_size,
                runtime,
                multi,
            )?;
            tmp_files.push(tmp_file);
        }

        let tmp_files: Vec<_> = tmp_files
            .into_iter()
            .map(|p| InputFile {
                path: p,
                ..Default::default()
            })
            .collect();

        // Erasing the timestamps again would restart every batch at its own
        // `start_time` and collapse the merged timeline.
        let final_args = config::MergeArgs {
            erase_timestamp: Some(false),
            ..merge_args.clone()
        };
        merge_impl(
            &tmp_files,
            output_file,
            &final_args,
            global_seed,
            first_index,
            runtime,
            multi,
        )?;
    }

    Ok(())
}

/// One entry of the merge heap.
///
/// Ordering is reversed so that a [`BinaryHeap`] pops the smallest timestamp
/// first; ties are broken by the reader index to keep the merge deterministic
/// while never requiring `T: Ord`.
struct HeapEntry<T> {
    timestamp: i64,
    reader: usize,
    value: T,
}

impl<T> PartialEq for HeapEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp && self.reader == other.reader
    }
}

impl<T> Eq for HeapEntry<T> {}

impl<T> PartialOrd for HeapEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for HeapEntry<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .timestamp
            .cmp(&self.timestamp)
            .then_with(|| other.reader.cmp(&self.reader))
    }
}

/// Read the next batch of `index` into the heap.
///
/// A batch holds the packets of every parallel group of one input packet, so its
/// minimum timestamp is a lower bound of everything this reader still has.
/// `in_flight` counts the packets of the reader that are in the heap, so reading
/// ahead adds to it; the reader is finished when the lower bound is `i64::MAX`.
fn pull<R, T>(
    index: usize,
    streams: &mut [R],
    heap: &mut BinaryHeap<HeapEntry<T>>,
    in_flight: &mut [usize],
    lower_bound: &mut [i64],
) where
    R: Iterator<Item = Vec<(i64, T)>>,
{
    match streams[index].next() {
        Some(batch) if !batch.is_empty() => {
            lower_bound[index] = batch
                .iter()
                .map(|(timestamp, _)| *timestamp)
                .min()
                .unwrap_or(i64::MAX);
            in_flight[index] += batch.len();
            heap.extend(batch.into_iter().map(|(timestamp, value)| HeapEntry {
                timestamp,
                reader: index,
                value,
            }));
        }
        _ => {
            // Finished: keep the count of the packets still in the heap.
            lower_bound[index] = i64::MAX;
        }
    }
}

/// Merge batches of already time-sorted streams, calling `emit` in
/// non-decreasing timestamp order.
///
/// A stream is only *base* sorted: the packets of one batch share their base
/// timestamp, but a parallel jitter may spread them, so a batch can end later
/// than the next batch of the same stream starts. A packet is therefore only
/// emitted once every exhausted stream has been read far enough that it cannot
/// still hold an earlier packet.
fn merge_batches<R, T, F>(streams: &mut [R], mut emit: F) -> anyhow::Result<()>
where
    R: Iterator<Item = Vec<(i64, T)>>,
    F: FnMut(T) -> anyhow::Result<()>,
{
    let reader_count = streams.len();
    let mut heap: BinaryHeap<HeapEntry<T>> = BinaryHeap::with_capacity(reader_count);
    let mut in_flight = vec![0usize; reader_count];
    let mut lower_bound = vec![i64::MIN; reader_count];

    loop {
        let Some(entry) = heap.pop() else {
            // Nothing buffered: keep reading as long as some stream is not
            // exhausted yet.
            let mut pulled = false;
            for index in 0..reader_count {
                if in_flight[index] == 0 && lower_bound[index] != i64::MAX {
                    pull(index, streams, &mut heap, &mut in_flight, &mut lower_bound);
                    pulled = true;
                }
            }

            if !pulled {
                return Ok(());
            }
            continue;
        };

        in_flight[entry.reader] -= 1;

        // Read ahead until every stream is known not to hold an earlier packet
        // than the one about to be emitted. A stream can still have packets in
        // the heap and yet have unread ones that come earlier, so this must not
        // wait for the current batch to be drained.
        loop {
            let mut pulled = false;
            for index in 0..reader_count {
                if lower_bound[index] < entry.timestamp {
                    pull(index, streams, &mut heap, &mut in_flight, &mut lower_bound);
                    pulled = true;
                }
            }

            if !pulled {
                break;
            }
        }

        // The refill may have revealed an earlier packet; put this one back.
        let earlier = heap
            .peek()
            .is_some_and(|next| next.timestamp < entry.timestamp);
        if earlier {
            in_flight[entry.reader] += 1;
            heap.push(entry);
            continue;
        }

        emit(entry.value)?;
    }
}

struct PacketReader {
    file: InputFile<PathBuf>,
    reader: SniffedReader<File>,

    current: usize,

    original_first_packet_time: Option<i64>,
    first_packet_time: Option<i64>,
    last_packet_time: i64,

    erase_timestamp: bool,
    keep_subsecond: bool,
    repeat_interval: i64,

    parallel: usize,
    jitter: Vec<i64>,

    pg: ProgressBar,

    rewriter: Rewriter,
}

impl PacketReader {
    fn from_input_file(
        file: InputFile<PathBuf>,
        index: usize,
        merge_args: &MergeArgs,
        global_seed: u64,
        runtime: &mut MapRuntime,
        pg: ProgressBar,
    ) -> anyhow::Result<Self> {
        let reader = SniffedReader::open(&file.path)?;

        // Everything per file is derived from the global seed, so a `--seed`
        // reproduces the whole run and the files stay independent.
        let seed = global_seed.wrapping_add(index as u64);
        if merge_args.seed.is_some() {
            info!("{}: using seed {seed}", file.path.display());
        }

        let parallel = file.parallel() as usize;

        // One constant offset per parallel group; group 0 keeps the original
        // timeline and the offsets are reused for every repeat.
        let jitter = {
            let jitter_ns = file.parallel_jitter_ns();
            let mut rng = derived_rng(seed, JITTER_RNG_SALT);
            (0..parallel)
                .map(|group| {
                    if group == 0 || jitter_ns == 0 {
                        0
                    } else {
                        rng.random_range(0..jitter_ns) as i64
                    }
                })
                .collect()
        };

        let rewriter = Rewriter::new(
            &file,
            runtime,
            seed,
            global_seed,
            parallel,
            merge_args.fix_checksum(),
        )?;
        let repeat_interval = file.repeat_interval_ns();

        Ok(Self {
            file,
            reader,
            current: 0,
            original_first_packet_time: None,
            first_packet_time: None,
            last_packet_time: 0,
            erase_timestamp: merge_args.erase_timestamp.unwrap_or(false),
            keep_subsecond: merge_args.keep_subsecond.unwrap_or(false),
            repeat_interval,
            parallel,
            jitter,
            pg,
            rewriter,
        })
    }

    fn link_type(&self) -> LinkType {
        self.reader
            .interfaces()
            .first()
            .map(|interface| interface.link_type)
            .unwrap_or(LinkType::Ethernet)
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

                    if self.current
                        == self.file.start_time().len()
                            * usize::try_from(self.file.repeat()).unwrap_or(usize::MAX)
                    {
                        self.pg
                            .finish_with_message(format!("{} done", self.file.path.display()));
                        return None;
                    }

                    // Start next group
                    match SniffedReader::open(&self.file.path) {
                        Ok(reader) => self.reader = reader,
                        Err(err) => {
                            error!(
                                "Cannot reopen {} for the next repeat: {err}",
                                self.file.path.display()
                            );
                            self.pg.finish_with_message(format!(
                                "{} aborted",
                                self.file.path.display()
                            ));
                            return None;
                        }
                    }
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
            let original_first = self
                .original_first_packet_time
                .expect("Original first packet time should be set");
            packet.timestamp = timestamp
                .saturating_sub(original_first)
                .saturating_add(first_packet_time);
        } else {
            // A new start of pcap
            self.original_first_packet_time = Some(timestamp);

            let repeat = usize::try_from(self.file.repeat()).unwrap_or(usize::MAX);

            if self.current.is_multiple_of(repeat) {
                // A new group: use its configured start time.
                let group = self.current / repeat;
                let start_time = i64::from(self.file.start_time()[group]) * 1_000_000_000;

                packet.timestamp = if self.erase_timestamp {
                    if self.keep_subsecond {
                        // Keep the sub-second part of the original timestamp.
                        start_time.saturating_add(timestamp % 1_000_000_000)
                    } else {
                        start_time
                    }
                } else {
                    timestamp.saturating_add(start_time)
                };
            } else {
                // Same group, repeating after the configured interval.
                packet.timestamp = self.last_packet_time.saturating_add(self.repeat_interval);
            }

            self.first_packet_time = Some(packet.timestamp);
        }

        self.last_packet_time = packet.timestamp;
        self.pg.inc(1);

        let mut items = vec![packet; self.parallel];

        for (group, item) in items.iter_mut().enumerate() {
            // Jitter is a per parallel group constant; the timestamps of the
            // different groups stay spread by the same offsets.
            item.timestamp = item.timestamp.saturating_add(self.jitter[group]);

            if !self.rewriter.is_active() {
                continue;
            }

            let mut packet = Packet::new(item.data.to_mut());

            if let Err(err) = packet.try_parse_with_link_type(item.link_type, Default::default()) {
                warn!("{err}");
            }

            self.rewriter.rewrite(&mut packet, group);
        }

        Some(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Emitted payload: the timestamp plus a packet id.
    type TestPacket = (i64, usize);
    /// One batch: the packets of every parallel group of one input packet.
    type TestBatch = Vec<(i64, TestPacket)>;

    /// Build batches of `(timestamp, payload)`; every batch holds the packets of
    /// one parallel group of one input packet. The payload carries the
    /// timestamp again so that the emitted order can be asserted.
    fn batches(packets: &[(i64, &[i64])], first_id: usize) -> Vec<TestBatch> {
        let mut id = first_id;
        packets
            .iter()
            .map(|(base, offsets)| {
                offsets
                    .iter()
                    .map(|offset| {
                        id += 1;
                        let timestamp = base + offset;
                        (timestamp, (timestamp, id))
                    })
                    .collect()
            })
            .collect()
    }

    fn all_timestamps(packets: &[(i64, &[i64])]) -> Vec<i64> {
        let mut timestamps: Vec<i64> = packets
            .iter()
            .flat_map(|(base, offsets)| {
                let base = *base;
                offsets.iter().map(move |offset| base + offset)
            })
            .collect();
        timestamps.sort_unstable();

        timestamps
    }

    fn merge(streams: Vec<Vec<TestBatch>>) -> Vec<TestPacket> {
        let mut streams: Vec<_> = streams
            .into_iter()
            .map(|stream| stream.into_iter())
            .collect();
        let mut emitted: Vec<TestPacket> = Vec::new();

        merge_batches(&mut streams, |packet| {
            emitted.push(packet);
            Ok(())
        })
        .unwrap();

        emitted
    }

    fn assert_sorted(packets: &[TestPacket]) {
        assert!(
            packets.windows(2).all(|window| window[0].0 <= window[1].0),
            "{packets:?}"
        );
    }

    #[test]
    fn merge_orders_one_stream() {
        let packets = [(0, &[0][..]), (10, &[0][..]), (20, &[0][..])];
        let emitted = merge(vec![batches(&packets, 0)]);

        assert_sorted(&emitted);
        assert_eq!(
            emitted
                .iter()
                .map(|(timestamp, _)| *timestamp)
                .collect::<Vec<_>>(),
            vec![0, 10, 20]
        );
    }

    #[test]
    fn merge_orders_jitter_across_batch_boundaries() {
        // Group offsets 0 and 90 while the next packet starts at 5: a naive
        // "refill once the batch is empty" loop would emit 90 before 5.
        let packets = [(0, &[0, 90][..]), (5, &[0, 90][..]), (95, &[0, 90][..])];
        let expected = all_timestamps(&packets);
        let emitted = merge(vec![batches(&packets, 0)]);

        assert_sorted(&emitted);
        assert_eq!(
            emitted
                .iter()
                .map(|(timestamp, _)| *timestamp)
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn merge_handles_equal_timestamps() {
        let packets = [(0, &[0, 0, 0][..]), (0, &[0, 0, 0][..])];
        let emitted = merge(vec![batches(&packets, 0)]);

        assert_sorted(&emitted);
        // Ties are broken by the reader, and the id (assigned in arrival order)
        // makes the emitted order observable.
        assert_eq!(
            emitted.iter().map(|(_, id)| *id).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5, 6]
        );
    }
}
