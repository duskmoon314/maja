use std::path::PathBuf;

use clap::{ArgAction, Args, Parser};
use glob::glob;
use log::error;
use serde::Deserialize;

/// How the Ip addresses should be rewritten
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(from = "String")]
pub enum IpMap {
    /// Rewrite all addresses to one specific address.
    Ip(std::net::IpAddr),

    /// Rewrite all addresses to a random address in the given IpNet.
    Net(ipnet::IpNet),

    /// Rewrite all addresses in the first IpNet to the second IpNet.
    Map(ipnet::IpNet, ipnet::IpNet),
}

impl From<String> for IpMap {
    fn from(value: String) -> Self {
        if let Ok(ip) = value.parse::<std::net::IpAddr>() {
            IpMap::Ip(ip)
        } else if let Ok(net) = value.parse::<ipnet::IpNet>() {
            IpMap::Net(net)
        } else if let Some((from, to)) = value.split_once(":") {
            let from_net = from
                .trim()
                .parse::<ipnet::IpNet>()
                .expect("Invalid FROM IpNet");
            let to_net = to.trim().parse::<ipnet::IpNet>().expect("Invalid TO IpNet");
            IpMap::Map(from_net, to_net)
        } else {
            panic!("Invalid IpMap format: {}", value);
        }
    }
}

/// Config for one input file.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InputFile<P: AsRef<std::path::Path>> {
    /// The path / glob pattern to the input file.
    pub path: P,

    /// The start time offset of each group of the input file in seconds.
    ///
    /// If erase_time == true, the start time should be positive to arrange the
    /// packets in the output file.
    ///
    /// If erase_time == false, the start time can be negative to shift the
    /// packets to its past.
    pub start_time: Vec<i32>,

    /// The number of times to repeat the input file in one group.
    pub repeat: u32,

    /// The number of parallel groups to create from the input file.
    pub parallel: u32,

    /// Rewrite both src and dst
    pub ip_map: Vec<IpMap>,

    /// Rewrite only src
    pub src_ip_map: Vec<IpMap>,

    /// Rewrite only dst
    pub dst_ip_map: Vec<IpMap>,
}

impl<P: AsRef<std::path::Path> + Default> Default for InputFile<P> {
    fn default() -> Self {
        InputFile {
            path: Default::default(),
            start_time: vec![0],
            repeat: 1,
            parallel: 1,
            ip_map: vec![],
            src_ip_map: vec![],
            dst_ip_map: vec![],
        }
    }
}

impl InputFile<String> {
    /// Parse the cli arguments into a InputFile
    ///
    /// ## Format
    ///
    /// ```text
    /// path[#s<start_time,..>][#r<repeat>][#p<parallel>][#ip<ip_map,..>][#src<ip_map,..>][#dst<ip_map,..>]
    /// ```
    fn parse(s: &str) -> Result<InputFile<String>, clap::Error> {
        let mut input_file = InputFile::default();

        let mut parts = s.split('#');

        let path = parts.next().expect("Input file path is required");
        input_file.path = path.to_string();

        for part in parts {
            if let Some(value) = part.strip_prefix("src") {
                input_file.src_ip_map = value.split(',').map(|s| s.to_string().into()).collect();
            } else if let Some(value) = part.strip_prefix("dst") {
                input_file.dst_ip_map = value.split(',').map(|s| s.to_string().into()).collect();
            } else if let Some(value) = part.strip_prefix("ip") {
                input_file.ip_map = value.split(',').map(|s| s.to_string().into()).collect();
            } else if let Some(value) = part.strip_prefix("s") {
                input_file.start_time = value
                    .split(',')
                    .map(|s| s.parse::<i32>().expect("Invalid start time"))
                    .collect();
            } else if let Some(value) = part.strip_prefix("r") {
                input_file.repeat = value.parse::<u32>().expect("Invalid repeat value");
            } else if let Some(value) = part.strip_prefix("p") {
                input_file.parallel = value.parse::<u32>().expect("Invalid parallel value");
            } else {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::InvalidValue,
                    format!("Invalid input file option: {}", part),
                ));
            }
        }

        Ok(input_file)
    }

    pub fn expand_glob(self) -> anyhow::Result<Vec<InputFile<PathBuf>>> {
        let mut expanded_files = Vec::new();

        for entry in glob(&self.path)? {
            match entry {
                Ok(path) => {
                    let input_file = InputFile {
                        path,
                        start_time: self.start_time.clone(),
                        repeat: self.repeat,
                        parallel: self.parallel,
                        ip_map: self.ip_map.clone(),
                        src_ip_map: self.src_ip_map.clone(),
                        dst_ip_map: self.dst_ip_map.clone(),
                    };
                    expanded_files.push(input_file);
                }
                Err(e) => error!("Error reading glob entry: {}", e),
            }
        }

        Ok(expanded_files)
    }
}

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
}

impl std::ops::BitOr for MergeArgs {
    type Output = MergeArgs;

    fn bitor(self, rhs: Self) -> Self::Output {
        MergeArgs {
            erase_timestamp: self.erase_timestamp.or(rhs.erase_timestamp),
            snap_len: self.snap_len.or(rhs.snap_len),
            nanosecond: self.nanosecond.or(rhs.nanosecond),
            keep_subsecond: self.keep_subsecond.or(rhs.keep_subsecond),
            batch_size: self.batch_size.or(rhs.batch_size),
        }
    }
}

#[derive(Debug, Clone, Args, Deserialize)]
pub struct Config {
    /// The input files to merge
    ///
    /// Format: `path[#s<start_time,..>][#r<repeat>][#p<parallel>][#ip<ip_map,..>][#src<ip_map,..>][#dst<ip_map,..>]`
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
            input_files: if self.input_files.is_empty() {
                rhs.input_files
            } else {
                self.input_files
            },
            output_file: self.output_file.or(rhs.output_file),
            merge_args: self.merge_args | rhs.merge_args,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
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
