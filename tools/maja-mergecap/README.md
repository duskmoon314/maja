# maja-mergecap

`maja-mergecap` merges capture files into a pcap output.

```sh
cargo run -p maja-mergecap -- --help
```

It is a workspace tool built on top of the `maja` capture APIs. Use it as a
starting point for workflows that need to combine, filter, or normalize packet
captures.

## Usage

```bash
$ maja-mergecap -h
Merge capture files with configurations.

Usage: maja-mergecap [OPTIONS] [INPUT_FILES]...

Arguments:
  [INPUT_FILES]...  The input files to merge

Options:
  -c, --config-file <FILE>         The config file to use
  -o, --output-file <OUTPUT_FILE>  The output file to write the merged packets to
  -e, --erase-timestamp            Whether to erase the timestamps of the packets in the output file
      --snap-len <SNAP_LEN>        The snap len of the output file
      --nanosecond                 The precision of the timestamp
      --keep-subsecond             Whether to keep sub-second precision when erasing timestamps
      --batch-size <BATCH_SIZE>    The number of input files to merge in a single pass
  -h, --help                       Print help (see more with '--help')
  -V, --version                    Print version
```

The input files can be appended with configuration:

```
path[#s<start_time,..>][#r<repeat>][#p<parallel>][#ip<ip_map,..>][#src<ip_map,..>][#dst<ip_map,..>]
```
