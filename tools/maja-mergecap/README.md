# maja-mergecap

`maja-mergecap` merges capture files into a pcap output.

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
      --seed <SEED>                Seed for the random address mapping
      --no-fix-checksum            Do not recompute the IPv4 header and TCP/UDP checksums
  -h, --help                       Print help (see more with '--help')
  -V, --version                    Print version
```

The input files can be appended with configuration:

```
path[#s<start_time,..>][#r<repeat>][#p<parallel>][#j<ns>][#ip<ip_map,..>][#src<ip_map,..>][#dst<ip_map,..>][#flow<flow_entry,..>]
```

The `#` suffix only covers the common options; `repeat_interval` and the
`flow_map` machinery are config file only. A config entry and a positional
argument for the same path merge **field by field**, so a complex file can be
tweaked for a single run:

```bash
maja-mergecap -c cfg.json 'client.pcap#j2000000#p8'
```

## Address rewriting

Three independent ways to rewrite addresses:

| Option                                                | Scope       | Semantics                                                |
| ----------------------------------------------------- | ----------- | -------------------------------------------------------- |
| `#ip<..>` (`ip_map`)                                  | both fields | direct rewrite of source and destination of every packet |
| `#src<..>` / `#dst<..>` (`src_ip_map` / `dst_ip_map`) | one field   | direct rewrite of one direction                          |
| `#flow<..>` (`flow_map`)                              | key         | keeps one target per key                                 |

`flow_map` and the direct maps are mutually exclusive; the direct maps are
stateless and draw per packet, `flow_map` keeps a key stable.

The entry syntax is shared by both:

| Entry          | Shape | Rewrites                                             |
| -------------- | ----- | ---------------------------------------------------- |
| `<from>=><to>` | pool  | addresses inside `from` to a draw from the `to` pool |
| `<from>-><to>` | mask  | addresses inside `from`, keeping their host bits     |
| `<net>`        | pool  | every address to a draw from the net                 |
| `<ip>`         | fixed | every address to that address                        |

For Ipv4, `<from>:<to>` can be used as an alternative to `<from>-><to>` (Backwards compatibility).

Assume we have a direct map with three entries:

```sh
'pcap#dst192.168.1.0/24->10.0.0.0/24,192.168.0.0/16=>10.1.0.0/24,10.9.0.0/16'
# 192.168.1.0/24 -> 10.0.0.<host>   mask
# 192.168.0.0/16 -> 10.1.0.0/24     pool
# anything else  -> 10.9.0.0/16     pool, a new draw for every packet

# a rule matches by longest prefix (CIDR), so /24 beats /16 for 192.168.1.10
10.0.0.1:5000 -> 192.168.1.10:80   becomes  10.0.0.1:5000 -> 10.0.0.10:80      # /24 wins
10.0.0.1:5001 -> 192.168.2.10:80   becomes  10.0.0.1:5001 -> 10.1.0.240:80     # /16
10.0.0.1:5002 -> 203.0.113.9:443   becomes  10.0.0.1:5002 -> 10.9.38.33:443    # no match
10.0.0.1:5003 -> 203.0.113.9:443   becomes  10.0.0.1:5003 -> 10.9.33.144:443   # no match, new draw
```

A `mask` whose `to` network is smaller than `from` logs a warning.

`flow_map` looks up each endpoint separately and remembers the target per key, so
packet order does not matter and both directions of a connection get the same
pair:

```sh
maja-mergecap -o nat.pcap --seed 42 \
  'client.pcap#flow192.168.0.0/16=>10.0.0.0/24,10.1.0.0/16=>10.2.0.0/24'

192.168.1.5:1234 -> 10.1.2.3:80   becomes  10.0.0.178:1234 -> 10.2.0.9:80
10.1.2.3:80 -> 192.168.1.5:1234   becomes  10.2.0.9:80 -> 10.0.0.178:1234
```

An address that matches no entry stays unchanged (one warning). An entry
without `from` is a catch-all, so there is at most one per family.

### Config file

For more complex setups, a JSON config file can be used.

```jsonc
{
  "input_files": [
    {
      "path": "client.pcap",
      "start_time": [0],                // replay the file once per entry, at that offset in seconds
      "repeat": 1,                      // replay the file this many times per pass, one after another
      "repeat_interval": 1000000000,    // wait this many ns between two replays
      "parallel": 3,                    // emit every packet once per group
      "parallel_jitter": 100000000,     // shift each group by a random offset; group 0 keeps the timeline
      "flow_map": {
        "key": "session",               // session: keep one pair per connection;
                                        // address: keep one target per original address
        "policy": "unique",             // how a pool picks an address:
                                        //   random: pick a new one for every packet
                                        //   sticky: pick one per key, then reuse it
                                        //   unique: like sticky, but pick an address that is still unused
                                        //           until the pool runs out
                                        //   hash: compute it from the key, store nothing
        "alloc_scope": "file",          // file: keep one mapping table per input file;
                                        // global: keep one mapping table for the whole merge
        "sharing": "per-group",         // per-group: give each parallel group its own mapping table;
                                        // shared: let every group use the same mapping table
        "entries": [
          { "from": "192.168.0.0/16", "to": "10.0.0.0/24" },                   // draw from this pool; the longest prefix wins
          { "from": "10.1.0.0/16", "to": "10.2.0.0/24", "policy": "sticky" },  // override the map policy for this entry
          { "from": "10.8.0.0/16", "to": "10.88.0.0/16", "shape": "mask" },    // keep the host bits
          { "to": "10.9.9.9" }                                                 // match what no rule matched; use this fixed target
        ],
        "exclude": ["224.0.0.0/4", "255.255.255.255/32"],  // never rewrite these
        "protocols": ["tcp", "udp"],                       // only rewrite these; "any" for all
        "fragments": true                                  // give every fragment of a datagram the same target
      }
    }
  ],
  "output_file": "out.pcap",
  "seed": 42,                           // reproduce the same choices with this number
  "fix_checksum": true                  // recompute the checksums after a rewrite
}
```

The file can also be an array of such objects; they are merged in order.

Every field has a default except `path`, `output_file` and mapping entries.

Instead of `flow_map`, a file can use the stateless per-direction maps:

```jsonc
"dst_ip_map": [
  { "to": "10.0.0.9" },
  { "from": "192.168.0.0/16", "to": "10.1.0.0/16", "shape": "mask" }
]
```
