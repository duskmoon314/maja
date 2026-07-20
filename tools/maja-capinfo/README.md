# maja-capinfo

`maja-capinfo` is a `capinfos`-like tool that prints summary information for capture files.

## Installation

```bash
cargo install maja-capinfo
```

## Usage

```bash
$ maja-capinfo -h
maja-capinfo

Usage: maja-capinfo [OPTIONS] [INPUTS]...

Arguments:
  [INPUTS]...  Input capture files

Options:
  -d, --dump <DUMP>      Whether to dump the inner metadata of all packets in the capture file [possible values: csv, parquet]
  -o, --output <OUTPUT>  The output directory for dumped files. If not specified, the same directory as the input file will be used
  -k, --top-k <TOP_K>    The number of top items to display in the statistics [default: 10]
      --batch-size <BATCH_SIZE>  The maximum number of packet metadata rows buffered before a dump batch is written [default: 65536]
  -h, --help             Print help (see more with '--help')
  -V, --version          Print version
```

Use Wireshark's [vlan.cap](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/vlan.cap.gz) as an example:

```bash
$ maja-capinfo -d csv vlan.cap
======================================================================
File:               vlan.cap
  Format:           Pcap
  Size:             144.46 kB
  Processing Time:  0.014774 s
  Interfaces:
    #0              LinkType = Ethernet, SnapLen = 65535, Resolution = 10^-6s (microseconds)

Packet Statistics:
  Total Packets:    395.00 
  Total L2 Bytes:   138.11 kB
    Avg L2 Length:  349.65B
  Total L3 Bytes:   113.36 kB
    Avg L3 Length:  286.99B
  Empty Packets:    0
  Errors:           0
  Ordered:          false
  First packet:     1999-11-05T18:20:40.056226+00:00[+00:00] (941826040056226000)
  Last packet:      1999-11-05T18:20:44.502622+00:00[+00:00] (941826044502622000)
  Duration:         PT4.446396S
  Throughput:       88.84 pps, 31.06 kBps

Aggregated Statistics:
  Length:           349.65 (± 463.88) [60, 1518] Bytes
  Unique SRC IP:    17
  Unique DST IP:    8
  TCP Count:        185
  UDP Count:        15
  Unique SRC Ports: 7
  Unique DST Ports: 7
  Unique 5-tuple:   15

Top10 Statistics:
  Top 10 SRC IPs:
    0.0.0.0          165.00 pkts,  20.61 kB
    131.151.32.129   138.00 pkts,  88.36 kB
    131.151.32.21     72.00 pkts,  19.91 kB
    131.151.6.171      5.00 pkts,   7.58 kB
    131.151.104.96     3.00 pkts,  288.00 B
    131.151.32.79      1.00 pkts,  247.00 B
    131.151.107.254    1.00 pkts,   70.00 B
    131.151.10.254     1.00 pkts,   70.00 B
    131.151.32.254     1.00 pkts,   70.00 B
    131.151.115.254    1.00 pkts,   70.00 B
  Top 10 DST IPs:
    0.0.0.0          165.00 pkts,  20.61 kB
    131.151.32.21    133.00 pkts,  80.79 kB
    131.151.32.129    77.00 pkts,  27.48 kB
    255.255.255.255    9.00 pkts,  630.00 B
    131.151.6.171      5.00 pkts,   7.58 kB
    131.151.107.255    3.00 pkts,  288.00 B
    131.151.32.255     2.00 pkts,  494.00 B
    131.151.5.255      1.00 pkts,  247.00 B
  Top 10 SRC Ports:
    0                195.00 pkts,  51.60 kB
    1162              96.00 pkts,  59.95 kB
    6000              62.00 pkts,  11.99 kB
    1173              27.00 pkts,  12.92 kB
    520                9.00 pkts,  630.00 B
    137                3.00 pkts,  288.00 B
    138                3.00 pkts,  741.00 B
  Top 10 DST Ports:
    0                195.00 pkts,  51.60 kB
    6000             123.00 pkts,  72.87 kB
    1162              43.00 pkts,   9.92 kB
    1173              19.00 pkts,   2.07 kB
    520                9.00 pkts,  630.00 B
    137                3.00 pkts,  288.00 B
    138                3.00 pkts,  741.00 B

Export Statistics:
  Output File: vlan.csv
  Format:                  Csv
  Elapsed Time:       0.006240 s
======================================================================
$ head vlan.csv
timestamp,length,eth_type,src_ip4,dst_ip4,ip_proto,tos,ttl,total_length,src_port,dst_port,tcp_flags,tcp_window,tcp_data_offset,udp_length
941826040056226000,1518,33024,2207719553,2207719445,6,0,64,1500,1162,6000,24,28920,8,0
941826040056331000,650,33024,2207719553,2207719445,6,0,64,632,1162,6000,24,28920,8,0
941826040059915000,64,33024,0,0,0,0,0,0,0,0,0,0,0,0
941826040063897000,1518,33024,2207719553,2207719445,6,0,64,1500,1162,6000,24,28920,8,0
941826040063982000,350,33024,2207719553,2207719445,6,0,64,332,1162,6000,24,28920,8,0
941826040064555000,70,33024,2207719445,2207719553,6,0,64,52,6000,1162,16,31856,8,0
941826040065843000,1518,33024,2207719445,2207719553,6,0,64,1500,6000,1162,24,31576,8,0
941826040065888000,638,33024,2207719445,2207719553,6,0,64,620,6000,1162,24,31576,8,0
941826040066028000,70,33024,2207719553,2207719445,6,0,64,52,1162,6000,16,27472,8,0
```
