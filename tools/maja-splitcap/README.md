# maja-splitcap

`maja-splitcap` is a tool to split a large capture file into smaller capture files, each containing one flow from the original capture file.

## Usage

```bash
$ maja-splitcap -h
Split capture files into per-flow pcap outputs.

Usage: maja-splitcap [OPTIONS] <INPUT> <OUTPUT>

Arguments:
  <INPUT>   Input capture file
  <OUTPUT>  Output directory for split pcap files

Options:
  -g, --granularity <GRANULARITY>  Split granularity [default: tuple5-sym] [possible values: src-ip, dst-ip, tuple2, tuple2-sym, tuple3, tuple3-sym, tuple4, tuple4-sym, tuple5, tuple5-sym]
  -n, --number <NUMBER>            Number of largest flows to write. Use 0 for all flows [default: 0]
      --two-pass                   Use two-pass mode to avoid storing packet data for unselected flows
      --snap-len <SNAP_LEN>        Override the output pcap snapshot length
      --nanosecond[=<NANOSECOND>]  Override output pcap timestamp precision [possible values: true, false]
  -h, --help                       Print help (see more with '--help')
  -V, --version                    Print version
```

Use Wireshark's [vlan.cap](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/vlan.cap.gz) as an example:

```bash
$ maja-splitcap vlan.cap vlan-split/
[2026-07-07T13:09:29Z INFO  maja_splitcap] Input format: Pcap
[2026-07-07T13:09:29Z INFO  maja_splitcap] Mode: single-pass
[2026-07-07T13:09:29Z INFO  maja_splitcap] Default link type: Ethernet
[2026-07-07T13:09:29Z INFO  maja_splitcap] SnapLen: 65535
[2026-07-07T13:09:29Z INFO  maja_splitcap] Resolution: 10^-6s (microseconds)
[2026-07-07T13:09:29Z INFO  maja_splitcap] Output SnapLen: 65535
[2026-07-07T13:09:29Z INFO  maja_splitcap] Output timestamp precision: microseconds

======================================================================
Split Summary
======================================================================
Total packets processed: 395
Packets written:         230
Packets skipped:         165
Output flows/files:      17
Top flows by packet count:
----------------------------------------------------------------------
131.151.32.21:6000_131.151.32.129:1162_Tcp.pcap                139 packets
131.151.32.21:6000_131.151.32.129:1173_Tcp.pcap                 46 packets
131.151.32.21:0_131.151.32.129:0_Icmp.pcap                      20 packets
131.151.6.171:0_131.151.32.129:0_Icmp.pcap                      10 packets
131.151.104.96:137_131.151.107.255:137_Udp.pcap                  3 packets
131.151.10.254:520_255.255.255.255:520_Udp.pcap                  1 packets
131.151.20.254:520_255.255.255.255:520_Udp.pcap                  1 packets
131.151.32.79:138_131.151.32.255:138_Udp.pcap                    1 packets
131.151.32.71:138_131.151.32.255:138_Udp.pcap                    1 packets
131.151.1.254:520_255.255.255.255:520_Udp.pcap                   1 packets
======================================================================
$ ls vlan-split/
131.151.10.254:520_255.255.255.255:520_Udp.pcap   131.151.1.254:520_255.255.255.255:520_Udp.pcap   131.151.32.254:520_255.255.255.255:520_Udp.pcap  131.151.6.171:0_131.151.32.129:0_Icmp.pcap
131.151.104.96:137_131.151.107.255:137_Udp.pcap   131.151.20.254:520_255.255.255.255:520_Udp.pcap  131.151.32.71:138_131.151.32.255:138_Udp.pcap    131.151.6.254:520_255.255.255.255:520_Udp.pcap
131.151.107.254:520_255.255.255.255:520_Udp.pcap  131.151.32.21:0_131.151.32.129:0_Icmp.pcap       131.151.32.79:138_131.151.32.255:138_Udp.pcap
131.151.111.254:520_255.255.255.255:520_Udp.pcap  131.151.32.21:6000_131.151.32.129:1162_Tcp.pcap  131.151.5.254:520_255.255.255.255:520_Udp.pcap
131.151.115.254:520_255.255.255.255:520_Udp.pcap  131.151.32.21:6000_131.151.32.129:1173_Tcp.pcap  131.151.5.55:138_131.151.5.255:138_Udp.pcap
```