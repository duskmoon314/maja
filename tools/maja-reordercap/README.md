# maja-reordercap

`maja-reordercap` reorders the packets of a capture file (pcap or pcapng) by timestamp, similar to Wireshark's `reordercap`.

The input file is memory-mapped and scanned once to build a compact index of `(timestamp, offset, record_len)` per packet — no packet bytes are copied while indexing, so memory usage stays proportional to the packet count (a few dozen bytes per packet), not the capture size. The output keeps the input format and is written by copying the original record bytes verbatim from the mapping in timestamp order, preserving byte order and timestamp precision. Sorting is stable: packets with equal timestamps keep their original relative order.

For pcapng input, blocks before the first packet block (SHB, IDBs) are copied first, packet blocks follow in timestamp order, and non-packet blocks after the first packet (NRB, ISB, ...) keep their original order at the end. Multi-section captures are reordered section by section: packet blocks never cross a section boundary, because their interface IDs refer to the interface list of their own section. Interface description blocks appearing after packet blocks are hoisted after the initial interface descriptions, preserving interface numbering. Simple packet blocks (which carry no timestamps) are rejected with an error.

## Usage

```bash
$ maja-reordercap -h
Reorder packets in a capture file by timestamp.

Usage: maja-reordercap [OPTIONS] <INPUT> [OUTPUT]

Arguments:
  <INPUT>   Path to the input capture file
  [OUTPUT]  Path to the output file (default: <input>.reordered.<format>)

Options:
  -d, --dry-run    Report out-of-order packets without writing any output
  -n, --no-output  Do not write output when the input is already ordered
  -h, --help       Print help (see more with '--help')
  -V, --version    Print version
```

Use Wireshark's [vlan.cap](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/vlan.cap.gz) as an example:

```bash
$ maja-reordercap -d vlan.cap
vlan.cap: 395 packets, 1 out of order
frame #96: ts 941826040.848711000 is 29000 ns earlier than frame #95 (ts 941826040.848740000)

$ maja-reordercap vlan.cap
vlan.cap: 395 packets, 1 out of order
wrote 395 packets to vlan.reordered.pcap
```
