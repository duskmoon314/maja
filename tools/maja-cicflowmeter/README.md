# maja-cicflowmeter

`maja-cicflowmeter` extracts bidirectional TCP and UDP flow features from pcap and pcapng files using the canonical 85-column [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter) schema.

## Installation

```bash
cargo install maja-cicflowmeter
```

## Usage

```bash
$ maja-cicflowmeter -h
Extract CICFlowMeter-compatible flow features from packet captures.

Usage: maja-cicflowmeter [OPTIONS] <INPUT> <OUTPUT>

Arguments:
  <INPUT>   Input pcap/pcapng file or directory
  <OUTPUT>  Output directory for generated CSV files

Options:
      --recursive
          Recurse into nested input directories
      --flow-timeout <FLOW_TIMEOUT>
          Flow timeout, for example 120s, 500ms, or 1m [default: 120s]
      --activity-timeout <ACTIVITY_TIMEOUT>
          Active/idle split timeout, for example 5s or 500ms [default: 5s]
      --label <LABEL>
          Label written in the final CSV column [default: NeedManualLabel]
      --overwrite
          Replace existing output files
  -h, --help
          Print help
  -V, --version
          Print version
```

Process one capture file:

```bash
maja-cicflowmeter capture.pcap output/
# output/capture.csv
```

Process all captures below a directory:

```bash
maja-cicflowmeter --recursive captures/ output/
```

Use a fixed label for every emitted flow:

```bash
maja-cicflowmeter --label BENIGN capture.pcap output/
```

The default flow timeout is 120 seconds and the default active/idle timeout is
5 seconds. Existing output files require `--overwrite`.

## Output

The CSV contains the canonical 85 CICFlowMeter columns, with `Label` as the
final column. The tool does not infer labels from capture filenames or packet
content; `Label` defaults to `NeedManualLabel`.

For encapsulated packets, the extractor selects the innermost TCP or UDP layer
and pairs it with the nearest enclosing IPv4 or IPv6 layer. This allows flow
features to be computed for supported tunneled traffic such as GRE and VXLAN,
including mixed outer and inner IP versions.

## Compatibility Notes

`Timestamp` is emitted as an ISO 8601 UTC string with the available fractional
second precision, for example:

```text
2018-11-03T02:13:03.684601Z
```

This is deterministic and differs from the original CICFlowMeter local-time,
second-resolution timestamp format.
