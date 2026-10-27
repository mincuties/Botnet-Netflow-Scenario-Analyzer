# Botnet Netflow Scenario Analyzer

A command-line program that analyses a labelled netflow capture, summarises the
traffic of every source IP address, flags source IPs whose behaviour crosses
configurable thresholds, and checks the flags against the ground-truth labels of
the CTU-13 botnet dataset.

Detection is rule-based by design. Every flag is a single, traceable comparison
such as `n_dst_ips=312 >= 50`, and every number in the output can be traced back
to rows of the input file. No machine-learning library is used; the program relies
on the Python standard library, NumPy and Matplotlib.

## Contents

1. [Quick start](#1-quick-start)
2. [What the program does](#2-what-the-program-does)
3. [Input](#3-input)
4. [Output](#4-output)
5. [Configuration](#5-configuration)
6. [Data](#6-data)
7. [Testing](#7-testing)
8. [Results on the sample](#8-results-on-the-sample)
9. [Project structure](#9-project-structure)
10. [Assessment criteria coverage](#10-assessment-criteria-coverage)
11. [Limitations](#11-limitations)
12. [Acknowledgement](#12-acknowledgement)

Further documentation:

- [docs/SYSTEM_DESIGN.md](docs/SYSTEM_DESIGN.md): how the program works, module by module.
- [docs/TESTING.md](docs/TESTING.md): every test input and its expected output.
- [data/DATA.md](data/DATA.md): data source, checksums, sampling and full analysis.

## 1. Quick start

Requirements: Python 3.10 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS / Linux: source .venv/bin/activate
pip install -r requirements.txt

python main.py --input data/sample.csv --config config.json
python -m pytest
```

Command-line arguments:

| Argument | Required | Default | Meaning |
|---|---|---|---|
| `--input` | yes | | netflow CSV file to analyse |
| `--config` | no | `config.json` | settings file |
| `--output` | no | `outputs` | folder for the results (created if missing) |

Exit code `0` means the analysis finished. Exit code `1` means the input or the
configuration could not be used; a one-line message starting with `Error:` explains
why, and no Python traceback is shown.

## 2. What the program does

```
input CSV ──► loader ──► Flow objects ──► per-IP statistics ──► rules ──► label check ──► outputs
              (clean)     (one per row)     (dict, set, NumPy)   (config)   (if Label)     (CSV, TXT, PNG)
```

1. **Load and validate** (`analyzer/loader.py`). Columns are matched by name, rows
   that cannot be trusted are skipped and counted by reason, and file-level problems
   stop the program with a clear message.
2. **Represent** (`analyzer/flow.py`). Each valid row becomes a `Flow` object.
3. **Aggregate** (`analyzer/features.py`). Flows are grouped by source IP in a
   dictionary; for every source IP the program counts flows, distinct destination IPs,
   distinct destination ports and bytes, and computes timing statistics with NumPy.
4. **Detect** (`analyzer/detectors.py`). Two rules, both with thresholds from `config.json`:
   - **fan-out**: the source contacted at least `fanout_min_destinations` different destination IPs
     (typical of scanning or spam);
   - **large upload**: the source sent at least `upload_min_src_bytes` bytes in total
     (typical of data exfiltration or flooding).
5. **Evaluate** (`analyzer/detectors.py`). If the file has a `Label` column, flagged IPs
   are compared with the labelled bot, normal and background IPs.
6. **Report** (`analyzer/report.py`, `analyzer/plots.py`). Results are written to a CSV
   report, a text summary and two charts.

A detailed description of each step is in [docs/SYSTEM_DESIGN.md](docs/SYSTEM_DESIGN.md).

## 3. Input

A text CSV file with a header line, in the CTU-13 `.binetflow` layout or any layout
that contains the required columns. Columns are matched by **name**, not by position,
ignoring letter case, spaces, `_` and `-`; common alternative names are also accepted
(for example `src_ip` for `SrcAddr`).

| Column | Required | Used for |
|---|---|---|
| `SrcAddr`, `DstAddr` | yes | grouping by source, distinct destinations |
| `SrcBytes` | no | large-upload rule (rule skipped if the column is absent) |
| `TotBytes` | no | report only |
| `Dport` | no | distinct destination ports; decimal and hexadecimal (`0x0008`) accepted |
| `StartTime` | no | time gaps between flows; format set in `config.json` |
| `Proto` | no | stored with each flow |
| `Label` | no | comparison with ground truth (skipped if absent) |

Handling rules:

| Situation | Behaviour |
|---|---|
| file missing, empty, binary, or missing a required column | stop, `Error: ...`, exit code 1 |
| header only (no data rows) | outputs written, summary states "No valid flows" |
| empty `SrcAddr` or `DstAddr` | row skipped, counted by reason |
| byte count empty, not a whole number, or negative | row skipped, counted by reason |
| row with a different number of fields from the header | row skipped, counted by reason |
| invalid port or time | row kept, value left empty |
| blank line | ignored, not counted |
| unknown extra columns | ignored, listed in the summary |
| comma, semicolon or tab separator; UTF-8 BOM | detected and handled automatically |

## 4. Output

All files are written to the output folder (default `outputs/`).

| File | Content |
|---|---|
| `summary.txt` | rows read, used and skipped (with reasons), missing and ignored columns, per-IP statistics, thresholds, flagged IPs with evidence, comparison with labels |
| `report.csv` | one row per flagged source IP |
| `top_fanout.png` | the source IPs with the most distinct destinations, threshold marked |
| `src_bytes_hist.png` | distribution of bytes sent per source IP, threshold marked |

`report.csv` columns:

| Column | Meaning |
|---|---|
| `src_ip` | flagged source IP |
| `rules` | rule(s) triggered, e.g. `fanout;large_upload` |
| `evidence` | measured value and threshold for each rule, e.g. `n_dst_ips=5124 >= 50` |
| `n_flows`, `n_dst_ips`, `n_dst_ports` | counts for this source IP |
| `src_bytes`, `total_bytes` | bytes sent, bytes in both directions |
| `label_class` | `bot`, `normal`, `background` or `no-label-column` |

Rows are sorted by `n_dst_ips` (descending), then `src_bytes` (descending), then IP, so
repeated runs produce identical files.

Example outputs from the sample data are in [docs/example_outputs/](docs/example_outputs/).

## 5. Configuration

All values that affect the result are in `config.json`:

| Key | Meaning | Value |
|---|---|---|
| `fanout_min_destinations` | fan-out threshold (distinct destination IPs) | 50 |
| `upload_min_src_bytes` | large-upload threshold (bytes sent) | 10000000 (10 MB) |
| `time_format` | `strptime` format of `StartTime` | `%Y/%m/%d %H:%M:%S.%f` |
| `plot_top_n` | number of IPs in `top_fanout.png` | 15 |

Both rules use `>=`, so a value equal to the threshold is flagged. The `_notes` key
holds descriptions and is not read by the program. A missing key, a value of the wrong
type, or a number below 1 stops the program with a message naming the key. The
reasoning behind both thresholds is in [data/DATA.md](data/DATA.md#3-results-on-the-sample-default-configjson).

## 6. Data

- **Dataset:** CTU-13, scenario 7 (Sogou botnet), Stratosphere Lab, Czech Technical
  University, 2011.
- **Original file:** `capture20110816-2.binetflow`, 114,077 labelled flows,
  SHA-256 `df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680`.
- **Committed sample:** `data/sample.csv`, the first 60,000 flows copied unchanged
  by `make_sample.py`, SHA-256 `c39e968afa6fe1d184dc63f1cc234bf044479ca6dff6a463af1df8659d24d8b1`.

Download link, label definitions and reproduction steps: [data/DATA.md](data/DATA.md).
All files under `tests/` are small synthetic files written for testing and are labelled
as such; they are not presented as real traffic.

## 7. Testing

```bash
python -m pytest
```

57 automated tests in five files:

| File | Covers |
|---|---|
| `tests/test_flow.py` | text-to-value conversion: counts, decimal and hex ports, times, label direction |
| `tests/test_loader.py` | one test per edge-case file in `tests/bad_files/` (13 files) |
| `tests/test_features_detectors.py` | distinct counts, NumPy statistics, threshold boundaries, label evaluation, threshold tuning |
| `tests/test_main_and_config.py` | invalid configurations, exit codes, the whole program on every edge-case file |
| `tests/test_manual_expected.py` | the whole program against a result computed by hand |

The hand-computed case uses `tests/data/tiny_manual.csv` (10 rows) with
`tests/data/tiny_config.json`. The working is in
[tests/data/tiny_manual_EXPECTED.md](tests/data/tiny_manual_EXPECTED.md) and the expected
`report.csv` is:

```
src_ip,rules,evidence,n_flows,n_dst_ips,n_dst_ports,src_bytes,total_bytes,label_class
10.0.0.1,fanout,n_dst_ips=3 >= 3,4,3,3,600,1000,bot
10.0.0.2,large_upload,src_bytes=2400 >= 2000,2,1,1,2400,8000,normal
```

Every test input and its expected output is listed in [docs/TESTING.md](docs/TESTING.md).

## 8. Results on the sample

On `data/sample.csv` (60,000 flows, 13,554 source IPs) with the default configuration:

| Measure | Result |
|---|---|
| rows skipped | 0 |
| source IPs flagged | 27 (19 fan-out, 10 large upload, 2 both) |
| labelled bot IPs flagged | 0 of 1 |
| labelled normal IPs flagged | 0 of 5 |
| flagged IPs with a background (unverified) label | 27 |

The single infected host, `147.32.84.165`, is **not** detected: it contacted 17
destinations and sent 447,399 bytes, below both thresholds and below one labelled-normal
host (35 destinations). The flagged hosts are unusual but cannot be confirmed as infected
from the labels. These findings apply only to this scenario and these thresholds. The full
analysis is in [data/DATA.md](data/DATA.md#3-results-on-the-sample-default-configjson).

## 9. Project structure

```
main.py                   command-line entry point
config.json               thresholds and settings
make_sample.py            reproduces data/sample.csv from the original file
tune_thresholds.py        optional: scores thresholds against labels (F1)
requirements.txt          dependencies
pytest.ini                test configuration
analyzer/
  flow.py                 Flow dataclass and value parsers
  loader.py               CSV reading, column matching, row validation
  features.py             per source IP statistics
  detectors.py            fan-out and large-upload rules, label evaluation
  config.py               configuration loading and validation
  report.py               report.csv and summary.txt
  plots.py                Matplotlib charts
data/
  sample.csv              60,000 real CTU-13 flows
  DATA.md                 provenance, checksums, analysis
docs/
  SYSTEM_DESIGN.md        design and module reference
  TESTING.md              test inputs and expected outputs
  example_outputs/        outputs of the default run on the sample
tests/
  bad_files/              13 synthetic edge-case files
  data/                   hand-computed test case
  test_*.py               pytest tests
```

## 10. Assessment criteria coverage

| Criterion | Where it is addressed |
|---|---|
| Environment, data, reproducibility | `requirements.txt`; documented source, download link and SHA-256 checksums in `data/DATA.md`; `make_sample.py` regenerates the sample exactly; deterministic output order |
| Functional correctness | schema handling by column name, required and optional columns, row validation with counted skip reasons, clear errors for unusable files (section 3) |
| Course programming concepts | functions with one task each; `dict` keyed by IP, `set` for distinct counts, `Counter` for skip reasons; CSV and JSON file I/O; NumPy (`diff`, `mean`, `std`, `median`, `percentile`, vectorised threshold scoring); Matplotlib charts; `dataclass` for `Flow` and `Alert`, custom exception classes |
| Testing and robustness | 57 tests, 13 edge-case files, whole-program run on each, one hand-computed expected result |
| Analysis and outputs | `evidence` column with value and threshold for every flag; label comparison that separates verified normal from unverified background; reported miss of the bot; limitations stated |
| Code quality and documentation | small modules, docstrings, no magic numbers (all thresholds in `config.json`), README and design documents |

## 11. Limitations

- A file is analysed once, offline; behaviour is summarised over the whole file, not per
  time window.
- Only two volume-based rules. Quiet bots, such as the one in the sample, are not
  detected. Blacklists of known command-and-control servers and timing (beaconing) rules
  are not implemented.
- A flag indicates unusual behaviour, not proof of infection: busy servers such as DNS
  resolvers and proxies also contact many hosts.
- Results hold only for the scenario and thresholds used. Each CTU-13 scenario has very
  few infected hosts, so counts are reported rather than percentages.
- All valid flows are held in memory; multi-gigabyte inputs would need streaming
  aggregation.

## 12. Acknowledgement

An AI assistant (Claude) was used during development.
