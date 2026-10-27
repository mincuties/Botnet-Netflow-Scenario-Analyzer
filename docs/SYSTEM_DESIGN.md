# System design

This document describes how the Botnet Netflow Scenario Analyzer works: the data
flow, the data structures, each module and its functions, the error-handling policy,
and the main design decisions.

## 1. Overview

The program is a single command-line run over one file:

```
python main.py --input data/sample.csv --config config.json
```

```
                 config.json
                      │
                      ▼
input CSV ──► loader.load_flows() ──► list[Flow] ──► features.compute_ip_stats()
                      │                                         │
              LoadResult (counts,                     dict: src_ip -> statistics
              skip reasons, columns)                            │
                      │                                         ▼
                      │                         detectors.run_detectors()
                      │                                         │
                      │                         dict: src_ip -> list[Alert]
                      │                                         │
                      │                    detectors.evaluate_against_labels()
                      │                                         │
                      └──────────────► report.py, plots.py ◄────┘
                                                │
                     summary.txt, report.csv, top_fanout.png, src_bytes_hist.png
```

`main.run()` calls these steps in order. `main.main()` parses the arguments, calls
`run()`, and converts known errors into a one-line message and exit code 1.

## 2. Path of one row through the system

Input row (CTU-13 layout):

```
2011/08/16 10:00:20.000000,0.5,tcp,10.0.0.1,1027,   ->,10.0.0.102,443,SRPA_SPA,0,0,4,300,180,flow=From-Botnet-V48-TCP-Test
```

1. `csv.reader` splits the line into 15 strings.
2. The field count is compared with the header (15). A different count would skip the row.
3. `row_to_flow()` reads each needed value through the column-position map built from
   the header (`SrcAddr` is position 3, `DstAddr` position 6, and so on):
   - `src_ip = "10.0.0.1"`, `dst_ip = "10.0.0.102"`: both non-empty, so the row continues;
   - `SrcBytes "180"` and `TotBytes "300"` go through `parse_count()` and become `180` and `300`;
   - `Dport "443"` goes through `parse_port()` and becomes `443`;
   - `StartTime` goes through `parse_time()` and becomes a `datetime`;
   - the result is `Flow(src_ip="10.0.0.1", dst_ip="10.0.0.102", dst_port=443, protocol="tcp", ...)`.
4. `group_by_source()` appends the Flow to `flows_by_ip["10.0.0.1"]`.
5. `compute_ip_stats()` adds `"10.0.0.102"` to the set of destinations of `10.0.0.1`,
   adds 180 to its bytes sent, and so on.
6. `detect_fanout()` compares the number of distinct destinations of `10.0.0.1` with the
   threshold. If it is reached, an `Alert("10.0.0.1", "fanout", 3, 3)` is created.
7. `write_report_csv()` writes the alert as `10.0.0.1,fanout,n_dst_ips=3 >= 3,...`.

## 3. Data structures

| Structure | Type | Content | Defined in |
|---|---|---|---|
| `Flow` | dataclass | one valid row: `src_ip`, `dst_ip`, `dst_port`, `protocol`, `start_time`, `src_bytes`, `total_bytes`, `label` | `flow.py` |
| `LoadResult` | dataclass | `flows` (list of Flow), `rows_read`, `skipped` (Counter: reason → count), `missing_optional`, `ignored_columns`, `delimiter` | `loader.py` |
| column map | dict | canonical column name → position in the row, e.g. `{"SrcAddr": 3, "DstAddr": 6}` | `loader.map_header()` |
| `flows_by_ip` | dict | source IP → list of its Flow objects | `features.group_by_source()` |
| `ip_stats` | dict of dicts | source IP → `n_flows`, `n_dst_ips`, `n_dst_ports`, `src_bytes`, `total_bytes`, `mean_gap_s`, `std_gap_s`, `is_bot`, `is_normal` | `features.compute_ip_stats()` |
| `Alert` | dataclass | `ip`, `rule`, `value`, `threshold`; `evidence()` formats them | `detectors.py` |
| `flagged` | dict | source IP → list of Alert | `detectors.run_detectors()` |
| evaluation | dict | counts of bots, normals, flagged bots, missed bots, flagged normals, flagged background | `detectors.evaluate_against_labels()` |

Why these choices:

- **dict keyed by IP**: the statistics of any IP are found directly by key; with a list
  every lookup would require a scan.
- **set for distinct values**: a set stores each value once, so `len(set)` is the
  number of distinct destinations or ports.
- **Counter for skip reasons**: missing keys start at zero, so
  `skipped[reason] += 1` needs no prior check.
- **dataclass for Flow and Alert**: named fields (`flow.src_ip`) instead of positions
  (`row[3]`); the constructor is generated automatically. No inheritance is needed.

## 4. Modules

### 4.1 `analyzer/flow.py`

| Function | Input | Output | Behaviour on bad input |
|---|---|---|---|
| `parse_count(text, column_name)` | `"214"`, `"100.0"` | `214`, `100` | `ValueError` for empty, non-numeric (`"abc"`), fractional (`"1.5"`) or negative (`"-5"`) |
| `parse_port(text)` | `"53"`, `"0x0008"`, `"08"` | `53`, `8`, `8` | `None` for empty, non-numeric or out of range (> 65535) |
| `parse_time(text, time_format)` | `"2011/08/16 10:01:46.972101"` | `datetime` | `None` if the text does not match the format |
| `Flow.is_from_botnet()` | label | `True` if it contains `From-Botnet` | case-insensitive |
| `Flow.is_from_normal()` | label | `True` if it contains `From-Normal` | case-insensitive |

`parse_port` uses `int(text, 0)`, which reads the base from the prefix, because CTU-13
stores ICMP type and code values as hexadecimal "ports" such as `0x0008`.

`is_from_botnet` checks for `From-Botnet`, not `Botnet`. CTU-13 also uses `To-Botnet`,
which marks traffic whose **destination** is the bot; the source of such a flow is not
infected.

Byte counts raise errors while ports and times return `None` because byte counts are
measured directly by a rule, whereas ports and times only feed descriptive statistics.

### 4.2 `analyzer/loader.py`

`load_flows(path, time_format)` returns a `LoadResult`. Steps:

1. Open the file with `encoding="utf-8-sig"` (removes a byte-order mark if present) and
   `newline=""` (required by the `csv` module).
2. Read the header line. If it is empty, raise `LoaderError("file is empty ...")`.
3. `detect_delimiter(header_line)`: count `,`, `;` and tab characters; use the most frequent.
4. `map_header(header)`: normalise each name with `simplify_name()` (lower case, remove
   spaces, `_` and `-`), look it up in `COLUMN_ALIASES`, and record its position. Unknown
   names are listed in `ignored_columns`. If a name appears twice, the first is used.
5. Check `REQUIRED_COLUMNS` (`SrcAddr`, `DstAddr`). If any is missing, raise
   `LoaderError` naming the missing column and listing the columns found.
6. Record which `OPTIONAL_COLUMNS` are absent.
7. For each following line: ignore blank lines; count the row; skip rows whose field
   count differs from the header; call `row_to_flow()`, and on `ValueError` skip the row
   and increment `skipped[short_reason(error)]`.

`short_reason()` keeps the text before the first colon, so
`"SrcBytes is not a number: 'abc'"` and `"SrcBytes is not a number: 'x'"` are counted
under the same reason.

File-level exceptions are converted to `LoaderError`: `FileNotFoundError`,
`UnicodeDecodeError` (binary or non-UTF-8 file), `csv.Error`, and other `OSError`s
(for example, a folder given as input).

### 4.3 `analyzer/features.py`

| Function | Purpose |
|---|---|
| `group_by_source(flows)` | one pass over the flows, building `{src_ip: [Flow, ...]}` |
| `compute_ip_stats(flows)` | per source IP: `n_flows`, `n_dst_ips` (set), `n_dst_ports` (set), `src_bytes`, `total_bytes`, `mean_gap_s`, `std_gap_s`, `is_bot`, `is_normal` |
| `sum_or_none(values)` | sum of byte counts, or `None` when the column is absent from the file |
| `gap_statistics(times)` | sorts known times, converts them to seconds since the first flow, applies `np.diff`, returns `np.mean` and `np.std`; returns `(None, None)` when fewer than two times are known |
| `describe(values)` | `count`, `mean`, `median`, 95th percentile and `max` with NumPy; `None` for an empty list |

### 4.4 `analyzer/detectors.py`

| Function | Rule |
|---|---|
| `detect_fanout(ip_stats, min_destinations)` | flag if `n_dst_ips >= min_destinations` |
| `detect_large_upload(ip_stats, min_src_bytes)` | flag if `src_bytes >= min_src_bytes`; IPs with `src_bytes = None` (column absent) are never flagged |
| `run_detectors(ip_stats, config)` | runs both rules and groups alerts by IP |
| `evaluate_against_labels(flagged, ip_stats)` | compares flagged IPs with label classes using set operations |

Label classes of a source IP:

| Class | Condition |
|---|---|
| bot | at least one of its flows has a `From-Botnet` label |
| normal | at least one `From-Normal` flow and no `From-Botnet` flow |
| background | all other IPs (not verified by the dataset authors) |

Evaluation counts:

| Count | Set expression | Meaning |
|---|---|---|
| `flagged_bots` | flagged ∩ bots | true positives |
| `missed_bots` | bots − flagged | false negatives |
| `flagged_normals` | flagged ∩ normals | false positives on verified clean hosts |
| `flagged_background` | flagged − bots − normals | flags that the labels cannot confirm or reject |

Background IPs are kept separate because counting them as false positives would
assume they are clean, which the dataset does not state.

### 4.5 `analyzer/config.py`

`load_config(path)` reads JSON and checks every key of `REQUIRED_KEYS` for presence,
type and (for integers) a minimum of 1. `true`/`false` are rejected for integer keys,
because `bool` is a subclass of `int` in Python. Any problem raises `ConfigError` with
the key name. Extra keys such as `_notes` are allowed and ignored.

### 4.6 `analyzer/report.py`

- `write_report_csv()` writes one row per flagged IP with the columns described in the
  README. Order: `n_dst_ips` descending, `src_bytes` descending, IP ascending. A fixed order
  makes output files reproducible and comparable.
- `build_summary()` builds the lines of `summary.txt`: loading counts and reasons,
  column information, NumPy statistics, thresholds (or a note that the upload rule was
  skipped), flagged IPs with evidence, label comparison (or a note that labels are absent),
  and a statement that a flag is not proof of infection.

### 4.7 `analyzer/plots.py`

- `plot_top_fanout()`: horizontal bar chart of the `plot_top_n` source IPs with the most
  distinct destinations; bars at or above the threshold in red, others in grey; threshold
  as a dashed line; logarithmic x axis because values range from tens to thousands.
- `plot_src_bytes_distribution()`: histogram of `log10(bytes sent + 1)` per source IP,
  logarithmic y axis, threshold as a dashed line. The `+ 1` avoids `log10(0)`.
- With no data, both functions still write a PNG stating "No data to plot".
- The `Agg` backend writes files without opening a window, so the program runs on
  machines without a display.

### 4.8 `main.py`

- `parse_arguments()` defines `--input` (required), `--config`, `--output`.
- `run()` executes the pipeline and returns the summary lines.
- `main()` catches `ConfigError`, `LoaderError` and `OSError`, prints `Error: <message>`
  to standard error and returns 1; otherwise prints the summary and returns 0.

### 4.9 Supporting scripts

- `make_sample.py`: copies the header and a block of consecutive rows from the original
  file without modification, and prints the SHA-256 of both files.
- `tune_thresholds.py`: for every distinct value of a measure, computes true positives,
  false positives and false negatives with vectorised NumPy comparisons, then precision,
  recall and F1; reports the threshold with the highest F1 and plots F1 against the
  threshold. All non-bot IPs count as negatives, so precision is a lower bound. A threshold
  chosen and scored on the same file is optimistic; this is printed with the result.

## 5. Error-handling policy

| Level | Example | Action |
|---|---|---|
| value | invalid port or time | keep the row, store `None` |
| row | invalid byte count, empty address, wrong field count | skip the row, count the reason |
| file | missing, empty, binary, required column absent | `LoaderError`, exit code 1 |
| configuration | missing key, wrong type, invalid JSON | `ConfigError`, exit code 1 |
| output | output folder not writable | `OSError`, exit code 1 |

No unhandled exception reaches the user for any input in `tests/bad_files/`; this is
verified by `test_every_bad_file_is_handled_without_crash`.

## 6. Design decisions

| Decision | Reason |
|---|---|
| `csv` module instead of pandas | file reading, iteration and dictionaries remain explicit, and each skipped row can be counted with its reason |
| match columns by name | files with reordered, renamed or extra columns are read correctly |
| only `SrcAddr` and `DstAddr` required | a file lacking an optional column is still analysed; affected parts are skipped and reported |
| rule-based detection | each decision is a visible comparison; no training data or model is needed |
| thresholds in `config.json` | values can be changed without editing code; no magic numbers |
| `>=` in both rules | the boundary is defined and tested explicitly |
| background label kept separate | avoids treating unverified hosts as clean |
| deterministic sorting | identical input gives identical output |

## 7. Complexity

Loading, grouping and statistics are each one pass over the rows: O(n) time for n rows.
Memory is O(n) because all valid flows are stored in a list. The sample (60,000 rows) is
processed in about three seconds and the full scenario file (114,077 rows) in about
four, including chart rendering.
