# Testing

This document lists every test input, the expected output for each, and how the
tests relate to the assessment criteria (functional correctness on schema edge cases,
robustness on unseen files, and one manually computed expected result).

## 1. Running the tests

```bash
python -m pytest            # all 57 tests
python -m pytest -v         # one line per test
python -m pytest tests/test_loader.py   # one file
```

`pytest.ini` sets the test folder and adds the project root to the import path, so the
command works from the project root without further setup.

Expected result:

```
57 passed
```

## 2. Test strategy

| Level | What is checked | Files |
|---|---|---|
| unit | each conversion function on valid and invalid text | `test_flow.py` |
| unit | the loader on one edge-case file per situation | `test_loader.py` |
| unit | statistics, rule boundaries, label evaluation, threshold scoring | `test_features_detectors.py` |
| integration | configuration errors, exit codes, the whole program on every edge-case file | `test_main_and_config.py` |
| acceptance | the whole program against a result computed by hand | `test_manual_expected.py` |

All test data under `tests/` is synthetic, written for testing, and not presented as
real traffic. Real data is used only in `data/sample.csv`.

## 3. Manually computed expected result

### 3.1 Input

`tests/data/tiny_manual.csv` (10 data rows, CTU-13 column layout):

```
StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label
2011/08/16 10:00:00.000000,0.5,tcp,10.0.0.1,1025,   ->,10.0.0.100,80,SRPA_SPA,0,0,4,100,60,flow=From-Botnet-V48-TCP-Test
2011/08/16 10:00:05.000000,1.0,tcp,10.0.0.2,1030,   ->,10.0.0.100,80,SRPA_SPA,0,0,10,5000,1500,flow=From-Normal-V48-Test
2011/08/16 10:00:10.000000,0.5,tcp,10.0.0.1,1026,   ->,10.0.0.101,80,SRPA_SPA,0,0,4,200,120,flow=From-Botnet-V48-TCP-Test
2011/08/16 10:00:20.000000,0.5,tcp,10.0.0.1,1027,   ->,10.0.0.102,443,SRPA_SPA,0,0,4,300,180,flow=From-Botnet-V48-TCP-Test
2011/08/16 10:00:25.000000,1.0,tcp,10.0.0.2,1031,   ->,10.0.0.100,80,SRPA_SPA,0,0,8,3000,900,flow=From-Normal-V48-Test
2011/08/16 10:00:30.000000,0.1,udp,10.0.0.1,1028,  <->,10.0.0.100,53,CON,0,0,2,400,240,flow=From-Botnet-V48-UDP-Test
2011/08/16 10:00:31.000000,0.0,icmp,10.0.0.3,0x0008,   ->,10.0.0.1,0x0008,ECO,0,0,1,98,98,flow=Background
2011/08/16 10:00:32.000000,0.2,tcp,10.0.0.4,2000,   ->,10.0.0.1,6667,SRPA_SPA,0,0,2,50,30,flow=To-Botnet-V48-Test
2011/08/16 10:00:33.000000,0.5,tcp,10.0.0.1,1029,   ->,10.0.0.103,80,SRPA_SPA,0,0,4,abc,60,flow=From-Botnet-V48-TCP-Test
2011/08/16 10:00:34.000000,0.5,tcp,,1029,   ->,10.0.0.104,80,SRPA_SPA,0,0,4,100,60,flow=Background
```

Configuration `tests/data/tiny_config.json`: fan-out threshold 3, large-upload threshold 2000.

The file contains, on purpose: a hexadecimal port (row 7), a `To-Botnet` label (row 8),
an invalid byte count (row 9) and an empty source address (row 10). Row 9 would give
`10.0.0.1` a fourth destination if it were wrongly accepted.

### 3.2 Calculation

| IP | rows kept | flows | TotBytes | SrcBytes | distinct destinations | distinct ports | gaps (s) |
|---|---|---|---|---|---|---|---|
| 10.0.0.1 | 1, 3, 4, 6 | 4 | 100+200+300+400 = 1000 | 60+120+180+240 = 600 | .100, .101, .102 = 3 | 80, 443, 53 = 3 | 10, 10, 10 → mean 10, std 0 |
| 10.0.0.2 | 2, 5 | 2 | 5000+3000 = 8000 | 1500+900 = 2400 | .100 = 1 | 80 = 1 | 20 → mean 20, std 0 |
| 10.0.0.3 | 7 | 1 | 98 | 98 | 1 | 8 (from `0x0008`) = 1 | one flow → none |
| 10.0.0.4 | 8 | 1 | 50 | 30 | 1 | 1 | one flow → none |

Rows read 10, kept 8, skipped 2 (`TotBytes is not a number`, `empty SrcAddr`).

Rules: `10.0.0.1` has exactly 3 destinations, and 3 >= 3, so it is flagged for fan-out.
`10.0.0.2` sent 2400 bytes, and 2400 >= 2000, so it is flagged for large upload.

Labels: bot = `10.0.0.1` only (`10.0.0.4` has `To-Botnet`, so it is not a bot);
normal = `10.0.0.2`. Bots flagged 1 of 1; normal hosts flagged 1 (a false alarm);
background hosts flagged 0.

The full working is in [tests/data/tiny_manual_EXPECTED.md](../tests/data/tiny_manual_EXPECTED.md).

### 3.3 Expected output

Command:

```bash
python main.py --input tests/data/tiny_manual.csv --config tests/data/tiny_config.json
```

`report.csv`:

```
src_ip,rules,evidence,n_flows,n_dst_ips,n_dst_ports,src_bytes,total_bytes,label_class
10.0.0.1,fanout,n_dst_ips=3 >= 3,4,3,3,600,1000,bot
10.0.0.2,large_upload,src_bytes=2400 >= 2000,2,1,1,2400,8000,normal
```

`summary.txt`:

```
Botnet Netflow Scenario Analyzer - summary
============================================
Input file: tests/data/tiny_manual.csv
Data rows read: 10
Valid flows used: 8
Rows skipped: 2
  - TotBytes is not a number: 1
  - empty SrcAddr: 1
Columns ignored (not used): Dur, Sport, Dir, State, sTos, dTos, TotPkts

Distinct source IPs: 4
Per source IP statistics (NumPy):
  n_flows: count=4 mean=2.0 median=1.5 p95=3.7 max=4
  n_dst_ips: count=4 mean=1.5 median=1.0 p95=2.7 max=3
  src_bytes: count=4 mean=782.0 median=349.0 p95=2130.0 max=2400

Rules (thresholds from config):
  fanout:       n_dst_ips >= 3
  large_upload: src_bytes >= 2000
Flagged source IPs: 2 (details in report.csv)
  10.0.0.1: n_dst_ips=3 >= 3
  10.0.0.2: src_bytes=2400 >= 2000

Comparison with dataset labels (an IP is a bot if it has a From-Botnet flow):
  Bot IPs in file: 1, labelled-normal IPs: 1
  Bots flagged: 1 of 1
  Bots missed: 0 []
  Labelled-normal IPs flagged (false alarms): 1
  Background IPs flagged (label unknown, not verified): 0

Note: a flag means 'unusual behaviour worth checking', not proof of infection.
Results are valid only for this file and these thresholds.
```

Checked by `tests/test_manual_expected.py` (three tests: loader counts, per-IP
statistics, whole-program report and summary).

## 4. Schema edge cases

Each file in `tests/bad_files/` isolates one situation that an unseen input file may
contain. Unless stated otherwise the header is the standard CTU-13 header:

```
StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label
```

### 4.1 Files that cannot be analysed (exit code 1)

| File | Input | Expected output |
|---|---|---|
| `empty.csv` | 0 bytes | `Error: file is empty (no header line): tests/bad_files/empty.csv` |
| `missing_dstaddr.csv` | header `StartTime,Proto,SrcAddr,Sport,Dport,TotBytes,SrcBytes,Label` | `Error: missing required column(s): DstAddr (found: StartTime, Proto, SrcAddr, Sport, Dport, TotBytes, SrcBytes, Label)` |
| `binary.csv` | bytes of a PNG image | `Error: file is not UTF-8 text (is it really a CSV?): tests/bad_files/binary.csv` |
| *(non-existent path)* | `nope.csv` | `Error: input file not found: ...` |

### 4.2 Files that are analysed (exit code 0)

| File | Input (data rows) | Expected behaviour | Key lines of `summary.txt` |
|---|---|---|---|
| `header_only.csv` | header, no rows | outputs written, no division by zero, empty charts | `Data rows read: 0` / `No valid flows: nothing to analyse.` |
| `no_label.csv` | standard header without `Label`, 2 rows | analysed; label comparison skipped; `label_class = no-label-column` | `Optional columns missing: Label` / `No Label column: comparison with ground truth skipped.` |
| `renamed_reordered.csv` | header `Label, dst_ip ,SRCADDR,Src_Bytes,TotBytes`, 2 rows | columns recognised by name; values read from the correct positions | `Valid flows used: 2` / `Optional columns missing: StartTime, Proto, Dport` |
| `extra_column.csv` | standard header plus `Country`, 2 rows | extra column ignored | `Columns ignored (not used): Dur, Sport, Dir, State, sTos, dTos, TotPkts, Country` |
| `bom.csv` | UTF-8 byte-order mark before `StartTime`, 1 row | first column recognised as `StartTime`; time parsed | `Valid flows used: 1` |
| `semicolon.csv` | same as standard but `;` separated, 1 row | separator detected | `Valid flows used: 1` |
| `single_flow.csv` | 1 row | time-gap statistics are `None`, not an error | `Distinct source IPs: 1` |
| `bad_time_and_port.csv` | `StartTime = not-a-date`, `Dport = 99999` | row kept; time and port stored as `None` | `Valid flows used: 1` / `Rows skipped: 0` |
| `bad_values.csv` | 6 rows: `TotBytes=-5`; `SrcBytes=abc`; `SrcBytes=1.5`; `TotBytes` empty; `DstAddr` empty; `TotBytes=100.0` | first five skipped, last accepted (`100.0` is a whole number) | `Data rows read: 6` / `Valid flows used: 1` / `Rows skipped: 5` with one line per reason |
| `wrong_field_count.csv` | valid row; 5-field row; 18-field row; blank line; valid row | short and long rows skipped; blank line ignored | `Data rows read: 4` / `Valid flows used: 2` / `- wrong number of fields (expected 15): 2` |

Full skip reasons for `bad_values.csv`:

```
Rows skipped: 5
  - SrcBytes is not a number: 1
  - SrcBytes is not a whole number: 1
  - TotBytes is empty: 1
  - TotBytes is negative: 1
  - empty DstAddr: 1
```

### 4.3 Whole-program robustness

`test_every_bad_file_is_handled_without_crash` runs `main()` on every file in
`tests/bad_files/` and accepts only exit code 0 or 1. Any unhandled exception fails the
test. New edge-case files placed in that folder are included automatically.

## 5. Unit tests of values and rules

| Test | Input | Expected |
|---|---|---|
| `parse_count` | `"214"`, `" 100.0 "` | `214`, `100` |
| `parse_count` rejects | `""`, `"abc"`, `"-5"`, `"1.5"` | `ValueError` |
| `parse_port` | `"53"`, `"0x0008"`, `"08"`, `""`, `"xyz"`, `"99999"` | `53`, `8`, `8`, `None`, `None`, `None` |
| `parse_time` | `"2011/08/16 10:01:46.972101"`, `"not-a-date"`, `""` | datetime with second 46, `None`, `None` |
| label direction | `From-Botnet`, `To-Botnet`, `From-Normal` | bot, not bot, normal |
| distinct destinations | A→X, A→X, A→Y, B→X | A: 3 flows, 2 destinations; B: 1 destination |
| time gaps | two flows 10 s apart | mean 10.0, std 0.0 |
| `describe` | `[]`; `[1, 2, 3, 4]` | `None`; mean 2.5, median 2.5, max 4 |
| fan-out boundary (threshold 50) | 49, 50, 51 destinations | 50 and 51 flagged, 49 not |
| upload boundary (threshold 1000) | 999, 1000, `None` bytes | only 1000 flagged |
| both rules on one IP | 10 destinations, 5000 bytes, thresholds 10 / 5000 | two alerts; evidence `n_dst_ips=10 >= 10` |
| label evaluation | victim flagged, bot not flagged | 1 bot, 0 flagged bots, missed `["bot"]`, 1 flagged background |
| threshold scoring | values 1, 5, 10, 20; bots at 10, 20; thresholds 5, 10 | TP 2, 2; FP 1, 0; FN 0, 0; F1 at 10 = 1.0 |

## 6. Configuration tests

| Input `config.json` | Expected |
|---|---|
| the project's `config.json` | loads |
| `fanout_min_destinations` missing | `ConfigError` naming the key |
| `"fanout_min_destinations": "50"` (text) | `ConfigError`: must be of type int |
| `"fanout_min_destinations": 0` | `ConfigError`: must be at least 1 |
| `[1, 2, 3]` | `ConfigError`: must contain a JSON object |
| `{ not json` | `ConfigError`: not valid JSON |

## 7. Run on real data

Command:

```bash
python main.py --input data/sample.csv --config config.json
```

Expected key lines (full output in [example_outputs/summary.txt](example_outputs/summary.txt)):

```
Data rows read: 60000
Valid flows used: 60000
Rows skipped: 0
Distinct source IPs: 13554
Flagged source IPs: 27 (details in report.csv)
  Bots flagged: 0 of 1
  Bots missed: 1 ['147.32.84.165']
  Labelled-normal IPs flagged (false alarms): 0
  Background IPs flagged (label unknown, not verified): 27
```

The interpretation of this result is in [data/DATA.md](../data/DATA.md).
