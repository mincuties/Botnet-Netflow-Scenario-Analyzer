# Botnet Netflow Scenario Analyzer

A command-line program that reads a netflow capture, describes the behaviour of every
host in the monitored network, scores each host on several botnet-related signals, and
reports the suspicious hosts with the evidence behind every flag. When the capture carries
CTU-13 labels, the program also measures its own result against the ground truth.

The program is written in Python with the standard library, NumPy and Matplotlib.
An optional decision-tree layer uses scikit-learn.

## Contents

1. [Quick start](#1-quick-start)
2. [How the program works](#2-how-the-program-works)
3. [Input](#3-input)
4. [Output](#4-output)
5. [Configuration](#5-configuration)
6. [Data](#6-data)
7. [Evaluation](#7-evaluation)
8. [Testing](#8-testing)
9. [Project structure](#9-project-structure)
10. [Assessment criteria](#10-assessment-criteria)
11. [Limitations](#11-limitations)
12. [Acknowledgement](#12-acknowledgement)

## 1. Quick start

Requirements: Python 3.10 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS / Linux: source .venv/bin/activate
pip install -r requirements.txt

python main.py --input data/sample.csv                 # rule-based analysis
python main.py --input data/sample.csv --ml            # plus the decision tree
python main.py --input data/scenarios/scenario11.binetflow.gz
python -m pytest                                       # 94 tests
```

| Argument | Required | Default | Meaning |
|---|---|---|---|
| `--input` | yes | | netflow CSV file, plain or gzip-compressed (`.gz`) |
| `--config` | no | `config.json` | settings file |
| `--output` | no | `outputs` | folder for the results (created if missing) |
| `--ml` | no | off | also use the trained decision tree |

Exit code `0` means the analysis finished. Exit code `1` means the input, the
configuration, the blocklist or the model could not be used; a one-line message starting
with `Error:` explains why, and no Python traceback is shown.

## 2. How the program works

```
input CSV ─► loader ─► Flow objects ─┬─► per-host statistics (whole file) ─┐
                                     ├─► per-host 5-minute windows ────────┤
                                     ├─► timing regularity per host pair ──┼─► signals ─► score ─► severity ─► outputs
                                     ├─► blocklist hits ───────────────────┤
                                     └─► decision tree (optional) ─────────┘
```

### 2.1 Loading

`analyzer/loader.py` reads the file with the `csv` module, matches columns by name,
converts every value, and skips rows that cannot be trusted, counting each skip by reason.
Each valid row becomes a `Flow` object (`analyzer/flow.py`). Files ending in `.gz` are
decompressed while reading.

### 2.2 Statistics

| Level | Key | Numbers | Module |
|---|---|---|---|
| host | source IP | flows, distinct destination IPs and ports (sets), bytes sent, TCP attempts and failures, first and last time seen | `features.py` |
| window | (source IP, window number) | the same counts inside each 5-minute window | `windows.py` |
| host pair | (source IP, destination IP) | regularity of the gaps between flows | `features.py` |

Windows matter because whole-file totals hide short events: a two-minute attack inside a
two-hour capture barely changes the totals of the host.

### 2.3 Signals

Only hosts of the monitored network (`monitored_prefix`, default `147.32.`) are judged.
Each signal is one comparison with a threshold from `config.json`.

| Signal | Fires when | Typical botnet behaviour | Group | Points |
|---|---|---|---|---|
| `fanout` | distinct destination IPs ≥ 50 | scanning, spam | spread | 2 |
| `port_scan` | distinct destination ports in one window ≥ 20 | port scanning | spread | 2 |
| `failed_tcp` | share of failed TCP attempts ≥ 0.5, after ≥ 20 attempts | scanning closed hosts | spread | 2 |
| `large_upload` | bytes sent ≥ 10,000,000 | flooding, data theft | volume | 2 |
| `burst` | flows in one window ≥ the 99.9th percentile of all windows (at least 100) | DDoS attack | volume | 2 |
| `beaconing` | gaps to one destination have a coefficient of variation ≤ 0.1, over ≥ 10 flows | automatic contact with a command server | control | 1 |
| `blocklist` | any flow to a known command-and-control (C&C) server | contact with a known botnet | control | 3 |
| `ml` (with `--ml`) | decision-tree bot probability ≥ 0.5 | learned combination of the numbers above | ml | 2 |

Definitions:

- **Failed TCP attempt.** CTU-13 writes the TCP flags of both sides as `SOURCE_DEST`. An
  attempt failed when the source sent a SYN (`S` before `_`) and the destination never sent
  one back (no `S` after `_`), as in `S_RA`.
- **Coefficient of variation (CV).** `std(gaps) / mean(gaps)`. Gaps of 10, 10, 10 seconds give
  CV 0 (a timer); people browsing give CV near 1 or higher.
- **Burst threshold.** `np.percentile` of the flow counts of every (host, window) in the file.
  It adapts to the size of the network: 544 flows in scenario 5, 756 in scenario 10.

### 2.4 Score and severity

Signals that describe the same behaviour belong to one group, and each group adds at most a
fixed number of points (`group_caps`: spread 2, volume 2, control 3, ml 2). A scanner fires
both `fanout` and `port_scan`; the cap counts that behaviour once.

| Score | Severity | Reported |
|---|---|---|
| 0 | none | no |
| 1 – 2 | low | counted in the summary only |
| 3 – 4 | medium | `report.csv` |
| ≥ 5 | high | `report.csv` and `recommended_blocks.csv` |

With these settings a host reaches medium only with evidence from two different groups, or
by contacting a known C&C server. A single unusual number, such as the fan-out of a DNS
resolver, is not enough. This keeps the number of alarms an operator must review low.

### 2.5 C&C blocklist

`data/blocklist.txt` holds 10 C&C server addresses. `build_blocklist.py` collected them from
the flows labelled as command-and-control (`-CC<number>` in the label) in scenario 10. The list
plays the role of a threat-intelligence feed: it is built from one capture and used on others.

### 2.6 Decision tree (optional)

`train_model.py` trains a scikit-learn `DecisionTreeClassifier` on every (host, 5-minute
window) of scenarios 5 and 10: 293,988 windows, 203 of them with botnet traffic. Each window
is described by six numbers: flows, distinct destination IPs, distinct destination ports,
`log10` of bytes sent, `log10` of bytes per flow, and the failed-TCP share. IP addresses are
never used, so the tree cannot memorise the bot addresses that repeat across CTU-13
scenarios. A host's probability is that of its most suspicious window.

| Setting | Value | Reason |
|---|---|---|
| `max_depth` | 4 | the tree can be read rule by rule ([text](docs/results/decision_tree.txt), [picture](docs/results/decision_tree.png)) |
| `class_weight` | `balanced` | bot windows are 0.07 % of the data |
| `min_samples_leaf` | 20 | no rule rests on a handful of windows |
| `random_state` | 0 | training twice gives the same tree (tested) |

The trained model is committed as `models/decision_tree.pkl`. scikit-learn is imported only
when `--ml` is used, so the rest of the program runs without it.

### 2.7 Response

`recommended_blocks.csv` lists the high-severity hosts with the action "review, then block at
the network edge". The program never blocks anything: a flag is evidence for a person to check,
not proof of infection.

## 3. Input

A CSV file with a header line, in the CTU-13 `.binetflow` layout or any layout that has the
required columns. Columns are matched by **name**, ignoring letter case, spaces, `_` and `-`;
common alternative names are accepted (for example `src_ip` for `SrcAddr`).

| Column | Required | Used for |
|---|---|---|
| `SrcAddr`, `DstAddr` | yes | grouping, distinct destinations, blocklist |
| `StartTime` | no | windows, burst, port scan, beaconing; format in `config.json` |
| `Dport` | no | distinct ports; decimal and hexadecimal (`0x0008`) accepted |
| `SrcBytes` | no | large upload, decision tree |
| `TotBytes` | no | report |
| `Proto`, `State` | no | failed TCP attempts |
| `Label` | no | comparison with ground truth |

When an optional column is missing, the signals that need it cannot fire, and the summary
says which ones.

| Situation | Behaviour |
|---|---|
| file missing, empty, binary, or missing a required column | stop, `Error: ...`, exit code 1 |
| header only | outputs written, summary states "No valid flows" |
| empty `SrcAddr` or `DstAddr` | row skipped, counted by reason |
| byte count empty, not a whole number, or negative | row skipped, counted by reason |
| row with a different number of fields from the header | row skipped, counted by reason |
| invalid port or time | row kept, value left empty |
| blank line | ignored |
| unknown extra columns | ignored, listed in the summary |
| comma, semicolon or tab separator; UTF-8 byte-order mark | detected automatically |

## 4. Output

| File | Content |
|---|---|
| `summary.txt` | rows read, used and skipped with reasons; NumPy statistics; every signal rule as applied; flagged hosts with evidence; comparison with labels |
| `report.csv` | one row per medium or high host |
| `recommended_blocks.csv` | high-severity hosts and the recommended action |
| `top_fanout.png` | hosts with the most distinct destinations, threshold marked |
| `src_bytes_hist.png` | distribution of bytes sent per host, threshold marked |
| `score_distribution.png` | number of hosts per score, coloured by severity |

`report.csv` columns: `src_ip`, `severity`, `score`, `signals`, `evidence`, `n_flows`,
`n_dst_ips`, `n_dst_ports`, `src_bytes`, `total_bytes`, `first_seen`, `last_seen`,
`label_class` (`bot`, `normal`, `background` or `no-label-column`). The `evidence` column
gives the measured value and the threshold of every signal, for example
`burst: flows in one window=2812 >= 503`. Rows are sorted by score, then destinations, then
bytes, then IP, so the same input always gives the same file.

Outputs of `python main.py --input data/sample.csv` are in
[docs/example_outputs/](docs/example_outputs/). On that sample (60,000 flows, 13,554 source
IPs, 272 of them monitored) the program reports 9 hosts: 1 high and 8 medium; 33 more are low.
The single bot of the capture is not among them (section 7.4).

## 5. Configuration

Every value that changes the result is in `config.json`; the `_notes` key describes each one.

| Key | Value |
|---|---|
| `time_format` | `%Y/%m/%d %H:%M:%S.%f` |
| `window_seconds` | 300 |
| `monitored_prefix` | `147.32.` (empty text = judge every host) |
| `blocklist_file` | `data/blocklist.txt` (empty text = no blocklist) |
| `plot_top_n` | 15 |
| `signals` | threshold, points and group of each signal (section 2.3) |
| `group_caps` | spread 2, volume 2, control 3, ml 2 |
| `severity` | low 1, medium 3, high 5 |
| `ml` | `enabled` false, `model_file` `models/decision_tree.pkl`, `min_probability` 0.5, `points` 2 |

File names are relative to the folder of `config.json`. A missing key, a value of the wrong
type, a value out of range (for example a share above 1 or a percentile above 100), severity
levels out of order, or a group without a cap stops the program with a message naming the key.

The thresholds were chosen on scenario 5 only and then left unchanged for all other scenarios
(section 7.1).

## 6. Data

Dataset: CTU-13, Stratosphere Lab, Czech Technical University in Prague, 2011
(https://www.stratosphereips.org/datasets-ctu13). S. García, M. Grill, J. Stiborek,
A. Zunino, "An empirical comparison of botnet detection methods", *Computers & Security* 45
(2014) 100–123.

Each scenario is one capture of a university network in which one or more machines were
infected on purpose. Every flow is labelled:

| Label | Meaning |
|---|---|
| `From-Botnet` | the source is an infected machine |
| `To-Botnet` | the destination is an infected machine (the source is not) |
| `From-Normal` | the source is a verified clean machine |
| `Background` | not verified either way |

### 6.1 Files

| File | Scenario (capture) | Family | Flows | Original file and SHA-256 |
|---|---|---|---|---|
| `data/scenarios/scenario05.binetflow.gz` | 5 (Botnet-46) | Virut | 129,832 | `capture20110815-2.binetflow`, `ef5c9ed6895d4ca5aec723449dae30054ccd1f6b091713a52ffcb681ff78a02c` |
| `data/scenarios/scenario07.binetflow.gz` | 7 (Botnet-48) | Sogou | 114,077 | `capture20110816-2.binetflow`, `df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680` |
| `data/scenarios/scenario10.binetflow.gz` | 10 (Botnet-51) | Rbot | 1,309,791 | `capture20110818.binetflow`, `840a7030d57cb965a4e6e19c61e89b20647a4aefe5608c2da90623710e7cd74f` |
| `data/scenarios/scenario11.binetflow.gz` | 11 (Botnet-52) | Rbot | 107,251 | `capture20110818-2.binetflow`, `cee542d4b5efe4fa1cd59b87ece5aaea9a13d8f0abe56cd07cee31590736428c` |
| `data/scenarios/scenario12.binetflow.gz` | 12 (Botnet-53) | NSIS.ay | 325,471 | `capture20110819.binetflow`, `1098f0addacedc321c7baefad63ef0d9a0f26630d0155087d37e8da770dd9f2e` |
| `data/sample.csv` | 7, first 60,000 flows | Sogou | 60,000 | SHA-256 `c39e968afa6fe1d184dc63f1cc234bf044479ca6dff6a463af1df8659d24d8b1` |

Original files: `https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-<N>/detailed-bidirectional-flow-labels/`
with `<N>` from the table. The `.gz` files are the original files compressed with `gzip -n`,
unchanged otherwise; `gunzip` restores them byte for byte, and the checksum of the result can
be compared with the table (`sha256sum` on Linux, `shasum -a 256` on macOS,
`certutil -hashfile <file> SHA256` on Windows). `data/sample.csv` is produced by
`python make_sample.py --source capture20110816-2.binetflow --output data/sample.csv --rows 60000`;
it contains all 63 botnet flows of scenario 7.

In scenario 12 the label `From-Botnet` is also attached to external peer-to-peer hosts that
talk to the bots. They are outside `147.32.` and therefore not counted; the scenario has three
infected local machines.

All files under `tests/` are small synthetic files written for testing.

## 7. Evaluation

### 7.1 Method

`python evaluate.py` runs three configurations on every scenario and writes
[docs/results/evaluation.md](docs/results/evaluation.md) and `.csv`:

| Configuration | Meaning |
|---|---|
| baseline | two simple rules, fan-out or large upload, either one alone flags the host |
| rules | the default configuration (all signals, group caps, severity, blocklist) |
| rules_ml | rules plus the decision tree (`--ml`) |

Ground truth for a monitored host: **bot** if it sent a `From-Botnet` flow; **normal** if it sent
a `From-Normal` flow and no botnet flow; **background** otherwise. A flag on a normal host is a
false alarm; a flag on a background host cannot be confirmed either way and is counted
separately. Precision (`bots flagged / all flagged`) treats background as not bot, so it is a
lower bound.

Measures against over-fitting:

- thresholds chosen on scenario 5 only ("dev"); scenarios 10, 11, 12 and 7 are "test";
- the blocklist comes from scenario 10, so it is switched off when scenario 10 is scored;
- the tree is trained on scenarios 5 and 10 and scored only on 11, 12 and 7;
- no setting was changed after looking at test results.

### 7.2 Results

| Scenario | Configuration | Bots flagged | Normal hosts flagged | Background flagged | Precision |
|---|---|---|---|---|---|
| 5 (dev) | baseline | 1 / 1 | 3 / 6 | 29 | 0.03 |
| 5 (dev) | rules | 1 / 1 | 1 / 6 | 12 | 0.07 |
| 10 | baseline | 10 / 10 | 4 / 7 | 97 | 0.09 |
| 10 | rules | 10 / 10 | 1 / 7 | 29 | 0.25 |
| 11 | baseline | 2 / 3 | 0 / 6 | 30 | 0.06 |
| 11 | rules | 3 / 3 | 0 / 6 | 13 | 0.19 |
| 11 | rules_ml | 3 / 3 | 1 / 6 | 39 | 0.07 |
| 12 | baseline | 3 / 3 | 3 / 6 | 49 | 0.05 |
| 12 | rules | 1 / 3 | 1 / 6 | 20 | 0.05 |
| 12 | rules_ml | 3 / 3 | 3 / 6 | 70 | 0.04 |
| 7 | baseline | 0 / 1 | 0 / 5 | 35 | 0.00 |
| 7 | rules | 0 / 1 | 0 / 5 | 10 | 0.00 |
| 7 | rules_ml | 0 / 1 | 1 / 5 | 43 | 0.00 |

Totals over the four test scenarios:

| Configuration | Bots flagged | Normal hosts flagged | Background flagged |
|---|---|---|---|
| baseline | 15 / 17 (88 %) | 7 / 24 | 211 |
| rules | 14 / 17 (82 %) | 2 / 24 | 72 |

Totals over scenarios 11, 12 and 7, where the tree may be scored:

| Configuration | Bots flagged | Normal hosts flagged | Background flagged |
|---|---|---|---|
| baseline | 5 / 7 | 3 / 17 | 114 |
| rules | 4 / 7 | 1 / 17 | 43 |
| rules_ml | 6 / 7 | 5 / 17 | 152 |

### 7.3 Interpretation

- **Default rules against the baseline.** Almost the same number of bots (14 against 15 of 17)
  with far fewer alarms: false alarms on verified normal hosts fall from 7 to 2 and unverified
  flags from 211 to 72. An operator would review 72 hosts across four captures instead of 211.
- **Which signals found the bots.** All 10 bots of scenario 10 and one bot of scenario 11 fire
  `large_upload`, `port_scan` and `burst` (DDoS traffic). In scenario 11, `147.32.84.192` sent
  only 7 flows and is found by the blocklist alone; `147.32.84.191` reaches high severity with the
  blocklist. In scenario 12, `147.32.84.165` fires `fanout`, `port_scan` and `burst`.
- **What the score costs.** Two bots of scenario 12 fire only spread signals (`fanout`,
  `port_scan`), stay at low severity and are not reported. The baseline reports them. Requiring
  two kinds of evidence trades these two bots for 139 fewer alarms.
- **Blocklist.** Useful against a family seen before (Rbot in scenarios 10 and 11); no effect on
  other families (12, 7). On the sample of scenario 7 it reports one background host that
  contacted a listed address once.
- **Decision tree.** It finds the two scenario 12 bots that the rules leave at low severity
  (4 → 6 of 7), but raises false alarms on normal hosts from 1 to 5 and unverified flags from 43
  to 152. With two training scenarios and 203 bot windows it is not better overall than the rules,
  so it stays optional. The sweep of `ml.min_probability` in
  [docs/results/ml_threshold_sweep.md](docs/results/ml_threshold_sweep.md) shows that 0.9 would
  remove most of the extra alarms (scenario 11: background 39 → 14, normal hosts 1 → 0) while
  losing one scenario 12 bot. That value was observed on test scenarios, so it is reported and
  not applied.

### 7.4 Missed bot and recurring false alarm

- The Sogou bot of scenario 7 (`147.32.84.165`) sent 63 flows to 17 destinations and 447,399
  bytes in about ten minutes; about a third of its flows are DNS lookups. No signal and no
  configuration, including the tree, flags it. A labelled-normal host of the same capture
  contacted more destinations (35). Detecting such a quiet bot would need information that
  netflow does not carry, such as the domain names it resolves.
- The normal host `147.32.84.170` is flagged in scenarios 5, 10 and 12 for wide fan-out with
  regular timing. A deployed system would keep an allowlist of known servers.

### 7.5 Why the project uses more than simple threshold rules

The course guideline asks for simple algorithms. The measurements above are the reason the
project goes further in four places, each kept as small and explainable as possible:

| Technique | Why it is needed | Evidence |
|---|---|---|
| 5-minute windows and a percentile threshold | DDoS bots contact few hosts (10 to 12 in scenario 10) but send thousands of flows in minutes; whole-file totals hide this | `port_scan` and `burst` fire for all 10 bots of scenario 10 |
| scoring with group caps and severity | a single rule flags many harmless busy hosts | normal hosts flagged 7 → 2, unverified flags 211 → 72 |
| C&C blocklist | a bot that sends almost nothing is invisible to behaviour signals | finds `147.32.84.192` in scenario 11 (7 flows) |
| decision tree (optional) | shows what a learned model adds and what it costs | 2 more bots, 4 more false alarms; off by default |

Each technique is still built from course material: dictionaries keyed by tuples, sets,
NumPy percentiles and standard deviations, and a depth-4 tree that can be printed as nested
if-statements.

### 7.6 Running time

On scenario 10 (1,309,791 flows, 179 MB uncompressed) loading takes about 25 seconds and
700 MB of memory; `evaluate.py` over all five scenarios takes about two minutes.

## 8. Testing

```bash
python -m pytest        # 94 tests, about 10 seconds
```

| File | Covers |
|---|---|
| `tests/test_flow.py` | counts, decimal and hexadecimal ports, times, label direction |
| `tests/test_loader.py` | one test per edge-case file in `tests/bad_files/` (13 files) |
| `tests/test_features_detectors.py` | distinct counts, gaps, beaconing CV by hand, every signal at its boundary, group caps, severity levels, monitored prefix, label evaluation |
| `tests/test_windows_blocklist.py` | window boundaries, burst percentile and minimum, tree features, blocklist file and hits |
| `tests/test_ml_model.py` | training is reproducible, probabilities, the shipped model with `--ml` (skipped without scikit-learn) |
| `tests/test_main_and_config.py` | ten invalid configurations, exit codes, missing blocklist or model, missing scikit-learn, missing `State`/`StartTime`/`Label` columns, the whole program on every edge-case file |
| `tests/test_manual_expected.py` | the whole program against the hand-computed case below, and identical output on two runs |

### 8.1 Hand-computed test case

Input `tests/data/tiny_manual.csv` (synthetic, CTU-13 layout), with
`tests/data/tiny_config.json` (small thresholds) and `tests/data/tiny_blocklist.txt`
(one listed address, `10.0.0.102`):

| Row | Time 10:00:.. | Proto | Source | Destination | Port | State | TotBytes | SrcBytes | Label | Kept |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 00 | tcp | 10.0.0.1 | 10.0.0.100 | 80 | SRPA_SPA | 100 | 60 | From-Botnet | yes |
| 2 | 05 | tcp | 10.0.0.2 | 10.0.0.100 | 80 | SRPA_SPA | 5000 | 1500 | From-Normal | yes |
| 3 | 10 | tcp | 10.0.0.1 | 10.0.0.101 | 80 | SRPA_SPA | 200 | 120 | From-Botnet | yes |
| 4 | 20 | tcp | 10.0.0.1 | 10.0.0.102 | 443 | S_RA | 300 | 180 | From-Botnet | yes |
| 5 | 25 | tcp | 10.0.0.2 | 10.0.0.100 | 80 | SRPA_SPA | 3000 | 900 | From-Normal | yes |
| 6 | 30 | udp | 10.0.0.1 | 10.0.0.100 | 53 | CON | 400 | 240 | From-Botnet | yes |
| 7 | 31 | icmp | 10.0.0.3 | 10.0.0.1 | 0x0008 | ECO | 98 | 98 | Background | yes, port 8 |
| 8 | 32 | tcp | 10.0.0.4 | 10.0.0.1 | 6667 | SRPA_SPA | 50 | 30 | To-Botnet | yes |
| 9 | 33 | tcp | 10.0.0.1 | 10.0.0.103 | 80 | SRPA_SPA | abc | 60 | From-Botnet | no: TotBytes is not a number |
| 10 | 34 | tcp | *(empty)* | 10.0.0.104 | 80 | SRPA_SPA | 100 | 60 | Background | no: empty SrcAddr |

**Rows.** 10 read, 8 kept, 2 skipped. Row 9 would give `10.0.0.1` a fourth destination if it
were wrongly accepted.

**Per host.**

| Host | Flows | SrcBytes | Destinations | Ports | TCP attempts / failed | Window 0 flows |
|---|---|---|---|---|---|---|
| 10.0.0.1 | 4 | 60+120+180+240 = 600 | .100 .101 .102 = 3 | 80 443 53 = 3 | 3 / 1 (row 4) | 4 |
| 10.0.0.2 | 2 | 1500+900 = 2400 | 1 | 1 | 2 / 0 | 2 |
| 10.0.0.3 | 1 | 98 | 1 | 1 | 0 / 0 | 1 |
| 10.0.0.4 | 1 | 30 | 1 | 1 | 1 / 0 | 1 |

All rows fall in the first 5-minute window. Burst threshold = max(minimum 4, 100th percentile
of [4, 2, 1, 1] = 4) = 4.

**Signals and score** (caps spread 2, volume 2, control 3; medium ≥ 2, high ≥ 5 in the tiny
configuration):

| Host | Signals | Score | Severity |
|---|---|---|---|
| 10.0.0.1 | fanout 3 ≥ 3, port_scan 3 ≥ 3 (spread 4, capped to 2); burst 4 ≥ 4 (volume 2); blocklist, row 4 (control 3); failed_tcp 1/3 < 0.5 does not fire | 2 + 2 + 3 = 7 | high |
| 10.0.0.2 | large_upload 2400 ≥ 2000 (volume 2) | 2 | medium |
| 10.0.0.3, 10.0.0.4 | none | 0 | none |

**Labels.** Bot: `10.0.0.1`. `10.0.0.4` is not a bot: `To-Botnet` means the bot is the
destination. Normal: `10.0.0.2`. Result: bots flagged 1 of 1; normal hosts flagged 1 (a false
alarm); background flagged 0.

**Expected output** (checked line by line by `tests/test_manual_expected.py`):

```
report.csv
10.0.0.1,high,7,fanout;port_scan;burst;blocklist,...,bot
10.0.0.2,medium,2,large_upload,...,normal

recommended_blocks.csv
10.0.0.1,7,fanout;port_scan;burst;blocklist,...
```

### 8.2 Edge-case files

| File in `tests/bad_files/` | Expected |
|---|---|
| `empty.csv` | `Error: file is empty`, exit code 1 |
| `missing_dstaddr.csv` | `Error: missing required column(s): DstAddr`, exit code 1 |
| `binary.csv` | `Error: file is not UTF-8 text`, exit code 1 |
| `header_only.csv` | outputs written, "No valid flows" |
| `no_label.csv` | analysed, label comparison skipped |
| `renamed_reordered.csv` | columns found by name in a different order |
| `extra_column.csv` | extra column ignored and listed |
| `bom.csv` | byte-order mark removed, first column recognised |
| `semicolon.csv` | `;` separator detected |
| `single_flow.csv` | no gap statistics, no error |
| `bad_time_and_port.csv` | row kept, time and port empty |
| `bad_values.csv` | 5 of 6 rows skipped, one line per reason |
| `wrong_field_count.csv` | short and long rows skipped, blank line ignored |

`test_every_bad_file_is_handled_without_crash` runs the whole program on every file in that
folder and accepts only exit code 0 or 1.

## 9. Project structure

```
main.py                 command-line entry point
config.json             all settings
evaluate.py             measures baseline, rules and rules_ml on every scenario
build_blocklist.py      builds data/blocklist.txt from scenario 10
train_model.py          trains models/decision_tree.pkl on scenarios 5 and 10
tune_thresholds.py      scores thresholds of one signal against the labels (F1)
make_sample.py          reproduces data/sample.csv
requirements.txt
analyzer/
  flow.py               Flow dataclass and value parsers
  loader.py             CSV and gzip reading, column matching, row validation
  features.py           per-host statistics, timing regularity
  windows.py            5-minute windows, burst threshold, tree features
  blocklist.py          C&C list reading and matching
  detectors.py          signals, score, severity, comparison with labels
  ml_model.py           optional decision tree
  pipeline.py           runs the steps in order
  config.py             settings checks
  report.py             report.csv, recommended_blocks.csv, summary.txt
  plots.py              charts
data/
  sample.csv            60,000 flows of scenario 7
  scenarios/            five CTU-13 scenarios (gzip)
  blocklist.txt         10 C&C addresses
models/
  decision_tree.pkl     trained tree
docs/
  example_outputs/      outputs of the run on data/sample.csv
  results/              evaluation tables, threshold sweep, tree as text and picture
tests/
  bad_files/            13 edge-case files
  data/                 hand-computed test case
```

## 10. Assessment criteria

| Criterion | Where it is addressed |
|---|---|
| Data and reproducibility | sources, links and SHA-256 checksums (section 6); `requirements.txt`; fixed random seed; scripts that rebuild the sample, the blocklist, the model and every result table; deterministic output order |
| Functional correctness | columns by name, required and optional columns, gzip input, row validation with counted reasons, clear errors (section 3) |
| Course concepts | functions with one task each; `dict` keyed by IP and by `(IP, window)` tuples; `set` for distinct counts; `Counter`; CSV, JSON and gzip file I/O; NumPy (`diff`, `mean`, `std`, `percentile`); Matplotlib; `dataclass` (`Flow`, `Signal`, `Detection`, `Analysis`); custom exceptions |
| Testing | 94 tests, 13 edge-case files, one hand-computed case, boundary tests for every signal (section 8) |
| Analysis | evidence for every flag; comparison with labels; dev/test split; baseline comparison; missed bot and false alarms reported (section 7) |
| Code quality | small modules with docstrings, all thresholds in `config.json`, optional dependency isolated |

## 11. Limitations

- Quiet bots are missed (section 7.4).
- 17 bot hosts across the test scenarios: one bot more or less changes recall by about
  6 points, so counts are always given next to percentages.
- Most flags fall on background hosts that the dataset does not verify.
- The program analyses one file at a time, offline, and keeps all flows in memory.
- The blocklist knows only the servers seen in scenario 10; real lists change daily.
- The decision tree is trained on two captures of two families and does not generalise well.

## 12. Acknowledgement

An AI assistant (Claude) was used during development.
