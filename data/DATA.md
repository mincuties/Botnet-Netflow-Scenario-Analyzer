# Data source, sample and analysis

## 1. Source

| Item | Value |
|---|---|
| Dataset | CTU-13, scenario 7 (capture CTU-Malware-Capture-Botnet-48, bot family **Sogou**) |
| Publisher | Stratosphere Lab, Czech Technical University (CTU), Prague, 2011 |
| Paper | S. García, M. Grill, J. Stiborek, A. Zunino, "An empirical comparison of botnet detection methods", *Computers & Security* 45 (2014) 100-123 |
| Dataset page | https://www.stratosphereips.org/datasets-ctu13 |
| Download folder | https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/ |
| Original file | `capture20110816-2.binetflow` (bidirectional Argus netflows with labels) |
| Downloaded | 2026-10-27 |
| Size | 15,630,512 bytes, 1 header line + 114,077 flows |
| SHA-256 | `df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680` |

The original file is not committed (`data/raw/` is in `.gitignore`). To reproduce,
download it into `data/raw/` and check the checksum:

```bash
# Linux:   sha256sum data/raw/capture20110816-2.binetflow
# macOS:   shasum -a 256 data/raw/capture20110816-2.binetflow
# Windows: certutil -hashfile data\raw\capture20110816-2.binetflow SHA256
```

## 2. The sample `data/sample.csv`

```bash
python make_sample.py --source data/raw/capture20110816-2.binetflow --output data/sample.csv --rows 60000
```

| Item | Value |
|---|---|
| Content | header + the **first 60,000 flows**, copied byte for byte (no cleaning, no editing) |
| Time covered | 2011/08/16 13:51:24 to 14:01:45 (about 10 minutes) |
| Why these rows | a single block from the start keeps the traffic as recorded; it contains all 63 From-Botnet flows of the scenario (the last one is at line 52,257 of the original) |
| Size | 8,230,198 bytes |
| SHA-256 | `c39e968afa6fe1d184dc63f1cc234bf044479ca6dff6a463af1df8659d24d8b1` |

Label meanings in CTU-13: `From-Botnet` = the source is the infected machine;
`To-Botnet` = the destination is the infected machine; `From-Normal` = the source is a
verified clean machine; `Background` = not verified either way.

In this scenario only **one** machine is infected: `147.32.84.165`.

## 3. Results on the sample (default `config.json`)

Command: `python main.py --input data/sample.csv --config config.json`
(copies of the outputs are in [docs/example_outputs/](../docs/example_outputs/)).

**Data quality.** 60,000 rows read, 60,000 used, 0 skipped. CTU-13 is clean; the
skip logic is exercised by the files in `tests/bad_files/` instead.

**What normal looks like.** 13,554 distinct source IPs. 13,237 of them (97.7 %)
contacted exactly one destination; the 95th percentile of `n_dst_ips` is 1 and the
95th percentile of bytes sent is 4,482 bytes.

**Why the thresholds.**
- Fan-out 50: far above what almost every host does (p95 = 1). The five labelled-normal
  machines contacted 3 to 35 destinations, so 50 is above all of them and gives no false
  alarm on a verified clean machine. 19 IPs reach 50.
- Large upload 10,000,000 bytes (10 MB): more than 2,000 times the p95. 10 IPs reach it.

**Flags.** 27 source IPs are flagged (19 fan-out, 10 large upload, 2 both). All 27
have a `Background` label, so the dataset cannot say whether they are infected. The
top one, `147.32.84.229`, contacted 5,124 different IPs on 4,926 different ports in
10 minutes. Six of the 10 large-upload IPs are outside the university network
(not `147.32.x.x`): they are servers *sending* data to local machines, which is most
likely ordinary downloads seen from the other side, not data theft.

**Comparison with labels.**

| | Count |
|---|---|
| Bot IPs (From-Botnet) | 1 |
| Bots flagged | **0 of 1** |
| Labelled-normal IPs flagged (false alarms) | 0 of 5 |
| Background IPs flagged (unknown) | 27 |

**The bot was missed.** `147.32.84.165` had 63 flows to 17 different destinations
and sent 447,399 bytes. It ranks 46th of 13,554 by destinations and 44th by bytes sent.
A labelled-normal machine (`147.32.84.164`) contacted more destinations (35) than the bot.
This bot was quiet: about a third of its flows are DNS lookups (21 flows to
`147.32.80.9:53`) and most of the rest are HTTP to a handful of command-and-control and
web servers. Neither rule is designed for that behaviour.

**Can a threshold fix it?** `python tune_thresholds.py --input data/sample.csv --rule fanout`
finds that catching the bot needs `n_dst_ips >= 17`, which also flags 47 other IPs
(precision 0.02). The large-upload rule is no better (bytes >= 447,399 flags 43 other IPs).
These numbers are chosen and scored on the same file, so they are optimistic.

**Conclusion (no overclaim).** On this scenario and these thresholds, the two rules
find hosts with unusually wide or heavy traffic, but they do **not** find the Sogou
bot, and none of the 27 flags can be confirmed as infected from the labels. Volume rules
suit noisy bots (spam, scanning, DDoS); a quiet bot like this one would need other
signals, for example regular timing to the same server (beaconing) or a blacklist of
known command-and-control addresses. The result says nothing about other CTU-13 scenarios.
