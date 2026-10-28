"""Measure the system on every CTU-13 scenario and compare it with a baseline.

Usage:
    python evaluate.py --config config.json
    python evaluate.py --config config.json --skip-ml   (without scikit-learn)

Three configurations are compared on the same files:
  baseline   two simple rules (fan-out, large upload), either one flags
  rules      all signals, group caps, severity, plus the C&C blocklist (default)
  rules_ml   rules plus the decision tree (--ml)

Honest-measurement rules, applied in SCENARIOS below:
  - settings were chosen on scenario 5 only ("dev"); the others are "test";
  - the blocklist comes from scenario 10, so it is switched off there;
  - the tree was trained on scenarios 5 and 10, so it is not scored there.
Writes docs/results/evaluation.csv and docs/results/evaluation.md, and
docs/results/ml_threshold_sweep.md: rules_ml with several values of
ml.min_probability. The sweep is reported for information only; the
setting in config.json is not changed from it, because it is measured on
test scenarios.
"""

import argparse
import copy
import csv
import os

from analyzer.blocklist import load_blocklist
from analyzer.config import load_config
from analyzer.detectors import evaluate_against_labels
from analyzer.loader import load_flows
from analyzer.pipeline import analyze

# (scenario, file, bot family, role, blocklist allowed, tree allowed)
SCENARIOS = [
    ("5", "data/scenarios/scenario05.binetflow.gz", "Virut", "dev", True, False),
    ("10", "data/scenarios/scenario10.binetflow.gz", "Rbot", "test", False, False),
    ("11", "data/scenarios/scenario11.binetflow.gz", "Rbot", "test", True, True),
    ("12", "data/scenarios/scenario12.binetflow.gz", "NSIS.ay (P2P)", "test", True, True),
    ("7", "data/scenarios/scenario07.binetflow.gz", "Sogou", "test", True, True),
]

SWEEP_PROBABILITIES = [0.5, 0.7, 0.9, 0.99]

COLUMNS = ["scenario", "family", "role", "config", "bots", "bots_flagged", "recall",
           "normals", "normals_flagged", "background_flagged", "flagged_total", "precision"]


def baseline_config(config):
    """The simple baseline expressed as a configuration: only fan-out and
    large upload count, and either one alone reaches 'medium'."""
    baseline = copy.deepcopy(config)
    for name, signal in baseline["signals"].items():
        signal["points"] = 0
    medium = baseline["severity"]["medium"]
    baseline["signals"]["fanout"]["points"] = medium
    baseline["signals"]["large_upload"]["points"] = medium
    for group in baseline["group_caps"]:
        baseline["group_caps"][group] = max(baseline["group_caps"][group], medium)
    return baseline


def result_row(scenario, family, role, name, analysis, prefix):
    e = evaluate_against_labels(analysis.flagged(), analysis.ip_stats, prefix)
    recall = e["flagged_bots"] / e["bot_ips"] if e["bot_ips"] else 0.0
    precision = e["flagged_bots"] / e["flagged_total"] if e["flagged_total"] else 0.0
    return {"scenario": scenario, "family": family, "role": role, "config": name,
            "bots": e["bot_ips"], "bots_flagged": e["flagged_bots"], "recall": round(recall, 2),
            "normals": e["normal_ips"], "normals_flagged": e["flagged_normals"],
            "background_flagged": e["flagged_background"], "flagged_total": e["flagged_total"],
            "precision": round(precision, 2)}


def write_markdown(path, rows):
    with open(path, "w", encoding="utf-8") as file:
        file.write("| Scenario | Family | Role | Configuration | Bots flagged | Recall | "
                   "Normal hosts flagged | Background flagged | Precision |\n")
        file.write("|---|---|---|---|---|---|---|---|---|\n")
        for r in rows:
            file.write(f"| {r['scenario']} | {r['family']} | {r['role']} | {r['config']} | "
                       f"{r['bots_flagged']} / {r['bots']} | {r['recall']:.2f} | "
                       f"{r['normals_flagged']} / {r['normals']} | {r['background_flagged']} | "
                       f"{r['precision']:.2f} |\n")


def main():
    parser = argparse.ArgumentParser(description="Evaluate on all CTU-13 scenarios.")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--results", default="docs/results")
    parser.add_argument("--skip-ml", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)
    baseline = baseline_config(config)
    blocked = load_blocklist(config["blocklist_file"])
    tree = None
    if not args.skip_ml:
        from analyzer.ml_model import load_model
        tree = load_model(config["ml"]["model_file"])

    rows = []
    sweep = []
    for scenario, path, family, role, use_blocklist, use_tree in SCENARIOS:
        if not os.path.exists(path):
            print(f"skipped scenario {scenario}: {path} not found")
            continue
        flows = load_flows(path, config["time_format"]).flows
        print(f"scenario {scenario}: {len(flows)} flows")
        prefix = config["monitored_prefix"]
        lists = blocked if use_blocklist else set()
        rows.append(result_row(scenario, family, role, "baseline", analyze(flows, baseline), prefix))
        rows.append(result_row(scenario, family, role, "rules", analyze(flows, config, lists), prefix))
        if tree is not None and use_tree:
            rows.append(result_row(scenario, family, role, "rules_ml",
                                   analyze(flows, config, lists, tree), prefix))
            for probability in SWEEP_PROBABILITIES:
                swept = copy.deepcopy(config)
                swept["ml"]["min_probability"] = probability
                sweep.append(result_row(scenario, family, role, f"ml >= {probability}",
                                        analyze(flows, swept, lists, tree), prefix))

    os.makedirs(args.results, exist_ok=True)
    with open(os.path.join(args.results, "evaluation.csv"), "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    write_markdown(os.path.join(args.results, "evaluation.md"), rows)
    if sweep:
        write_markdown(os.path.join(args.results, "ml_threshold_sweep.md"), sweep)
    for r in rows:
        print(f"  {r['scenario']:>2} {r['config']:<12} bots {r['bots_flagged']}/{r['bots']} "
              f"normals {r['normals_flagged']}/{r['normals']} background {r['background_flagged']} "
              f"precision {r['precision']:.2f}")


if __name__ == "__main__":
    main()
