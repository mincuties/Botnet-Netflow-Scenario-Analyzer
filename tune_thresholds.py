"""Optional tool: choose a rule threshold using the dataset labels.

This is a very small form of "training": try many thresholds and keep the
one whose flags agree best with the From-Botnet labels (highest F1).

Usage:
    python tune_thresholds.py --input data/sample.csv --config config.json --rule fanout

WARNING: a threshold chosen on a file and then scored on the SAME file
looks better than it really is. Choose on one scenario, report on another.
"""

import argparse
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from analyzer.config import load_config
from analyzer.features import compute_ip_stats
from analyzer.loader import load_flows

MEASURES = {"fanout": "n_dst_ips", "large_upload": "src_bytes"}


def score_thresholds(values, is_bot, thresholds):
    """For each threshold return (tp, fp, fn, precision, recall, f1) arrays.

    values: NumPy array, one number per source IP.
    is_bot: NumPy array of True/False, same order.
    Every IP without a From-Botnet label counts as "not bot" here, so the
    false-positive count is strict (background IPs are not verified).
    """
    tp, fp, fn = [], [], []
    for t in thresholds:
        flagged = values >= t                       # True/False for every IP at once
        tp.append(int(np.sum(flagged & is_bot)))
        fp.append(int(np.sum(flagged & ~is_bot)))
        fn.append(int(np.sum(~flagged & is_bot)))
    tp, fp, fn = np.array(tp), np.array(fp), np.array(fn)
    # np.maximum(..., 1) avoids dividing by zero when nothing is flagged.
    precision = tp / np.maximum(tp + fp, 1)
    recall = tp / np.maximum(tp + fn, 1)
    f1 = 2 * precision * recall / np.maximum(precision + recall, 1e-12)
    return tp, fp, fn, precision, recall, f1


def main():
    parser = argparse.ArgumentParser(description="Choose a threshold using dataset labels.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--rule", choices=sorted(MEASURES), default="fanout")
    parser.add_argument("--output", default="outputs")
    args = parser.parse_args()

    config = load_config(args.config)
    stats = compute_ip_stats(load_flows(args.input, config["time_format"]).flows)
    measure = MEASURES[args.rule]
    ips = [ip for ip, s in stats.items() if s[measure] is not None]
    values = np.array([stats[ip][measure] for ip in ips], dtype=float)
    is_bot = np.array([stats[ip]["is_bot"] for ip in ips], dtype=bool)
    if is_bot.sum() == 0:
        print("No From-Botnet labels in this file: cannot tune a threshold.")
        return

    # Candidate thresholds: every distinct value seen (that covers all cases).
    thresholds = np.unique(values)
    tp, fp, fn, precision, recall, f1 = score_thresholds(values, is_bot, thresholds)
    best = int(np.argmax(f1))       # first (smallest) threshold with the best F1

    print(f"Rule {args.rule} ({measure}), {len(ips)} source IPs, {int(is_bot.sum())} bot IPs")
    print(f"Best threshold: {measure} >= {thresholds[best]:.0f}  "
          f"flags {tp[best]} of {tp[best] + fn[best]} bots, {fp[best]} non-bot IPs, "
          f"precision={precision[best]:.2f} recall={recall[best]:.2f} F1={f1[best]:.2f}")
    print("(Chosen and scored on the same file: optimistic. Check it on another scenario.)")

    os.makedirs(args.output, exist_ok=True)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.plot(thresholds, f1, color="#2a6fdb", linewidth=2)
    ax.axvline(thresholds[best], color="#c8443a", linestyle="--",
               label=f"best = {thresholds[best]:.0f}")
    ax.set_xscale("log")
    ax.set_xlabel(f"threshold on {measure} (log scale)")
    ax.set_ylabel("F1 score")
    ax.set_title(f"F1 score by threshold, rule {args.rule}")
    ax.legend(frameon=False)
    fig.tight_layout()
    path = os.path.join(args.output, f"tune_{args.rule}.png")
    fig.savefig(path, dpi=120)
    plt.close(fig)
    print(f"Chart written to {path}")


if __name__ == "__main__":
    main()
