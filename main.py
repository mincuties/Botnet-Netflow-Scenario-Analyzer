"""Botnet Netflow Scenario Analyzer - command line entry point.

Usage:
    python main.py --input data/sample.csv --config config.json

Steps: read config -> load flows -> stats per source IP -> rules ->
compare with labels -> write report.csv, summary.txt and 2 PNG charts.
"""

import argparse
import os
import sys

from analyzer.config import ConfigError, load_config
from analyzer.detectors import evaluate_against_labels, run_detectors
from analyzer.features import compute_ip_stats
from analyzer.loader import LoaderError, load_flows
from analyzer.plots import plot_src_bytes_distribution, plot_top_fanout
from analyzer.report import build_summary, write_report_csv, write_summary


def parse_arguments(argv):
    parser = argparse.ArgumentParser(description="Flag suspicious source IPs in a netflow CSV file.")
    parser.add_argument("--input", required=True, help="netflow CSV file (e.g. data/sample.csv)")
    parser.add_argument("--config", default="config.json", help="settings file (default: config.json)")
    parser.add_argument("--output", default="outputs", help="folder for results (default: outputs)")
    return parser.parse_args(argv)


def run(input_path, config_path, output_dir):
    """Do the whole analysis. Returns the summary lines (handy for tests)."""
    config = load_config(config_path)
    load_result = load_flows(input_path, config["time_format"])

    ip_stats = compute_ip_stats(load_result.flows)
    flagged = run_detectors(ip_stats, config)

    has_labels = "Label" not in load_result.missing_optional
    evaluation = evaluate_against_labels(flagged, ip_stats) if has_labels else None

    os.makedirs(output_dir, exist_ok=True)
    write_report_csv(os.path.join(output_dir, "report.csv"), flagged, ip_stats, has_labels)
    lines = build_summary(input_path, load_result, ip_stats, flagged, config, evaluation)
    write_summary(os.path.join(output_dir, "summary.txt"), lines)
    plot_top_fanout(os.path.join(output_dir, "top_fanout.png"), ip_stats,
                    config["fanout_min_destinations"], config["plot_top_n"])
    plot_src_bytes_distribution(os.path.join(output_dir, "src_bytes_hist.png"), ip_stats,
                                config["upload_min_src_bytes"])
    return lines


def main(argv=None):
    """Return 0 on success, 1 on an input or configuration problem."""
    args = parse_arguments(argv)
    try:
        lines = run(args.input, args.config, args.output)
    except (ConfigError, LoaderError) as error:
        # A clear one-line message instead of a long Python traceback.
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Error: cannot write results: {error}", file=sys.stderr)
        return 1
    print("\n".join(lines))
    print(f"Results written to: {args.output}/ (report.csv, summary.txt, top_fanout.png, src_bytes_hist.png)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
