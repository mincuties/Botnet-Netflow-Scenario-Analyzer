"""Botnet Netflow Scenario Analyzer - command line entry point.

Usage:
    python main.py --input data/sample.csv --config config.json

Steps: read config -> load flows -> statistics per source IP and per
5-minute window -> signals and blocklist -> score and severity ->
compare with labels -> write the outputs.
"""

import argparse
import os
import sys

from analyzer.blocklist import load_blocklist
from analyzer.config import ConfigError, load_config
from analyzer.detectors import evaluate_against_labels
from analyzer.loader import LoaderError, load_flows
from analyzer.pipeline import analyze
from analyzer.plots import plot_score_distribution, plot_src_bytes_distribution, plot_top_fanout
from analyzer.report import build_summary, write_recommended_blocks, write_report_csv, write_summary


class SetupError(Exception):
    """The blocklist file named in config.json cannot be used."""


def parse_arguments(argv):
    parser = argparse.ArgumentParser(description="Flag suspicious source IPs in a netflow CSV file.")
    parser.add_argument("--input", required=True, help="netflow CSV file, plain or .gz (e.g. data/sample.csv)")
    parser.add_argument("--config", default="config.json", help="settings file (default: config.json)")
    parser.add_argument("--output", default="outputs", help="folder for results (default: outputs)")
    return parser.parse_args(argv)


def run(input_path, config_path, output_dir):
    """Do the whole analysis. Returns the summary lines (handy for tests)."""
    config = load_config(config_path)
    try:
        blocked = load_blocklist(config["blocklist_file"])
    except OSError as error:
        raise SetupError(f"cannot read blocklist_file: {error}")
    load_result = load_flows(input_path, config["time_format"])

    analysis = analyze(load_result.flows, config, blocked)
    flagged = analysis.flagged()

    has_labels = "Label" not in load_result.missing_optional
    evaluation = None
    if has_labels:
        evaluation = evaluate_against_labels(flagged, analysis.ip_stats, config["monitored_prefix"])

    os.makedirs(output_dir, exist_ok=True)
    write_report_csv(os.path.join(output_dir, "report.csv"), flagged, analysis.ip_stats, has_labels)
    write_recommended_blocks(os.path.join(output_dir, "recommended_blocks.csv"), flagged, analysis.ip_stats)
    lines = build_summary(input_path, load_result, analysis, config, evaluation)
    write_summary(os.path.join(output_dir, "summary.txt"), lines)
    signals = config["signals"]
    plot_top_fanout(os.path.join(output_dir, "top_fanout.png"), analysis.ip_stats,
                    signals["fanout"]["threshold"], config["plot_top_n"])
    plot_src_bytes_distribution(os.path.join(output_dir, "src_bytes_hist.png"), analysis.ip_stats,
                                signals["large_upload"]["threshold"])
    plot_score_distribution(os.path.join(output_dir, "score_distribution.png"), analysis.detections)
    return lines


def main(argv=None):
    """Return 0 on success, 1 on an input or configuration problem."""
    args = parse_arguments(argv)
    try:
        lines = run(args.input, args.config, args.output)
    except (ConfigError, LoaderError, SetupError) as error:
        # A clear one-line message instead of a long Python traceback.
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Error: cannot write results: {error}", file=sys.stderr)
        return 1
    print("\n".join(lines))
    print(f"Results written to: {args.output}/ (report.csv, recommended_blocks.csv, summary.txt, 3 PNG charts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
