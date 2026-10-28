"""Botnet Netflow Scenario Analyzer - command line entry point.

Usage:
    python main.py --input data/sample.csv --config config.json
    python main.py --input data/sample.csv --config config.json --ml

Steps: read config -> load flows -> statistics per source IP and per
5-minute window -> signals, blocklist and (with --ml) decision tree ->
score and severity -> compare with labels -> write the outputs.
"""

import argparse
import os
import pickle
import sys

from analyzer.blocklist import load_blocklist
from analyzer.config import ConfigError, load_config
from analyzer.detectors import evaluate_against_labels
from analyzer.loader import LoaderError, load_flows
from analyzer.pipeline import analyze
from analyzer.plots import plot_score_distribution, plot_src_bytes_distribution, plot_top_fanout
from analyzer.report import build_summary, write_recommended_blocks, write_report_csv, write_summary


class SetupError(Exception):
    """A file named in config.json (blocklist, model) cannot be used."""


def parse_arguments(argv):
    parser = argparse.ArgumentParser(description="Flag suspicious source IPs in a netflow CSV file.")
    parser.add_argument("--input", required=True, help="netflow CSV file, plain or .gz (e.g. data/sample.csv)")
    parser.add_argument("--config", default="config.json", help="settings file (default: config.json)")
    parser.add_argument("--output", default="outputs", help="folder for results (default: outputs)")
    parser.add_argument("--ml", action="store_true",
                        help="also use the trained decision tree (needs scikit-learn)")
    return parser.parse_args(argv)


def load_extras(config, use_ml):
    """Load the blocklist and, if asked, the decision tree."""
    try:
        blocked = load_blocklist(config["blocklist_file"])
    except OSError as error:
        raise SetupError(f"cannot read blocklist_file: {error}")
    tree = None
    if use_ml or config["ml"]["enabled"]:
        try:
            from analyzer.ml_model import load_model
            tree = load_model(config["ml"]["model_file"])
        except ImportError:
            raise SetupError("--ml needs scikit-learn: pip install scikit-learn")
        except (OSError, pickle.UnpicklingError, EOFError) as error:
            raise SetupError(f"cannot load ml.model_file (run train_model.py first): {error}")
    return blocked, tree


def run(input_path, config_path, output_dir, use_ml=False):
    """Do the whole analysis. Returns the summary lines (handy for tests)."""
    config = load_config(config_path)
    blocked, tree = load_extras(config, use_ml)
    load_result = load_flows(input_path, config["time_format"])

    analysis = analyze(load_result.flows, config, blocked, tree)
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
        lines = run(args.input, args.config, args.output, args.ml)
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
