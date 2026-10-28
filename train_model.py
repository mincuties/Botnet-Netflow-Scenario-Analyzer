"""Train the optional decision tree on the training scenarios.

Usage:
    python train_model.py --config config.json

Training scenarios: 5 (Virut) and 10 (Rbot). The tree is never scored on
these files; evaluate.py scores it on scenarios 11, 12 and 7 only.
Writes the model file named in config.json (ml.model_file), the tree as
text rules (docs/results/decision_tree.txt) and as a picture
(docs/results/decision_tree.png).
"""

import argparse
import os

from analyzer.config import load_config
from analyzer.loader import load_flows
from analyzer.ml_model import describe_tree, plot_tree_png, save_model, train_tree, windows_to_rows
from analyzer.windows import compute_windows

TRAINING_FILES = [
    "data/scenarios/scenario05.binetflow.gz",
    "data/scenarios/scenario10.binetflow.gz",
]


def main():
    parser = argparse.ArgumentParser(description="Train the decision tree.")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--results", default="docs/results")
    args = parser.parse_args()
    config = load_config(args.config)

    X, y = [], []
    for path in TRAINING_FILES:
        flows = load_flows(path, config["time_format"]).flows
        windows = compute_windows(flows, config["window_seconds"])
        _, rows, labels = windows_to_rows(windows)
        X.extend(rows)
        y.extend(labels)
        print(f"{path}: {len(rows)} windows, {sum(labels)} bot windows")

    tree = train_tree(X, y)
    os.makedirs(os.path.dirname(config["ml"]["model_file"]) or ".", exist_ok=True)
    save_model(tree, config["ml"]["model_file"])
    os.makedirs(args.results, exist_ok=True)
    with open(os.path.join(args.results, "decision_tree.txt"), "w", encoding="utf-8") as file:
        file.write(f"Trained on: {', '.join(TRAINING_FILES)}\n")
        file.write(f"Windows: {len(y)} (bot windows: {sum(y)})\n\n")
        file.write(describe_tree(tree))
    plot_tree_png(tree, os.path.join(args.results, "decision_tree.png"))
    print(f"Model saved to {config['ml']['model_file']}")


if __name__ == "__main__":
    main()
