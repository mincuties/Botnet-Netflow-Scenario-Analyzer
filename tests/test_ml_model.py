"""Tests for the optional decision tree layer (skipped without scikit-learn)."""

import os
import pickle

import pytest

pytest.importorskip("sklearn")

from analyzer.ml_model import ip_probabilities, load_model, save_model, train_tree, windows_to_rows  # noqa: E402
from main import main  # noqa: E402

HERE = os.path.dirname(__file__)
TINY = os.path.join(HERE, "data", "tiny_manual.csv")
TINY_CONFIG = os.path.join(HERE, "data", "tiny_config.json")


def window(n_flows, ports, is_bot):
    return {"n_flows": n_flows, "dst_ips": {f"d{i}" for i in range(ports)},
            "dst_ports": set(range(ports)), "src_bytes": 100 * n_flows,
            "tcp_attempts": 0, "tcp_failed": 0, "is_bot": is_bot}


def toy_windows():
    """40 quiet windows (not bot) and 40 busy windows (bot)."""
    windows = {}
    for i in range(40):
        windows[(f"normal{i}", 0)] = window(3 + i % 3, 2, False)
        windows[(f"bot{i}", 0)] = window(300 + i, 60, True)
    return windows


def test_rows_are_in_a_fixed_order():
    keys, X, y = windows_to_rows(toy_windows())
    assert keys == sorted(keys)
    assert len(X) == len(y) == 80 and sum(y) == 40


def test_tree_separates_easy_data_and_is_reproducible(tmp_path):
    _, X, y = windows_to_rows(toy_windows())
    first, second = train_tree(X, y), train_tree(X, y)
    assert list(first.predict(X)) == y
    assert pickle.dumps(first) == pickle.dumps(second)       # same data -> same tree
    path = tmp_path / "tree.pkl"
    save_model(first, path)
    probabilities = ip_probabilities(load_model(path), toy_windows())
    assert probabilities["bot0"] == 1.0 and probabilities["normal0"] == 0.0


def test_ip_probability_is_the_most_suspicious_window():
    windows = toy_windows()
    _, X, y = windows_to_rows(windows)
    tree = train_tree(X, y)
    mixed = {("A", 0): window(3, 2, False), ("A", 1): window(320, 60, False)}
    assert ip_probabilities(tree, mixed) == {"A": 1.0}
    assert ip_probabilities(tree, {}) == {}


def test_shipped_model_runs_with_ml_flag(tmp_path):
    code = main(["--input", TINY, "--config", TINY_CONFIG, "--output", str(tmp_path), "--ml"])
    assert code == 0
    summary = (tmp_path / "summary.txt").read_text(encoding="utf-8")
    assert "ml           (+2, ml): decision tree probability >= 0.5" in summary
