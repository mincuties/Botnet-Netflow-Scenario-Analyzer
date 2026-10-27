"""Tests for features.py and detectors.py, including the threshold boundary."""

import os

from analyzer.detectors import detect_fanout, detect_large_upload, evaluate_against_labels, run_detectors
from analyzer.features import compute_ip_stats, describe, gap_statistics
from analyzer.flow import Flow
from analyzer.loader import load_flows

BAD = os.path.join(os.path.dirname(__file__), "bad_files")


def make_stats(n_dst_ips, src_bytes):
    return {"n_dst_ips": n_dst_ips, "src_bytes": src_bytes}


def test_distinct_destinations_use_a_set():
    flows = [Flow("A", "X"), Flow("A", "X"), Flow("A", "Y"), Flow("B", "X")]
    stats = compute_ip_stats(flows)
    assert stats["A"]["n_flows"] == 3
    assert stats["A"]["n_dst_ips"] == 2       # X counted once
    assert stats["B"]["n_dst_ips"] == 1


def test_single_flow_has_no_gap_statistics():
    result = load_flows(os.path.join(BAD, "single_flow.csv"))
    stats = compute_ip_stats(result.flows)
    assert stats["10.0.0.1"]["mean_gap_s"] is None


def test_gap_statistics_with_numpy():
    result = load_flows(os.path.join(BAD, "no_label.csv"))   # two flows 10 s apart
    times = [f.start_time for f in result.flows]
    assert gap_statistics(times) == (10.0, 0.0)


def test_describe_empty_and_simple():
    assert describe([]) is None
    d = describe([1, 2, 3, 4])
    assert d["mean"] == 2.5 and d["median"] == 2.5 and d["max"] == 4


def test_fanout_threshold_is_inclusive():
    stats = {"at": make_stats(50, 0), "below": make_stats(49, 0), "above": make_stats(51, 0)}
    flagged = {a.ip for a in detect_fanout(stats, 50)}
    assert flagged == {"at", "above"}


def test_large_upload_threshold_and_missing_column():
    stats = {"big": make_stats(1, 1000), "small": make_stats(1, 999), "unknown": make_stats(1, None)}
    flagged = {a.ip for a in detect_large_upload(stats, 1000)}
    assert flagged == {"big"}


def test_one_ip_can_trigger_both_rules():
    stats = {"A": make_stats(10, 5000)}
    flagged = run_detectors(stats, {"fanout_min_destinations": 10, "upload_min_src_bytes": 5000})
    assert [a.rule for a in flagged["A"]] == ["fanout", "large_upload"]
    assert flagged["A"][0].evidence() == "n_dst_ips=10 >= 10"


def test_to_botnet_label_does_not_make_source_a_bot():
    flows = [Flow("victim", "bot", label="flow=To-Botnet-V1"),
             Flow("bot", "x", label="flow=From-Botnet-V1")]
    stats = compute_ip_stats(flows)
    result = evaluate_against_labels({"victim": []}, stats)
    assert result["bot_ips"] == 1
    assert result["flagged_bots"] == 0
    assert result["missed_bot_list"] == ["bot"]
    assert result["flagged_background"] == 1


def test_threshold_tuning_scores():
    import numpy as np
    from tune_thresholds import score_thresholds
    values = np.array([1, 5, 10, 20])
    is_bot = np.array([False, False, True, True])
    tp, fp, fn, precision, recall, f1 = score_thresholds(values, is_bot, np.array([5, 10]))
    assert list(tp) == [2, 2] and list(fp) == [1, 0] and list(fn) == [0, 0]
    assert f1[1] == 1.0
