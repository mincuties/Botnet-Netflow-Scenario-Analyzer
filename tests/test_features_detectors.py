"""Tests for features.py and detectors.py: statistics, signals, boundaries,
group caps, severity and the comparison with labels."""

import copy
import json
import os
from datetime import datetime, timedelta

import pytest

from analyzer.detectors import (Signal, evaluate_against_labels, run_detection, severity_of,
                                signals_for_ip, total_score)
from analyzer.features import compute_ip_stats, describe, gap_statistics, pair_regularity
from analyzer.flow import Flow
from analyzer.loader import load_flows

HERE = os.path.dirname(__file__)
BAD = os.path.join(HERE, "bad_files")
T0 = datetime(2011, 8, 16, 10, 0, 0)


def tiny_config():
    with open(os.path.join(HERE, "data", "tiny_config.json"), encoding="utf-8") as file:
        return json.load(file)


def make_stats(n_dst_ips=1, src_bytes=0, tcp_attempts=0, tcp_failed=0):
    return {"n_dst_ips": n_dst_ips, "src_bytes": src_bytes,
            "tcp_attempts": tcp_attempts, "tcp_failed": tcp_failed}


def fired(stats, extra=None, config=None, burst_limit=100):
    config = config or tiny_config()
    return [s.name for s in signals_for_ip("10.0.0.9", stats, extra or {}, config, burst_limit)]


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


def test_failed_tcp_flags():
    assert Flow("a", "b", protocol="tcp", state="S_RA").is_failed_tcp()
    assert not Flow("a", "b", protocol="tcp", state="SRPA_SPA").is_failed_tcp()
    assert not Flow("a", "b", protocol="udp", state="S_RA").is_failed_tcp()
    assert not Flow("a", "b", protocol="tcp", state="").is_tcp_attempt()


def test_beaconing_cv_hand_calculation():
    # Gaps 10, 10, 10 s -> CV 0. Gaps 10, 30 s -> mean 20, std 10, CV 0.5.
    regular = [Flow("A", "C2", start_time=T0 + timedelta(seconds=s)) for s in (0, 10, 20, 30)]
    uneven = [Flow("B", "web", start_time=T0 + timedelta(seconds=s)) for s in (0, 10, 40)]
    best = pair_regularity(regular + uneven, min_flows=3)
    assert best["A"] == (0.0, "C2", 4)
    assert best["B"][0] == pytest.approx(0.5)


def test_beaconing_needs_min_flows_and_real_gaps():
    two = [Flow("A", "C2", start_time=T0), Flow("A", "C2", start_time=T0 + timedelta(seconds=5))]
    same_time = [Flow("B", "x", start_time=T0) for _ in range(5)]
    assert pair_regularity(two + same_time, min_flows=3) == {}


def test_fanout_threshold_is_inclusive():
    assert fired(make_stats(n_dst_ips=3)) == ["fanout"]
    assert fired(make_stats(n_dst_ips=2)) == []


def test_large_upload_threshold_and_missing_column():
    assert fired(make_stats(src_bytes=2000)) == ["large_upload"]
    assert fired(make_stats(src_bytes=1999)) == []
    assert fired(make_stats(src_bytes=None)) == []


def test_failed_tcp_needs_enough_attempts():
    assert fired(make_stats(tcp_attempts=2, tcp_failed=2)) == []          # below min_attempts 3
    assert fired(make_stats(tcp_attempts=4, tcp_failed=2)) == ["failed_tcp"]   # 0.5 >= 0.5
    assert fired(make_stats(tcp_attempts=4, tcp_failed=1)) == []


def test_window_beacon_blocklist_and_ml_signals():
    extra = {"window": {"max_window_flows": 100, "max_window_ports": 3},
             "beacon": (0.1, "C2", 12), "blocklist_hits": 2, "ml_probability": 0.5}
    assert fired(make_stats(), extra, burst_limit=100) == [
        "port_scan", "burst", "beaconing", "blocklist", "ml"]
    extra = {"window": {"max_window_flows": 99, "max_window_ports": 2},
             "beacon": (0.11, "C2", 12), "blocklist_hits": 0, "ml_probability": 0.49}
    assert fired(make_stats(), extra, burst_limit=100) == []


def test_group_cap_stops_double_counting():
    caps = {"spread": 2, "volume": 2, "control": 3}
    spread_only = [Signal("fanout", "spread", 3, 3, 2), Signal("port_scan", "spread", 3, 3, 2)]
    assert total_score(spread_only, caps) == 2
    mixed = spread_only + [Signal("burst", "volume", 9, 4, 2), Signal("blocklist", "control", 1, 1, 3)]
    assert total_score(mixed, caps) == 7


@pytest.mark.parametrize("score, level", [(0, "none"), (1, "low"), (2, "low"), (3, "medium"),
                                          (4, "medium"), (5, "high"), (9, "high")])
def test_severity_levels(score, level):
    assert severity_of(score, {"low": 1, "medium": 3, "high": 5}) == level


def test_only_monitored_ips_are_judged():
    config = tiny_config()
    stats = {"10.0.0.9": make_stats(n_dst_ips=5), "8.8.8.8": make_stats(n_dst_ips=5)}
    assert set(run_detection(stats, {}, config, 100)) == {"10.0.0.9"}
    config = copy.deepcopy(config)
    config["monitored_prefix"] = ""
    assert set(run_detection(stats, {}, config, 100)) == {"10.0.0.9", "8.8.8.8"}


def test_to_botnet_label_does_not_make_source_a_bot():
    flows = [Flow("victim", "bot", label="flow=To-Botnet-V1"),
             Flow("bot", "x", label="flow=From-Botnet-V1")]
    stats = compute_ip_stats(flows)
    result = evaluate_against_labels({"victim": None}, stats)
    assert result["bot_ips"] == 1
    assert result["flagged_bots"] == 0
    assert result["missed_bot_list"] == ["bot"]
    assert result["flagged_background"] == 1


def test_evaluation_ignores_unmonitored_ips():
    flows = [Flow("147.32.84.165", "x", label="flow=From-Botnet-V1"),
             Flow("1.2.3.4", "x", label="flow=From-Botnet-V1")]
    result = evaluate_against_labels({"1.2.3.4": None}, compute_ip_stats(flows), "147.32.")
    assert result["bot_ips"] == 1 and result["flagged_total"] == 1 and result["flagged_bots"] == 0


def test_threshold_tuning_scores():
    import numpy as np
    from tune_thresholds import score_thresholds
    values = np.array([1, 5, 10, 20])
    is_bot = np.array([False, False, True, True])
    tp, fp, fn, precision, recall, f1 = score_thresholds(values, is_bot, np.array([5, 10]))
    assert list(tp) == [2, 2] and list(fp) == [1, 0] and list(fn) == [0, 0]
    assert f1[1] == 1.0
