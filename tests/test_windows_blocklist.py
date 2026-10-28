"""Tests for windows.py (5-minute windows, burst threshold) and blocklist.py."""

from datetime import datetime, timedelta

import pytest

from analyzer.blocklist import count_blocklist_hits, load_blocklist
from analyzer.flow import Flow
from analyzer.windows import (burst_threshold, compute_windows, window_features, window_maxima,
                              window_number)

T0 = datetime(2011, 8, 16, 10, 0, 0)


def at(seconds, src="A", dst="X", port=80, **kw):
    return Flow(src, dst, dst_port=port, start_time=T0 + timedelta(seconds=seconds), **kw)


def test_window_number_boundaries():
    assert window_number(T0 + timedelta(seconds=299.9), T0, 300) == 0
    assert window_number(T0 + timedelta(seconds=300), T0, 300) == 1


def test_windows_split_by_ip_and_time():
    flows = [at(0, port=80), at(10, port=443), at(400, port=22), at(5, src="B"),
             Flow("A", "Y")]                       # no time: not in any window
    windows = compute_windows(flows, 300)
    assert set(windows) == {("A", 0), ("A", 1), ("B", 0)}
    assert windows[("A", 0)]["n_flows"] == 2
    assert windows[("A", 0)]["dst_ports"] == {80, 443}
    maxima = window_maxima(windows)
    assert maxima["A"] == {"max_window_flows": 2, "max_window_ports": 2, "active_windows": 2}


def test_no_times_gives_no_windows():
    assert compute_windows([Flow("A", "X")], 300) == {}


def test_burst_threshold_percentile_and_minimum():
    windows = {(str(i), 0): {"n_flows": n} for i, n in enumerate([1, 2, 3, 4, 100])}
    assert burst_threshold(windows, 100, 5) == 100      # the busiest window
    assert burst_threshold(windows, 50, 5) == 5         # median 3 -> raised to the minimum
    assert burst_threshold({}, 99.9, 7) == 7


def test_window_features_for_the_tree():
    w = {"n_flows": 4, "dst_ips": {"X", "Y"}, "dst_ports": {80}, "src_bytes": 999,
         "tcp_attempts": 4, "tcp_failed": 1}
    # log10(999 + 1) = 3; bytes per flow 999 / 4 = 249.75 -> log10(250.75) = 2.399
    assert window_features(w) == pytest.approx([4, 2, 1, 3.0, 2.39924, 0.25], abs=1e-4)


def test_load_blocklist_with_comments(tmp_path):
    path = tmp_path / "list.txt"
    path.write_text("# known servers\n1.2.3.4\n\n5.6.7.8  # second\n", encoding="utf-8")
    assert load_blocklist(str(path)) == {"1.2.3.4", "5.6.7.8"}
    assert load_blocklist("") == set()


def test_count_blocklist_hits():
    flows = [Flow("A", "1.2.3.4"), Flow("A", "1.2.3.4"), Flow("B", "9.9.9.9")]
    assert count_blocklist_hits(flows, {"1.2.3.4"}) == {"A": 2}
    assert count_blocklist_hits(flows, set()) == {}
