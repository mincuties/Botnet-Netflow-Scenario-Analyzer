"""End-to-end test against a result computed BY HAND.

tests/data/tiny_manual.csv is a 10-row file written by hand for testing
(it is NOT real CTU-13 data). The expected numbers below were worked out
on paper; the working is in README.md, section "Hand-computed test case".
"""

import csv
import os

from analyzer.features import compute_ip_stats
from analyzer.loader import load_flows
from analyzer.windows import compute_windows
from main import main

DATA = os.path.join(os.path.dirname(__file__), "data")
TINY = os.path.join(DATA, "tiny_manual.csv")
TINY_CONFIG = os.path.join(DATA, "tiny_config.json")


def test_loader_counts_match_hand_calculation():
    result = load_flows(TINY)
    assert result.rows_read == 10
    assert len(result.flows) == 8
    assert dict(result.skipped) == {"TotBytes is not a number": 1, "empty SrcAddr": 1}


def test_ip_stats_match_hand_calculation():
    stats = compute_ip_stats(load_flows(TINY).flows)
    a = stats["10.0.0.1"]
    assert (a["n_flows"], a["total_bytes"], a["src_bytes"]) == (4, 1000, 600)
    assert (a["n_dst_ips"], a["n_dst_ports"]) == (3, 3)
    assert (a["mean_gap_s"], a["std_gap_s"]) == (10.0, 0.0)
    assert (a["tcp_attempts"], a["tcp_failed"]) == (3, 1)     # row 4 is S_RA
    b = stats["10.0.0.2"]
    assert (b["n_flows"], b["total_bytes"], b["src_bytes"], b["n_dst_ips"]) == (2, 8000, 2400, 1)
    c = stats["10.0.0.3"]
    assert (c["n_dst_ports"], c["mean_gap_s"]) == (1, None)   # hex port 0x0008, single flow
    assert stats["10.0.0.4"]["is_bot"] is False                # To-Botnet label


def test_windows_match_hand_calculation():
    windows = compute_windows(load_flows(TINY).flows, 300)
    counts = {key: w["n_flows"] for key, w in windows.items()}
    assert counts == {("10.0.0.1", 0): 4, ("10.0.0.2", 0): 2, ("10.0.0.3", 0): 1, ("10.0.0.4", 0): 1}


def test_whole_program_report_matches_hand_calculation(tmp_path):
    exit_code = main(["--input", TINY, "--config", TINY_CONFIG, "--output", str(tmp_path)])
    assert exit_code == 0
    with open(tmp_path / "report.csv", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    assert [(r["src_ip"], r["severity"], r["score"], r["signals"], r["label_class"]) for r in rows] == [
        ("10.0.0.1", "high", "7", "fanout;port_scan;burst;blocklist", "bot"),
        ("10.0.0.2", "medium", "2", "large_upload", "normal"),
    ]
    assert rows[0]["evidence"] == (
        "fanout: distinct destination IPs=3 >= 3; "
        "port_scan: distinct destination ports in one window=3 >= 3; "
        "burst: flows in one window=4 >= 4; "
        "blocklist: flows to blocklisted IPs=1 >= 1")
    assert rows[1]["evidence"] == "large_upload: bytes sent=2400 >= 2000"

    with open(tmp_path / "recommended_blocks.csv", encoding="utf-8") as file:
        blocks = list(csv.DictReader(file))
    assert [b["src_ip"] for b in blocks] == ["10.0.0.1"]       # high severity only

    summary = (tmp_path / "summary.txt").read_text(encoding="utf-8")
    assert "Bots flagged: 1 of 1" in summary
    assert "Labelled-normal IPs flagged (false alarms): 1" in summary
    assert "IPs by severity: high 1, medium 1, low 0" in summary
    for chart in ("top_fanout.png", "src_bytes_hist.png", "score_distribution.png"):
        assert (tmp_path / chart).stat().st_size > 0


def test_same_input_gives_same_report(tmp_path):
    main(["--input", TINY, "--config", TINY_CONFIG, "--output", str(tmp_path / "a")])
    main(["--input", TINY, "--config", TINY_CONFIG, "--output", str(tmp_path / "b")])
    for name in ("report.csv", "recommended_blocks.csv", "summary.txt"):
        first = (tmp_path / "a" / name).read_text(encoding="utf-8")
        second = (tmp_path / "b" / name).read_text(encoding="utf-8").replace("/b/", "/a/")
        assert first == second
