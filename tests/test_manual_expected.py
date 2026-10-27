"""End-to-end test against a result computed BY HAND.

tests/data/tiny_manual.csv is a 10-row file written by hand for testing
(it is NOT real CTU-13 data). The expected numbers below were worked out
on paper; the working is in tests/data/tiny_manual_EXPECTED.md.
"""

import csv
import os

from analyzer.features import compute_ip_stats
from analyzer.loader import load_flows
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
    b = stats["10.0.0.2"]
    assert (b["n_flows"], b["total_bytes"], b["src_bytes"], b["n_dst_ips"]) == (2, 8000, 2400, 1)
    c = stats["10.0.0.3"]
    assert (c["n_dst_ports"], c["mean_gap_s"]) == (1, None)   # hex port 0x0008, single flow
    assert stats["10.0.0.4"]["is_bot"] is False                # To-Botnet label


def test_whole_program_report_matches_hand_calculation(tmp_path):
    exit_code = main(["--input", TINY, "--config", TINY_CONFIG, "--output", str(tmp_path)])
    assert exit_code == 0
    with open(tmp_path / "report.csv", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    assert [(r["src_ip"], r["rules"], r["label_class"]) for r in rows] == [
        ("10.0.0.1", "fanout", "bot"),
        ("10.0.0.2", "large_upload", "normal"),
    ]
    assert rows[0]["evidence"] == "n_dst_ips=3 >= 3"
    assert rows[1]["evidence"] == "src_bytes=2400 >= 2000"
    summary = (tmp_path / "summary.txt").read_text(encoding="utf-8")
    assert "Bots flagged: 1 of 1" in summary
    assert "Labelled-normal IPs flagged (false alarms): 1" in summary
    assert (tmp_path / "top_fanout.png").stat().st_size > 0
    assert (tmp_path / "src_bytes_hist.png").stat().st_size > 0
