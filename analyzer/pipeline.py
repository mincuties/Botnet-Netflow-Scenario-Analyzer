"""The analysis steps in order, shared by main.py and evaluate.py.

flows -> per-IP statistics -> 5-minute windows -> beaconing -> blocklist
-> signals and score -> detections
"""

from dataclasses import dataclass

from analyzer.blocklist import count_blocklist_hits
from analyzer.detectors import run_detection
from analyzer.features import compute_ip_stats, pair_regularity
from analyzer.windows import burst_threshold, compute_windows, window_maxima


@dataclass
class Analysis:
    ip_stats: dict      # src_ip -> numbers over the whole file
    windows: dict       # (src_ip, window) -> numbers per window
    detections: dict    # src_ip -> Detection (only IPs with a signal)
    burst_limit: int    # flows per window that the burst signal uses
    blocklist_size: int

    def flagged(self):
        """Detections of severity medium or high."""
        return {ip: d for ip, d in self.detections.items() if d.is_flagged()}


def analyze(flows, config, blocked=frozenset()):
    """Run every step on a list of Flow objects and return an Analysis."""
    ip_stats = compute_ip_stats(flows)
    windows = compute_windows(flows, config["window_seconds"])
    maxima = window_maxima(windows)
    burst = config["signals"]["burst"]
    limit = burst_threshold(windows, burst["percentile"], burst["min_flows"])
    beacons = pair_regularity(flows, config["signals"]["beaconing"]["min_flows"])
    hits = count_blocklist_hits(flows, blocked)

    extras = {}
    for ip in ip_stats:
        extras[ip] = {
            "window": maxima.get(ip),
            "beacon": beacons.get(ip),
            "blocklist_hits": hits.get(ip, 0),
        }
    detections = run_detection(ip_stats, extras, config, limit)
    return Analysis(ip_stats, windows, detections, limit, len(blocked))
