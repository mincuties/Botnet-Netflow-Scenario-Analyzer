"""Split each source IP's traffic into fixed time windows (default 5 minutes).

Counting over the whole file hides short events: a scan that lasts two
minutes inside a two-hour capture barely changes the totals. Counting per
window keeps such bursts visible.

Main data structure: a dictionary keyed by a tuple (source IP, window number):
    windows[("147.32.84.165", 3)] = {"n_flows": 812, "dst_ips": {...}, ...}
Window number 3 means "from 15 to 20 minutes after the first flow of the
file" when the window length is 300 seconds.
"""

import math

import numpy as np


def file_start_time(flows):
    """Earliest known StartTime in the file, or None if no flow has a time."""
    times = [f.start_time for f in flows if f.start_time is not None]
    if len(times) == 0:
        return None
    return min(times)


def window_number(time, start, window_seconds):
    """0 for the first window_seconds after `start`, 1 for the next, ..."""
    return int((time - start).total_seconds() // window_seconds)


def compute_windows(flows, window_seconds):
    """Return {(src_ip, window): counts} for every flow with a known time."""
    start = file_start_time(flows)
    windows = {}
    if start is None:
        return windows
    for flow in flows:
        if flow.start_time is None:
            continue
        key = (flow.src_ip, window_number(flow.start_time, start, window_seconds))
        if key not in windows:
            windows[key] = {"n_flows": 0, "dst_ips": set(), "dst_ports": set(),
                            "src_bytes": 0, "tcp_attempts": 0, "tcp_failed": 0,
                            "is_bot": False}
        w = windows[key]
        w["n_flows"] += 1
        w["dst_ips"].add(flow.dst_ip)
        if flow.dst_port is not None:
            w["dst_ports"].add(flow.dst_port)
        w["src_bytes"] += flow.src_bytes or 0
        if flow.is_tcp_attempt():
            w["tcp_attempts"] += 1
            if flow.is_failed_tcp():
                w["tcp_failed"] += 1
        if flow.is_from_botnet():
            w["is_bot"] = True
    return windows


def window_maxima(windows):
    """Per source IP: the busiest window's flow count and port count.

    Returns {src_ip: {"max_window_flows": ..., "max_window_ports": ...,
    "active_windows": ...}}.
    """
    maxima = {}
    for (ip, _), w in windows.items():
        if ip not in maxima:
            maxima[ip] = {"max_window_flows": 0, "max_window_ports": 0, "active_windows": 0}
        m = maxima[ip]
        m["max_window_flows"] = max(m["max_window_flows"], w["n_flows"])
        m["max_window_ports"] = max(m["max_window_ports"], len(w["dst_ports"]))
        m["active_windows"] += 1
    return maxima


def burst_threshold(windows, percentile, minimum):
    """Flow count per window that only the busiest windows reach.

    np.percentile(values, 99.9) is the value below which 99.9 % of all
    (IP, window) flow counts fall. The threshold therefore adapts to the
    size of the network. `minimum` stops it from becoming tiny in a quiet
    file, where even the top 0.1 % may be only a handful of flows.
    """
    if len(windows) == 0:
        return minimum
    counts = np.array([w["n_flows"] for w in windows.values()], dtype=float)
    return max(minimum, int(math.ceil(np.percentile(counts, percentile))))


def window_features(w):
    """The numbers the decision tree sees for one (IP, window).

    Byte counts are turned into log10 so that 1 KB, 1 MB and 1 GB become
    3, 6 and 9: the tree then compares orders of magnitude, not raw bytes.
    """
    failed_ratio = w["tcp_failed"] / w["tcp_attempts"] if w["tcp_attempts"] > 0 else 0.0
    return [
        w["n_flows"],
        len(w["dst_ips"]),
        len(w["dst_ports"]),
        math.log10(w["src_bytes"] + 1),
        math.log10(w["src_bytes"] / w["n_flows"] + 1),
        failed_ratio,
    ]


FEATURE_NAMES = ["n_flows", "n_dst_ips", "n_dst_ports", "log10_src_bytes",
                 "log10_bytes_per_flow", "failed_tcp_ratio"]
