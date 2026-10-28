"""Group flows by source IP and compute numbers ("features") for each IP.

Main data structure: a dictionary keyed by source IP, for example
    stats["147.32.84.165"] = {"n_flows": 4, "n_dst_ips": 3, ...}
A dict allows finding one IP's numbers instantly, without scanning a list.
"""

import numpy as np


def group_by_source(flows):
    """Return {src_ip: [flow, flow, ...]} built with one pass over the flows."""
    flows_by_ip = {}
    for flow in flows:
        if flow.src_ip not in flows_by_ip:
            flows_by_ip[flow.src_ip] = []
        flows_by_ip[flow.src_ip].append(flow)
    return flows_by_ip


def sum_or_none(values):
    """Sum a list of numbers, but return None if the column was missing.

    The loader sets src_bytes / total_bytes to None only when the file has
    no such column, so either all values are None or none of them are.
    """
    if len(values) == 0 or values[0] is None:
        return None
    return sum(values)


def gap_statistics(times):
    """Mean and standard deviation (in seconds) of the gaps between flows.

    Needs at least 2 flows with a known time; otherwise returns (None, None)
    instead of crashing or dividing by zero.
    """
    known = sorted(t for t in times if t is not None)
    if len(known) < 2:
        return None, None
    # Seconds since the first flow of this IP.
    seconds = np.array([(t - known[0]).total_seconds() for t in known])
    gaps = np.diff(seconds)            # time between flow i and flow i+1
    return float(np.mean(gaps)), float(np.std(gaps))


def compute_ip_stats(flows):
    """Return {src_ip: dict of numbers} for every source IP."""
    stats = {}
    for ip, ip_flows in group_by_source(flows).items():
        # A set keeps only DIFFERENT values, so len(set) = "how many distinct".
        dst_ips = {f.dst_ip for f in ip_flows}
        dst_ports = {f.dst_port for f in ip_flows if f.dst_port is not None}
        times = [f.start_time for f in ip_flows if f.start_time is not None]
        mean_gap, std_gap = gap_statistics(times)
        tcp_attempts = sum(1 for f in ip_flows if f.is_tcp_attempt())
        tcp_failed = sum(1 for f in ip_flows if f.is_failed_tcp())
        stats[ip] = {
            "n_flows": len(ip_flows),
            "n_dst_ips": len(dst_ips),
            "n_dst_ports": len(dst_ports),
            "src_bytes": sum_or_none([f.src_bytes for f in ip_flows]),
            "total_bytes": sum_or_none([f.total_bytes for f in ip_flows]),
            "mean_gap_s": mean_gap,
            "std_gap_s": std_gap,
            "tcp_attempts": tcp_attempts,
            "tcp_failed": tcp_failed,
            "first_seen": min(times) if times else None,
            "last_seen": max(times) if times else None,
            "is_bot": any(f.is_from_botnet() for f in ip_flows),
            "is_normal": any(f.is_from_normal() for f in ip_flows),
        }
    return stats


def pair_regularity(flows, min_flows):
    """Most regular source -> destination conversation of each source IP.

    Malware often "phones home" to its command server at a fixed interval
    (beaconing). For every (source, destination) pair with at least
    `min_flows` flows, the coefficient of variation of the gaps is

        CV = standard deviation of gaps / mean gap

    CV = 0 means perfectly regular (10 s, 10 s, 10 s); people browsing give
    CV around 1 or more. Returns {src_ip: (lowest CV, destination, flows)}
    for IPs that have at least one qualifying pair.
    """
    times_by_pair = {}
    for flow in flows:
        if flow.start_time is not None:
            times_by_pair.setdefault((flow.src_ip, flow.dst_ip), []).append(flow.start_time)

    best = {}
    for (src, dst), times in times_by_pair.items():
        if len(times) < min_flows:
            continue
        mean_gap, std_gap = gap_statistics(times)
        if mean_gap is None or mean_gap <= 0:
            continue  # all flows at the same instant: no rhythm to measure
        cv = std_gap / mean_gap
        if src not in best or cv < best[src][0]:
            best[src] = (cv, dst, len(times))
    return best


def describe(values):
    """Simple NumPy statistics of a list of numbers, for the summary.

    Returns None for an empty list (no data -> nothing to describe).
    """
    if len(values) == 0:
        return None
    array = np.array(values, dtype=float)
    return {
        "count": int(array.size),
        "mean": float(np.mean(array)),
        "median": float(np.median(array)),
        "p95": float(np.percentile(array, 95)),
        "max": float(np.max(array)),
    }
