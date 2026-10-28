"""Signals, scoring and severity: decide which source IPs to report.

Each signal is one simple test, such as "contacted at least 50 different
IPs". A signal that fires gives the IP some points. Signals that measure the
same kind of behaviour belong to one group, and each group has a maximum
number of points, so one behaviour is not counted twice (a scanner usually
fires both "fan-out" and "port scan"). The total score decides the
severity: low, medium or high. Only medium and high are reported.

A flag means "unusual behaviour worth checking", never "this IP is a bot".
Every signal keeps its measured value and its threshold, so each line of
the report can be traced back to the data.
"""

from dataclasses import dataclass

# What each signal measures, for the evidence text.
SIGNAL_MEASURES = {
    "fanout": "distinct destination IPs",
    "large_upload": "bytes sent",
    "failed_tcp": "share of failed TCP attempts",
    "port_scan": "distinct destination ports in one window",
    "burst": "flows in one window",
    "beaconing": "lowest gap CV to one destination",
    "blocklist": "flows to blocklisted IPs",
    "ml": "decision tree bot probability",
}

SEVERITY_ORDER = ["none", "low", "medium", "high"]


@dataclass
class Signal:
    name: str         # key of SIGNAL_MEASURES
    group: str        # "spread", "volume", "control" or "ml"
    value: float      # measured value for this IP
    threshold: float  # limit from config.json (or computed from the data)
    points: int

    def evidence(self):
        """Human-readable reason, e.g. "fanout: distinct destination IPs=312 >= 50"."""
        sign = "<=" if self.name == "beaconing" else ">="
        return f"{self.name}: {SIGNAL_MEASURES[self.name]}={format_number(self.value)} {sign} {format_number(self.threshold)}"


@dataclass
class Detection:
    ip: str
    signals: list
    score: int
    severity: str

    def is_flagged(self):
        return self.severity in ("medium", "high")


def format_number(value):
    """312 -> "312", 0.8333 -> "0.83"."""
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}"


def is_monitored(ip, monitored_prefix):
    """Only IPs of the monitored network are judged ("" = every IP)."""
    return ip.startswith(monitored_prefix)


def signals_for_ip(ip, stats, extra, config, burst_limit):
    """Run every signal for one IP and return the list of those that fire.

    `extra` holds the per-IP results computed outside features.py:
    window maxima, beaconing, blocklist hits and the decision tree score.
    """
    s = config["signals"]
    fired = []

    def check(name, value, threshold):
        if value is not None and value >= threshold:
            fired.append(Signal(name, s[name]["group"], value, threshold, s[name]["points"]))

    check("fanout", stats["n_dst_ips"], s["fanout"]["threshold"])
    check("large_upload", stats["src_bytes"], s["large_upload"]["threshold"])

    # Failed TCP attempts: only meaningful after enough attempts.
    if stats["tcp_attempts"] >= s["failed_tcp"]["min_attempts"]:
        check("failed_tcp", stats["tcp_failed"] / stats["tcp_attempts"], s["failed_tcp"]["threshold"])

    window = extra.get("window")
    if window is not None:
        check("port_scan", window["max_window_ports"], s["port_scan"]["threshold"])
        check("burst", window["max_window_flows"], burst_limit)

    # Beaconing fires when the gaps are REGULAR, i.e. the CV is SMALL.
    beacon = extra.get("beacon")
    if beacon is not None and beacon[0] <= s["beaconing"]["max_cv"]:
        fired.append(Signal("beaconing", s["beaconing"]["group"], beacon[0],
                            s["beaconing"]["max_cv"], s["beaconing"]["points"]))

    hits = extra.get("blocklist_hits", 0)
    if hits > 0:
        fired.append(Signal("blocklist", s["blocklist"]["group"], hits, 1, s["blocklist"]["points"]))

    probability = extra.get("ml_probability")
    if probability is not None:
        ml = config["ml"]
        if probability >= ml["min_probability"]:
            fired.append(Signal("ml", "ml", probability, ml["min_probability"], ml["points"]))
    return fired


def total_score(signals, group_caps):
    """Add the points per group, cap each group, then add the groups.

    Example with caps {"spread": 3}: fanout (2) + port_scan (2) = 4 points
    of "spread", capped to 3.
    """
    per_group = {}
    for signal in signals:
        per_group[signal.group] = per_group.get(signal.group, 0) + signal.points
    return sum(min(points, group_caps[group]) for group, points in per_group.items())


def severity_of(score, levels):
    """Map a score to "none", "low", "medium" or "high" using config levels."""
    if score >= levels["high"]:
        return "high"
    if score >= levels["medium"]:
        return "medium"
    if score >= levels["low"]:
        return "low"
    return "none"


def run_detection(ip_stats, extras, config, burst_limit):
    """Return {ip: Detection} for every monitored IP with at least one signal."""
    detections = {}
    for ip, stats in ip_stats.items():
        if not is_monitored(ip, config["monitored_prefix"]):
            continue
        signals = signals_for_ip(ip, stats, extras.get(ip, {}), config, burst_limit)
        if len(signals) == 0:
            continue
        score = total_score(signals, config["group_caps"])
        detections[ip] = Detection(ip, signals, score, severity_of(score, config["severity"]))
    return detections


def evaluate_against_labels(flagged_ips, ip_stats, monitored_prefix=""):
    """Compare flagged IPs with the CTU-13 labels (only if labels exist).

    An IP counts as a bot if at least one of its flows has a From-Botnet
    label. "Background" IPs have no verified label, so a flagged background
    IP is NOT proven to be a false alarm; it is counted separately. Only
    monitored IPs are counted, since the others are never judged.
    """
    monitored = {ip for ip in ip_stats if is_monitored(ip, monitored_prefix)}
    bots = {ip for ip in monitored if ip_stats[ip]["is_bot"]}
    normals = {ip for ip in monitored if ip_stats[ip]["is_normal"] and not ip_stats[ip]["is_bot"]}
    flagged = set(flagged_ips)
    return {
        "bot_ips": len(bots),
        "normal_ips": len(normals),
        "flagged_total": len(flagged),
        "flagged_bots": len(flagged & bots),                    # true positives
        "missed_bots": len(bots - flagged),                     # false negatives
        "flagged_normals": len(flagged & normals),              # false positives
        "flagged_background": len(flagged - bots - normals),    # unknown
        "missed_bot_list": sorted(bots - flagged),
    }
