"""Two simple rules that mark a source IP as suspicious.

A rule only says "this IP behaves unusually", never "this IP is a bot".
Each alert keeps the measured value and the threshold, so every line of
the report can be traced back to the data.
"""

from dataclasses import dataclass


@dataclass
class Alert:
    ip: str
    rule: str        # "fanout" or "large_upload"
    value: int       # measured value for this IP
    threshold: int   # the limit from config.json

    def evidence(self):
        """Human-readable reason, e.g. "n_dst_ips=312 >= 50"."""
        measure = RULE_MEASURES[self.rule]
        return f"{measure}={self.value} >= {self.threshold}"


# Which number from features.py each rule looks at.
RULE_MEASURES = {
    "fanout": "n_dst_ips",
    "large_upload": "src_bytes",
}


def detect_fanout(ip_stats, min_destinations):
    """Fan-out: one IP talks to MANY different destination IPs.

    Typical for bots that scan the network or send spam. The rule fires
    when n_dst_ips >= min_destinations (equal to the threshold counts).
    """
    alerts = []
    for ip, stats in ip_stats.items():
        if stats["n_dst_ips"] >= min_destinations:
            alerts.append(Alert(ip, "fanout", stats["n_dst_ips"], min_destinations))
    return alerts


def detect_large_upload(ip_stats, min_src_bytes):
    """Large upload: one IP SENDS many bytes in total (SrcBytes).

    Can mean data being stolen or a bot taking part in an attack. Returns
    an empty list if the file had no SrcBytes column (value is None).
    """
    alerts = []
    for ip, stats in ip_stats.items():
        sent = stats["src_bytes"]
        if sent is not None and sent >= min_src_bytes:
            alerts.append(Alert(ip, "large_upload", sent, min_src_bytes))
    return alerts


def run_detectors(ip_stats, config):
    """Run every rule and return {ip: [alert, ...]} for flagged IPs only."""
    alerts = (detect_fanout(ip_stats, config["fanout_min_destinations"])
              + detect_large_upload(ip_stats, config["upload_min_src_bytes"]))
    flagged = {}
    for alert in alerts:
        flagged.setdefault(alert.ip, []).append(alert)
    return flagged


def evaluate_against_labels(flagged, ip_stats):
    """Compare flagged IPs with the CTU-13 labels (only if labels exist).

    An IP counts as a bot if at least one of its flows has a From-Botnet
    label. "Background" IPs have no verified label, so a flagged background
    IP is NOT proven to be a false alarm; it is counted separately.
    """
    bots = {ip for ip, s in ip_stats.items() if s["is_bot"]}
    normals = {ip for ip, s in ip_stats.items() if s["is_normal"] and not s["is_bot"]}
    flagged_ips = set(flagged)
    return {
        "bot_ips": len(bots),
        "normal_ips": len(normals),
        "flagged_bots": len(flagged_ips & bots),                 # true positives
        "missed_bots": len(bots - flagged_ips),                  # false negatives
        "flagged_normals": len(flagged_ips & normals),           # false positives
        "flagged_background": len(flagged_ips - bots - normals),  # unknown
        "missed_bot_list": sorted(bots - flagged_ips),
    }
