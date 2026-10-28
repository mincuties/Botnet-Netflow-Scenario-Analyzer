"""Write the results: report.csv, recommended_blocks.csv and summary.txt."""

import csv

from analyzer.detectors import SEVERITY_ORDER
from analyzer.features import describe

REPORT_COLUMNS = ["src_ip", "severity", "score", "signals", "evidence", "n_flows",
                  "n_dst_ips", "n_dst_ports", "src_bytes", "total_bytes",
                  "first_seen", "last_seen", "label_class"]

BLOCK_COLUMNS = ["src_ip", "score", "reason", "first_seen", "last_seen", "action"]


def label_class(stats, has_labels):
    """What the dataset label says about this IP: bot, normal or background."""
    if not has_labels:
        return "no-label-column"
    if stats["is_bot"]:
        return "bot"
    if stats["is_normal"]:
        return "normal"
    return "background"


def format_time(value):
    return "" if value is None else value.strftime("%Y-%m-%d %H:%M:%S")


def sorted_detections(detections, ip_stats):
    """Same order every run: highest score first, then most destinations,
    then most bytes sent, then by IP text (so ties are always broken)."""
    def sort_key(ip):
        s = ip_stats[ip]
        return (-detections[ip].score, -s["n_dst_ips"], -(s["src_bytes"] or 0), ip)
    return sorted(detections, key=sort_key)


def write_report_csv(path, flagged, ip_stats, has_labels):
    """One row per flagged IP, with every signal that fired and its numbers."""
    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(REPORT_COLUMNS)
        for ip in sorted_detections(flagged, ip_stats):
            d = flagged[ip]
            s = ip_stats[ip]
            writer.writerow([
                ip, d.severity, d.score,
                ";".join(sig.name for sig in d.signals),
                "; ".join(sig.evidence() for sig in d.signals),
                s["n_flows"], s["n_dst_ips"], s["n_dst_ports"],
                "" if s["src_bytes"] is None else s["src_bytes"],
                "" if s["total_bytes"] is None else s["total_bytes"],
                format_time(s["first_seen"]), format_time(s["last_seen"]),
                label_class(s, has_labels),
            ])


def write_recommended_blocks(path, flagged, ip_stats):
    """Simulated response: high-severity IPs an analyst should review and
    may block. Nothing is blocked by this program."""
    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(BLOCK_COLUMNS)
        for ip in sorted_detections(flagged, ip_stats):
            d = flagged[ip]
            if d.severity != "high":
                continue
            s = ip_stats[ip]
            writer.writerow([ip, d.score, ";".join(sig.name for sig in d.signals),
                             format_time(s["first_seen"]), format_time(s["last_seen"]),
                             "review, then block at the network edge"])


def format_stats(name, numbers):
    """One summary line like "n_dst_ips: count=... mean=2.1 median=1 ..."."""
    d = describe(numbers)
    if d is None:
        return f"  {name}: no data"
    return (f"  {name}: count={d['count']} mean={d['mean']:.1f} "
            f"median={d['median']:.1f} p95={d['p95']:.1f} max={d['max']:.0f}")


def signal_settings_lines(config, analysis, load_result):
    """Describe each signal's rule as used in this run."""
    s = config["signals"]
    missing = load_result.missing_optional
    lines = [
        f"  fanout       (+{s['fanout']['points']}, {s['fanout']['group']}): distinct destination IPs >= {s['fanout']['threshold']}",
        f"  large_upload (+{s['large_upload']['points']}, {s['large_upload']['group']}): bytes sent >= {s['large_upload']['threshold']}",
        f"  failed_tcp   (+{s['failed_tcp']['points']}, {s['failed_tcp']['group']}): failed share >= {s['failed_tcp']['threshold']} after >= {s['failed_tcp']['min_attempts']} attempts",
        f"  port_scan    (+{s['port_scan']['points']}, {s['port_scan']['group']}): distinct ports in one window >= {s['port_scan']['threshold']}",
        f"  burst        (+{s['burst']['points']}, {s['burst']['group']}): flows in one window >= {analysis.burst_limit} (percentile {s['burst']['percentile']}, minimum {s['burst']['min_flows']})",
        f"  beaconing    (+{s['beaconing']['points']}, {s['beaconing']['group']}): gap CV <= {s['beaconing']['max_cv']} over >= {s['beaconing']['min_flows']} flows to one destination",
        f"  blocklist    (+{s['blocklist']['points']}, {s['blocklist']['group']}): any flow to {analysis.blocklist_size} blocklisted IPs",
    ]
    if analysis.ml_used:
        lines.append(f"  ml           (+{config['ml']['points']}, ml): decision tree probability >= {config['ml']['min_probability']}")
    else:
        lines.append("  ml: not used (run with --ml to enable)")
    if "SrcBytes" in missing:
        lines.append("  note: no SrcBytes column, large_upload cannot fire")
    if "State" in missing:
        lines.append("  note: no State column, failed_tcp cannot fire")
    if "StartTime" in missing:
        lines.append("  note: no StartTime column, port_scan, burst and beaconing cannot fire")
    caps = ", ".join(f"{g} {c}" for g, c in sorted(config["group_caps"].items()))
    levels = config["severity"]
    lines.append(f"  group caps: {caps}")
    lines.append(f"  severity: low >= {levels['low']}, medium >= {levels['medium']}, high >= {levels['high']} (medium and high are reported)")
    return lines


def build_summary(input_path, load_result, analysis, config, evaluation):
    """Return the text of summary.txt as a list of lines."""
    ip_stats = analysis.ip_stats
    flagged = analysis.flagged()
    lines = []
    lines.append("Botnet Netflow Scenario Analyzer - summary")
    lines.append("=" * 44)
    lines.append(f"Input file: {input_path}")
    lines.append(f"Data rows read: {load_result.rows_read}")
    lines.append(f"Valid flows used: {len(load_result.flows)}")
    lines.append(f"Rows skipped: {sum(load_result.skipped.values())}")
    for reason, count in sorted(load_result.skipped.items()):
        lines.append(f"  - {reason}: {count}")
    if load_result.missing_optional:
        lines.append("Optional columns missing: " + ", ".join(load_result.missing_optional))
    if load_result.ignored_columns:
        lines.append("Columns ignored (not used): " + ", ".join(load_result.ignored_columns))
    lines.append("")

    if len(load_result.flows) == 0:
        lines.append("No valid flows: nothing to analyse.")
        return lines

    prefix = config["monitored_prefix"]
    monitored = [ip for ip in ip_stats if ip.startswith(prefix)]
    lines.append(f"Distinct source IPs: {len(ip_stats)}")
    lines.append(f"Monitored source IPs (prefix '{prefix}'): {len(monitored)}")
    lines.append(f"Source IP x {config['window_seconds']} s windows: {len(analysis.windows)}")
    lines.append("Per source IP statistics (NumPy):")
    lines.append(format_stats("n_flows", [s["n_flows"] for s in ip_stats.values()]))
    lines.append(format_stats("n_dst_ips", [s["n_dst_ips"] for s in ip_stats.values()]))
    lines.append(format_stats("src_bytes", [s["src_bytes"] for s in ip_stats.values()
                                            if s["src_bytes"] is not None]))
    lines.append("")

    lines.append("Signals (points, group): rule")
    lines.extend(signal_settings_lines(config, analysis, load_result))
    counts = {level: 0 for level in SEVERITY_ORDER[1:]}
    for d in analysis.detections.values():
        if d.severity in counts:
            counts[d.severity] += 1
    lines.append(f"IPs by severity: high {counts['high']}, medium {counts['medium']}, low {counts['low']} (low is not reported)")
    lines.append(f"Flagged source IPs: {len(flagged)} (details in report.csv; high severity also in recommended_blocks.csv)")
    for ip in sorted_detections(flagged, ip_stats):
        d = flagged[ip]
        lines.append(f"  {ip} [{d.severity}, score {d.score}]: " + "; ".join(sig.evidence() for sig in d.signals))
    lines.append("")

    if evaluation is None:
        lines.append("No Label column: comparison with ground truth skipped.")
    else:
        e = evaluation
        lines.append("Comparison with dataset labels (monitored IPs; an IP is a bot if it has a From-Botnet flow):")
        lines.append(f"  Bot IPs in file: {e['bot_ips']}, labelled-normal IPs: {e['normal_ips']}")
        lines.append(f"  Bots flagged: {e['flagged_bots']} of {e['bot_ips']}")
        lines.append(f"  Bots missed: {e['missed_bots']} {e['missed_bot_list']}")
        lines.append(f"  Labelled-normal IPs flagged (false alarms): {e['flagged_normals']}")
        lines.append(f"  Background IPs flagged (label unknown, not verified): {e['flagged_background']}")
    lines.append("")
    lines.append("Note: a flag means 'unusual behaviour worth checking', not proof of infection.")
    lines.append("Results are valid only for this file and these settings.")
    return lines


def write_summary(path, lines):
    with open(path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")
