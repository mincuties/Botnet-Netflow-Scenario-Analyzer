"""Write the results to outputs/report.csv and outputs/summary.txt."""

import csv

from analyzer.features import describe

REPORT_COLUMNS = ["src_ip", "rules", "evidence", "n_flows", "n_dst_ips",
                  "n_dst_ports", "src_bytes", "total_bytes", "label_class"]


def label_class(stats, has_labels):
    """What the dataset label says about this IP: bot, normal or background."""
    if not has_labels:
        return "no-label-column"
    if stats["is_bot"]:
        return "bot"
    if stats["is_normal"]:
        return "normal"
    return "background"


def sorted_flagged_ips(flagged, ip_stats):
    """Order flagged IPs the same way every run: most destinations first,
    then most bytes sent, then by IP text (so ties are always broken)."""
    def sort_key(ip):
        s = ip_stats[ip]
        return (-s["n_dst_ips"], -(s["src_bytes"] or 0), ip)
    return sorted(flagged, key=sort_key)


def write_report_csv(path, flagged, ip_stats, has_labels):
    """One row per flagged IP, with the numbers that triggered the rules."""
    with open(path, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(REPORT_COLUMNS)
        for ip in sorted_flagged_ips(flagged, ip_stats):
            alerts = flagged[ip]
            s = ip_stats[ip]
            writer.writerow([
                ip,
                ";".join(a.rule for a in alerts),
                "; ".join(a.evidence() for a in alerts),
                s["n_flows"],
                s["n_dst_ips"],
                s["n_dst_ports"],
                "" if s["src_bytes"] is None else s["src_bytes"],
                "" if s["total_bytes"] is None else s["total_bytes"],
                label_class(s, has_labels),
            ])


def format_stats(name, numbers):
    """One summary line like "n_dst_ips per IP: mean=2.1 median=1 ..."."""
    d = describe(numbers)
    if d is None:
        return f"  {name}: no data"
    return (f"  {name}: count={d['count']} mean={d['mean']:.1f} "
            f"median={d['median']:.1f} p95={d['p95']:.1f} max={d['max']:.0f}")


def build_summary(input_path, load_result, ip_stats, flagged, config, evaluation):
    """Return the text of summary.txt as a list of lines."""
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

    lines.append(f"Distinct source IPs: {len(ip_stats)}")
    lines.append("Per source IP statistics (NumPy):")
    lines.append(format_stats("n_flows", [s["n_flows"] for s in ip_stats.values()]))
    lines.append(format_stats("n_dst_ips", [s["n_dst_ips"] for s in ip_stats.values()]))
    lines.append(format_stats("src_bytes", [s["src_bytes"] for s in ip_stats.values()
                                            if s["src_bytes"] is not None]))
    lines.append("")

    lines.append("Rules (thresholds from config):")
    lines.append(f"  fanout:       n_dst_ips >= {config['fanout_min_destinations']}")
    if "SrcBytes" in load_result.missing_optional:
        lines.append("  large_upload: SKIPPED (no SrcBytes column)")
    else:
        lines.append(f"  large_upload: src_bytes >= {config['upload_min_src_bytes']}")
    lines.append(f"Flagged source IPs: {len(flagged)} (details in report.csv)")
    for ip in sorted_flagged_ips(flagged, ip_stats):
        lines.append(f"  {ip}: " + "; ".join(a.evidence() for a in flagged[ip]))
    lines.append("")

    if evaluation is None:
        lines.append("No Label column: comparison with ground truth skipped.")
    else:
        e = evaluation
        lines.append("Comparison with dataset labels (an IP is a bot if it has a From-Botnet flow):")
        lines.append(f"  Bot IPs in file: {e['bot_ips']}, labelled-normal IPs: {e['normal_ips']}")
        lines.append(f"  Bots flagged: {e['flagged_bots']} of {e['bot_ips']}")
        lines.append(f"  Bots missed: {e['missed_bots']} {e['missed_bot_list']}")
        lines.append(f"  Labelled-normal IPs flagged (false alarms): {e['flagged_normals']}")
        lines.append(f"  Background IPs flagged (label unknown, not verified): {e['flagged_background']}")
    lines.append("")
    lines.append("Note: a flag means 'unusual behaviour worth checking', not proof of infection.")
    lines.append("Results are valid only for this file and these thresholds.")
    return lines


def write_summary(path, lines):
    with open(path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")
