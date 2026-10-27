"""Draw the two PNG charts with Matplotlib."""

import matplotlib

matplotlib.use("Agg")  # draw to files only; no window needed
import matplotlib.pyplot as plt
import numpy as np

FLAGGED_COLOR = "#c8443a"   # IPs that crossed the threshold
NORMAL_COLOR = "#9aa3ad"    # everything else
LINE_COLOR = "#222222"      # threshold line


def style_axes(ax):
    """Light grid and no top/right border, so the data stands out."""
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="x", color="#e5e5e5", linewidth=0.8)
    ax.set_axisbelow(True)


def empty_chart(path, title):
    """Still produce a PNG when there is nothing to draw."""
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.text(0.5, 0.5, "No data to plot", ha="center", va="center", fontsize=14)
    ax.set_title(title)
    ax.axis("off")
    fig.savefig(path, dpi=120)
    plt.close(fig)


def plot_top_fanout(path, ip_stats, threshold, top_n):
    """Horizontal bars: the top_n source IPs by number of destination IPs."""
    title = f"Top {top_n} source IPs by distinct destination IPs"
    if len(ip_stats) == 0:
        empty_chart(path, title)
        return
    # Same ordering rule as the report: biggest first, ties by IP text.
    ranked = sorted(ip_stats.items(), key=lambda item: (-item[1]["n_dst_ips"], item[0]))
    top = ranked[:top_n][::-1]     # reverse so the biggest bar is at the top
    ips = [ip for ip, _ in top]
    values = [s["n_dst_ips"] for _, s in top]
    colors = [FLAGGED_COLOR if v >= threshold else NORMAL_COLOR for v in values]

    fig, ax = plt.subplots(figsize=(9, 0.4 * len(ips) + 1.8))
    ax.barh(ips, values, color=colors, height=0.6)
    ax.axvline(threshold, color=LINE_COLOR, linestyle="--", linewidth=1.2,
               label=f"fan-out threshold = {threshold}")
    for y, v in enumerate(values):
        ax.text(v, y, f" {v}", va="center", fontsize=8)
    # Log scale: one IP can have thousands of destinations while others have
    # tens, and on a normal scale the small bars would be invisible.
    ax.set_xscale("log")
    ax.set_xlabel("Number of distinct destination IPs (count, log scale)")
    ax.set_ylabel("Source IP")
    ax.set_title(title)
    ax.legend(loc="best", frameon=False)
    style_axes(ax)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def plot_src_bytes_distribution(path, ip_stats, threshold):
    """Histogram of total bytes SENT per source IP, on a log10 scale.

    Byte counts range from tens to billions, so a log scale is needed to
    see anything. log10(1000) = 3, log10(1,000,000) = 6.
    """
    title = "Distribution of bytes sent per source IP"
    sent = [s["src_bytes"] for s in ip_stats.values() if s["src_bytes"] is not None]
    if len(sent) == 0:
        empty_chart(path, title)
        return
    log_sent = np.log10(np.array(sent, dtype=float) + 1)   # +1 avoids log10(0)

    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.hist(log_sent, bins=30, color=NORMAL_COLOR, edgecolor="white")
    ax.axvline(np.log10(threshold + 1), color=FLAGGED_COLOR, linestyle="--", linewidth=1.5,
               label=f"large-upload threshold = {threshold:,} bytes")
    ax.set_xlabel("log10(bytes sent + 1)   (3 = 1 KB, 6 = 1 MB, 9 = 1 GB)")
    # Most IPs send very little, so the y axis is also logarithmic to keep
    # the few heavy senders visible.
    ax.set_yscale("log")
    ax.set_ylabel("Number of source IPs (log scale)")
    ax.set_title(title)
    ax.legend(frameon=False)
    style_axes(ax)
    ax.grid(axis="y", color="#e5e5e5", linewidth=0.8)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
