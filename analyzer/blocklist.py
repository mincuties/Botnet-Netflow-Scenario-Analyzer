"""Known command-and-control (C&C) servers: a simple threat-intelligence check.

Real monitoring systems compare traffic with lists of servers known to
control botnets. Here the list is a text file with one IP per line; lines
starting with # are comments. The list shipped in data/blocklist.txt is
built by build_blocklist.py from the labels of ONE CTU-13 scenario and is
then used on OTHER scenarios, as a real list would be.
"""


def load_blocklist(path):
    """Return the set of IPs in the file, or an empty set if path is ""."""
    if path == "":
        return set()
    blocked = set()
    with open(path, encoding="utf-8") as file:
        for line in file:
            line = line.split("#")[0].strip()   # drop comments and spaces
            if line != "":
                blocked.add(line)
    return blocked


def count_blocklist_hits(flows, blocked):
    """Return {src_ip: number of flows sent to a blocklisted destination}."""
    hits = {}
    if len(blocked) == 0:
        return hits
    for flow in flows:
        if flow.dst_ip in blocked:
            hits[flow.src_ip] = hits.get(flow.src_ip, 0) + 1
    return hits
