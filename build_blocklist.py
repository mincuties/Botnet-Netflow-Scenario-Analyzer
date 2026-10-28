"""Build data/blocklist.txt from the C&C labels of one CTU-13 scenario.

Usage:
    python build_blocklist.py --source data/scenarios/scenario10.binetflow.gz --output data/blocklist.txt

CTU-13 marks command-and-control traffic with "CC" in the label, for
example "flow=From-Botnet-V51-1-TCP-CC106-IRC-Not-Encrypted". The
destination IPs of those flows are the C&C servers. The list is meant for
OTHER scenarios: using it on the scenario it came from would overstate the results.
"""

import argparse
import re

from analyzer.loader import load_flows

# "-CC" followed by a number, e.g. "-CC106-": the label of a C&C channel.
CC_LABEL = re.compile(r"-CC\d+")


def command_servers(flows):
    """Return {C&C IP: number of From-Botnet flows labelled CC to it}."""
    servers = {}
    for flow in flows:
        if flow.is_from_botnet() and CC_LABEL.search(flow.label):
            servers[flow.dst_ip] = servers.get(flow.dst_ip, 0) + 1
    return servers


def main():
    parser = argparse.ArgumentParser(description="Build a C&C blocklist from CTU-13 labels.")
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", default="data/blocklist.txt")
    args = parser.parse_args()

    servers = command_servers(load_flows(args.source).flows)
    with open(args.output, "w", encoding="utf-8") as file:
        file.write(f"# C&C servers labelled in {args.source}\n")
        file.write("# Built by build_blocklist.py; one IP per line\n")
        for ip in sorted(servers):
            file.write(f"{ip}  # {servers[ip]} labelled C&C flows\n")
    print(f"{len(servers)} C&C IPs written to {args.output}")


if __name__ == "__main__":
    main()
