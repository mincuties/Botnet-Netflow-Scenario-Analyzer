"""Read a netflow CSV file safely and turn good rows into Flow objects.

The loader never crashes on a bad ROW: it skips the row and counts the
reason. It only stops (with LoaderError) when the whole FILE is unusable:
file missing, file empty, or a required column missing.
"""

import csv
import gzip
from collections import Counter
from dataclasses import dataclass, field

from analyzer.flow import Flow, parse_count, parse_port, parse_time

# Columns without which the analysis cannot run.
REQUIRED_COLUMNS = ["SrcAddr", "DstAddr"]

# Optional columns: if one is missing, the analysis still runs and the
# summary reports the missing column.
OPTIONAL_COLUMNS = ["StartTime", "Proto", "Dport", "SrcBytes", "TotBytes", "State", "Label"]

# Accepted spellings for each column. Keys are written in the
# "simplified" form produced by simplify_name() below.
COLUMN_ALIASES = {
    "srcaddr": "SrcAddr", "srcip": "SrcAddr", "sourceip": "SrcAddr", "saddr": "SrcAddr",
    "dstaddr": "DstAddr", "dstip": "DstAddr", "destinationip": "DstAddr", "daddr": "DstAddr",
    "starttime": "StartTime", "timestamp": "StartTime",
    "proto": "Proto", "protocol": "Proto",
    "dport": "Dport", "dstport": "Dport", "destinationport": "Dport",
    "srcbytes": "SrcBytes", "sbytes": "SrcBytes",
    "totbytes": "TotBytes", "totalbytes": "TotBytes", "bytes": "TotBytes",
    "label": "Label",
    "state": "State", "tcpflags": "State",
}


class LoaderError(Exception):
    """The whole file cannot be used (not just one bad row)."""


@dataclass
class LoadResult:
    """Everything the loader found out about the file."""

    flows: list = field(default_factory=list)
    rows_read: int = 0                                  # data rows, header not counted
    skipped: Counter = field(default_factory=Counter)  # reason -> how many rows
    missing_optional: list = field(default_factory=list)
    ignored_columns: list = field(default_factory=list)
    delimiter: str = ","


def simplify_name(name):
    """Make column names comparable: " Src_Addr " -> "srcaddr"."""
    return name.strip().lower().replace("_", "").replace(" ", "").replace("-", "")


def detect_delimiter(header_line):
    """Guess the separator from the header line: comma, semicolon or tab."""
    candidates = [",", ";", "\t"]
    counts = {sep: header_line.count(sep) for sep in candidates}
    best = max(candidates, key=lambda sep: counts[sep])
    if counts[best] == 0:
        return ","  # a single column; the required-column check will complain
    return best


def map_header(header):
    """Find which position in the row holds each known column.

    Returns (positions, ignored) where positions is a dict like
    {"SrcAddr": 3, "DstAddr": 6, ...} and ignored lists unknown columns.
    Reading by NAME (not by position) means a file with columns in a
    different order still works.
    """
    positions = {}
    ignored = []
    for index, raw_name in enumerate(header):
        canonical = COLUMN_ALIASES.get(simplify_name(raw_name))
        if canonical is None:
            ignored.append(raw_name.strip())
        elif canonical not in positions:   # keep the first if a name repeats
            positions[canonical] = index
    return positions, ignored


def row_to_flow(row, positions, time_format):
    """Build a Flow from one CSV row (a list of strings).

    Raises ValueError with a short reason if the row must be skipped.
    """
    def get(column):
        # Value of an optional column, or "" when the file lacks the column.
        if column in positions:
            return row[positions[column]].strip()
        return ""

    src_ip = get("SrcAddr")
    dst_ip = get("DstAddr")
    if src_ip == "":
        raise ValueError("empty SrcAddr")
    if dst_ip == "":
        raise ValueError("empty DstAddr")

    # Byte counts are what the rules measure, so a bad value means the
    # row is not trustworthy: skip it. (Only checked if the column exists.)
    src_bytes = None
    total_bytes = None
    if "SrcBytes" in positions:
        src_bytes = parse_count(get("SrcBytes"), "SrcBytes")
    if "TotBytes" in positions:
        total_bytes = parse_count(get("TotBytes"), "TotBytes")

    return Flow(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=parse_port(get("Dport")),
        protocol=get("Proto").lower(),
        start_time=parse_time(get("StartTime"), time_format),
        src_bytes=src_bytes,
        total_bytes=total_bytes,
        label=get("Label"),
        state=get("State"),
    )


def short_reason(error):
    """Group error messages into a few reasons for the summary.

    "SrcBytes is not a number: 'abc'" -> "SrcBytes is not a number"
    """
    return str(error).split(":")[0]


def open_text(path):
    """Open a plain or gzip-compressed (.gz) text file for reading.

    utf-8-sig removes the invisible BOM character that Excel adds.
    newline="" is what the csv module documentation asks for.
    """
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8-sig", newline="")
    return open(path, encoding="utf-8-sig", newline="")


def load_flows(path, time_format="%Y/%m/%d %H:%M:%S.%f"):
    """Read the file at `path` and return a LoadResult."""
    result = LoadResult()
    try:
        with open_text(path) as file:
            header_line = file.readline()
            if header_line.strip() == "":
                raise LoaderError(f"file is empty (no header line): {path}")

            result.delimiter = detect_delimiter(header_line)
            header = next(csv.reader([header_line], delimiter=result.delimiter))
            positions, result.ignored_columns = map_header(header)

            missing = [c for c in REQUIRED_COLUMNS if c not in positions]
            if missing:
                raise LoaderError(
                    "missing required column(s): " + ", ".join(missing)
                    + f" (found: {', '.join(h.strip() for h in header)})"
                )
            result.missing_optional = [c for c in OPTIONAL_COLUMNS if c not in positions]

            for row in csv.reader(file, delimiter=result.delimiter):
                if len(row) == 0 or all(cell.strip() == "" for cell in row):
                    continue  # blank line: not data, not an error
                result.rows_read += 1
                if len(row) != len(header):
                    result.skipped[f"wrong number of fields (expected {len(header)})"] += 1
                    continue
                try:
                    flow = row_to_flow(row, positions, time_format)
                except ValueError as error:
                    result.skipped[short_reason(error)] += 1
                    continue
                result.flows.append(flow)
    except FileNotFoundError:
        raise LoaderError(f"input file not found: {path}")
    except UnicodeDecodeError:
        raise LoaderError(f"file is not UTF-8 text (is it really a CSV?): {path}")
    except csv.Error as error:
        raise LoaderError(f"CSV format problem: {error}")
    except OSError as error:
        # For example: the path is a folder, or read permission is missing.
        raise LoaderError(f"cannot open input file: {error}")
    return result
