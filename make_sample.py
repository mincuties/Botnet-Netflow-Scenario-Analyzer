"""Cut a small sample out of a big CTU-13 .binetflow file.

Usage:
    python make_sample.py --source data/raw/capture20110816-2.binetflow --output data/sample.csv --rows 20000

The sample is the header line plus a block of consecutive rows, copied
EXACTLY as they are in the original (no change, no cleaning), so anyone
can re-create it from the original file. SHA-256 checksums of both files
are printed so they can be written into data/DATA.md.
"""

import argparse
import hashlib


def sha256_of(path):
    """Checksum of a file, read in 1 MB pieces so big files fit in memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def cut_sample(source, output, rows, start):
    """Copy the header and rows start .. start+rows-1 (0 = first data row)."""
    written = 0
    with open(source, encoding="utf-8", newline="") as src, \
         open(output, "w", encoding="utf-8", newline="") as out:
        out.write(src.readline())          # header line
        for index, line in enumerate(src):
            if index < start:
                continue
            if written == rows:
                break
            out.write(line)
            written += 1
    return written


def main():
    parser = argparse.ArgumentParser(description="Cut a sample from a CTU-13 binetflow file.")
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", default="data/sample.csv")
    parser.add_argument("--rows", type=int, default=20000)
    parser.add_argument("--start", type=int, default=0, help="first data row to copy (0-based)")
    args = parser.parse_args()

    written = cut_sample(args.source, args.output, args.rows, args.start)
    print(f"Copied {written} data rows from row {args.start} of {args.source}")
    print(f"SHA-256 source: {sha256_of(args.source)}")
    print(f"SHA-256 sample: {sha256_of(args.output)}")


if __name__ == "__main__":
    main()
