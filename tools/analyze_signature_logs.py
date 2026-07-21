#!/usr/bin/env python3
"""Extract machine-readable RESULT rows from Pico signature serial logs."""

import argparse
import csv
import sys
from pathlib import Path


FIELDS = [
    "scheme", "parameters", "implementation", "status", "board",
    "clock_hz", "message_bytes", "public_key_bytes", "secret_key_bytes",
    "signature_bytes", "operation", "samples", "mean_ms", "std_ms",
    "min_ms", "max_ms", "median_ms", "mean_cycles", "median_cycles",
    "operations_per_second",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("logs", nargs="+")
    parser.add_argument("--csv", required=True, dest="output")
    args = parser.parse_args()

    rows = []
    for name in args.logs:
        path = Path(name)
        rows_before = len(rows)
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            if not line.startswith("RESULT,"):
                continue
            values = next(csv.reader([line]))[1:]
            if len(values) != len(FIELDS):
                raise SystemExit(
                    f"{path}:{line_number}: expected {len(FIELDS)} fields, "
                    f"found {len(values)}"
                )
            rows.append(dict(zip(FIELDS, values)) | {"source_log": str(path)})
        if len(rows) == rows_before:
            print(
                f"warning: {path} contains no completed RESULT row; keep it as "
                "failure evidence and report the outcome separately",
                file=sys.stderr,
            )

    if not rows:
        raise SystemExit("no RESULT rows found; keep incomplete logs as failure evidence")

    with open(args.output, "w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=FIELDS + ["source_log"])
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
