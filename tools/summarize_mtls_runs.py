#!/usr/bin/env python3
"""Pool equal-sized MQTT benchmark run summaries without inventing medians."""

import argparse
import csv
import math
from collections import defaultdict


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="CSV produced from 30-attempt firmware summaries")
    parser.add_argument("output", help="destination summary CSV")
    parser.add_argument("--attempts-per-run", type=int, default=30)
    args = parser.parse_args()

    groups = defaultdict(list)
    with open(args.input, newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            key = (row["Scheme"], row["Category"], row["Board"], row["Metric"])
            groups[key].append(row)

    fields = [
        "scheme", "category", "board", "metric", "runs", "attempts",
        "mean_ms", "pooled_std_ms", "min_ms", "max_ms",
        "lowest_run_median_ms", "highest_run_median_ms",
    ]
    with open(args.output, "w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        for key in sorted(groups):
            rows = groups[key]
            n = args.attempts_per_run
            means = [float(row["Mean_ms"]) for row in rows]
            stds = [float(row["Std_ms"]) for row in rows]
            medians = [float(row["Median_ms"]) for row in rows]
            grand_mean = sum(means) / len(means)
            total_n = n * len(rows)
            sum_squares = sum(
                (n - 1) * std * std + n * (mean - grand_mean) ** 2
                for mean, std in zip(means, stds)
            )
            pooled_std = math.sqrt(sum_squares / (total_n - 1)) if total_n > 1 else 0
            writer.writerow({
                "scheme": key[0], "category": key[1], "board": key[2],
                "metric": key[3], "runs": len(rows), "attempts": total_n,
                "mean_ms": f"{grand_mean:.3f}",
                "pooled_std_ms": f"{pooled_std:.3f}",
                "min_ms": f"{min(float(row['Min_ms']) for row in rows):.3f}",
                "max_ms": f"{max(float(row['Max_ms']) for row in rows):.3f}",
                "lowest_run_median_ms": f"{min(medians):.3f}",
                "highest_run_median_ms": f"{max(medians):.3f}",
            })


if __name__ == "__main__":
    main()
