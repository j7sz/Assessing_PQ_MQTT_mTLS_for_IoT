#!/usr/bin/env python3
"""Join firmware attempts to packet-capture rows and summarize network effects."""

from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import defaultdict

KEY = ("scheme", "board", "campaign", "run")


def normalized_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(str(row[name]).strip() for name in KEY)


def number(row: dict[str, str], name: str) -> float:
    value = row.get(name, "")
    return float(value) if value not in (None, "") else math.nan


def median(values: list[float]) -> float:
    usable = [value for value in values if math.isfinite(value)]
    return statistics.median(usable) if usable else math.nan


def pearson(xs: list[float], ys: list[float]) -> float:
    pairs = [(x, y) for x, y in zip(xs, ys) if math.isfinite(x) and math.isfinite(y)]
    if len(pairs) < 2:
        return math.nan
    xbar = statistics.fmean(x for x, _ in pairs)
    ybar = statistics.fmean(y for _, y in pairs)
    numerator = sum((x - xbar) * (y - ybar) for x, y in pairs)
    xsum = sum((x - xbar) ** 2 for x, _ in pairs)
    ysum = sum((y - ybar) ** 2 for _, y in pairs)
    denominator = math.sqrt(xsum * ysum)
    return numerator / denominator if denominator else math.nan


def fmt(value: float) -> str:
    return "" if not math.isfinite(value) else f"{value:.3f}"


def read_rows(path: str) -> list[dict[str, str]]:
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempts_csv", help="output from analyze_hs_csv.py --attempts-csv")
    parser.add_argument("pcap_csv", help="output from analyze_tls_pcaps.py --csv")
    parser.add_argument("--csv", required=True, help="per-scheme network-effects output")
    parser.add_argument(
        "--certificate-sizes",
        help="optional CSV: scheme,certificate_chain_bytes (DER bytes actually sent)",
    )
    args = parser.parse_args()

    attempts = read_rows(args.attempts_csv)
    captures = {normalized_key(row): row for row in read_rows(args.pcap_csv)}
    certificate_sizes: dict[str, float] = {}
    if args.certificate_sizes:
        certificate_sizes = {
            row["scheme"].strip(): float(row["certificate_chain_bytes"])
            for row in read_rows(args.certificate_sizes)
        }

    joined: list[dict[str, str]] = []
    for attempt in attempts:
        capture = captures.get(normalized_key(attempt))
        if capture is not None:
            joined.append({**attempt, **capture})
    if not joined:
        raise SystemExit("error: no rows joined on scheme,board,campaign,run")

    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in joined:
        grouped[(row["board"], row["scheme"])].append(row)

    baselines: dict[str, tuple[float, float]] = {}
    for (board, scheme), rows in grouped.items():
        if scheme == "ECDSA-P256":
            successful = [row for row in rows if row.get("success") == "1"]
            baselines[board] = (
                median([number(row, "total_ms") for row in successful]),
                median([number(row, "tcp_segment_count") for row in successful]),
            )

    output = []
    for (board, scheme), rows in sorted(grouped.items()):
        successful = [row for row in rows if row.get("success") == "1"]
        clean = [row for row in successful if row.get("has_retransmission") == "0"]
        retransmitted = [row for row in successful if row.get("has_retransmission") == "1"]
        latency = median([number(row, "total_ms") for row in successful])
        segments = median([number(row, "tcp_segment_count") for row in successful])
        wire = median([number(row, "total_wire_bytes") for row in successful])
        ecdsa_latency, ecdsa_segments = baselines.get(board, (math.nan, math.nan))
        extra_segments = segments - ecdsa_segments
        latency_per_extra = (
            (latency - ecdsa_latency) / extra_segments
            if math.isfinite(extra_segments) and extra_segments != 0 else math.nan
        )
        chain_bytes = certificate_sizes.get(scheme, math.nan)
        tls_mqtt_bytes = median([
            number(row, "total_tx_bytes") + number(row, "total_rx_bytes")
            for row in successful
        ])
        output.append({
            "board": board,
            "scheme": scheme,
            "joined_attempts": len(rows),
            "successful_joined_attempts": len(successful),
            "success_without_retransmissions": len(clean),
            "success_with_retransmissions": len(retransmitted),
            "median_total_ms_without_retransmissions": fmt(median([
                number(row, "total_ms") for row in clean
            ])),
            "median_total_ms_with_retransmissions": fmt(median([
                number(row, "total_ms") for row in retransmitted
            ])),
            "median_total_wire_bytes": fmt(wire),
            "wire_traffic_multiplier_over_ecdsa": "",  # filled below
            "median_tcp_segments": fmt(segments),
            "additional_segments_over_ecdsa": fmt(extra_segments),
            "latency_ms_per_additional_segment": fmt(latency_per_extra),
            "segment_net_wait_pearson_r": fmt(pearson(
                [number(row, "tcp_segment_count") for row in successful],
                [number(row, "net_wait_ms") for row in successful],
            )),
            "certificate_chain_bytes": fmt(chain_bytes),
            "certificate_percent_of_tls_mqtt_bytes": fmt(
                100.0 * chain_bytes / tls_mqtt_bytes
                if math.isfinite(chain_bytes) and tls_mqtt_bytes > 0 else math.nan
            ),
        })

    for board in {row["board"] for row in output}:
        ecdsa_wire = next(
            (float(row["median_total_wire_bytes"]) for row in output
             if row["board"] == board and row["scheme"] == "ECDSA-P256"
             and row["median_total_wire_bytes"]),
            math.nan,
        )
        for row in output:
            if row["board"] == board and math.isfinite(ecdsa_wire) and ecdsa_wire > 0:
                row["wire_traffic_multiplier_over_ecdsa"] = fmt(
                    float(row["median_total_wire_bytes"]) / ecdsa_wire
                ) if row["median_total_wire_bytes"] else ""

    with open(args.csv, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(output[0]))
        writer.writeheader()
        writer.writerows(output)

    unmatched = len(attempts) - len(joined)
    print(f"joined {len(joined)}/{len(attempts)} firmware attempts; unmatched={unmatched}")
    print(f"wrote {len(output)} scheme/board rows to {args.csv}")


if __name__ == "__main__":
    main()
