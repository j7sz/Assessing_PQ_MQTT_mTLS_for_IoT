#!/usr/bin/env python3
"""Analyze attempt-level MQTT/TLS benchmark serial captures.

The current firmware emits one ``csv_hs`` row for every attempted connection,
including failures and timeouts. This tool reports aggregate and per-campaign
success rates, robust latency statistics, a distribution-free confidence
interval for the median, memory high-water marks, traffic, and deployment
multipliers. Legacy success-only rows remain readable but are explicitly
labelled as such.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import sys
from collections import Counter, defaultdict

PREFIX = "csv_hs,"
HEADER_PREFIX = "csv_hs_header,"
START_PREFIX = "csv_hs_start,"
LATENCY_FIELDS = [
    "dns_ms", "tcp_ms", "tls_ms", "mqtt_ms", "total_ms",
    "crypto_ms", "net_wait_ms",
]
INTEGER_FIELDS = [
    "campaign", "run", "start_epoch_ms", "tcp_start_epoch_ms", "success",
    "error_code", "timeout",
    "heap_capacity_bytes", "heap_in_use_before_bytes",
    "heap_peak_in_use_bytes", "heap_peak_delta_bytes", "heap_in_use_after_bytes",
    "free_before_bytes", "free_before_tls_bytes", "min_free_bytes", "free_after_bytes",
    "maximum_allocation_request_bytes", "allocation_calls", "free_calls",
    "failed_allocations", "stack_capacity_bytes", "stack_high_water_bytes",
    "stack_unused_bytes", "stack_guard_corrupted", "alloc_failed",
    "alloc_failure_bytes", "hs_tx_bytes", "hs_rx_bytes", "hs_tx_writes",
    "hs_rx_reads", "total_tx_bytes", "total_rx_bytes",
]

TARGET_SCHEMES = {
    "mqtt_client_plain": "Plain-MQTT",
    "mqtt_client_ecdsa_p256": "ECDSA-P256",
    "mqtt_client_rsa2048": "RSA-2048",
    "mqtt_client_mldsa44": "ML-DSA-44",
    "mqtt_client_hawk512": "HAWK-512",
    "mqtt_client_falcon512": "Falcon-512",
    "mqtt_client_mayo1": "MAYO-1",
    "mqtt_client_snova_24_5_16_4": "SNOVA-24-5-16-4",
}

LEGACY_FIELDS_17 = [
    "record", "scheme", "board", "run", "dns_ms", "tcp_ms", "tls_ms",
    "mqtt_ms", "total_ms", "crypto_ms", "net_wait_ms", "hs_tx_bytes",
    "hs_rx_bytes", "hs_tx_writes", "hs_rx_reads", "total_tx_bytes",
    "total_rx_bytes",
]
LEGACY_FIELDS_13 = [
    "record", "scheme", "board", "run", "dns_ms", "tcp_ms", "tls_ms",
    "crypto_ms", "net_wait_ms", "hs_tx_bytes", "hs_rx_bytes",
    "hs_tx_writes", "hs_rx_reads",
]


def quantile(sorted_values: list[float], p: float) -> float:
    """Hyndman/Fan type-7 quantile (linear interpolation)."""
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = p * (len(sorted_values) - 1)
    lo = math.floor(position)
    hi = math.ceil(position)
    fraction = position - lo
    return sorted_values[lo] + fraction * (sorted_values[hi] - sorted_values[lo])


def median_confidence_interval(
    sorted_values: list[float], confidence: float = 0.95
) -> tuple[float, float, float]:
    """Exact distribution-free order-statistic interval for the median.

    Returns the narrowest symmetric interval whose binomial coverage is at
    least the requested confidence. For very small n, even [min,max] cannot
    attain 95%; in that case its actual coverage is returned.
    """
    n = len(sorted_values)
    best_k = 1
    best_coverage = 1.0 - 2.0 * (0.5**n)
    for k in range(1, n // 2 + 1):
        tail = sum(math.comb(n, i) for i in range(k)) / (2.0**n)
        coverage = 1.0 - 2.0 * tail
        if coverage + 1e-12 >= confidence:
            best_k = k
            best_coverage = coverage
        else:
            break
    return (
        sorted_values[best_k - 1],
        sorted_values[n - best_k],
        best_coverage,
    )


def robust_stats(values: list[float]) -> dict[str, float | int]:
    values = sorted(values)
    q1 = quantile(values, 0.25)
    median = quantile(values, 0.50)
    q3 = quantile(values, 0.75)
    ci_low, ci_high, coverage = median_confidence_interval(values)
    return {
        "n": len(values),
        "median": median,
        "q1": q1,
        "q3": q3,
        "iqr": q3 - q1,
        "p90": quantile(values, 0.90),
        "min": values[0],
        "max": values[-1],
        "median_ci_low": ci_low,
        "median_ci_high": ci_high,
        "median_ci_coverage": coverage,
    }


def parse_bool(raw: str) -> int:
    return int(raw.strip().lower() in {"1", "true", "yes"})


def normalize(raw: dict[str, str], path: str, legacy: bool) -> dict:
    aliases = {
        "iter": "run",
        "mqtt_connect_ms": "mqtt_ms",
        "mqtts_total_connect_ms": "total_ms",
    }
    row = {aliases.get(key, key): value for key, value in raw.items()}
    row.setdefault("campaign", os.path.basename(path) if legacy else "0")
    row.setdefault("success", "1")
    row.setdefault("failure_stage", "none")
    row.setdefault("error_code", "0")
    row.setdefault("timeout", "0")
    row.setdefault("alloc_failed", "0")
    row.setdefault("alloc_failure_stage", "none")
    for field in LATENCY_FIELDS:
        row[field] = float(row.get(field, "0") or 0)
    for field in INTEGER_FIELDS:
        value = row.get(field, "0") or 0
        if field in {"success", "timeout", "stack_guard_corrupted", "alloc_failed"}:
            row[field] = parse_bool(str(value))
        elif field == "campaign" and not str(value).lstrip("-").isdigit():
            row[field] = str(value)
        else:
            row[field] = int(float(value))
    row["legacy_success_only"] = int(legacy)
    row["source_file"] = path
    return row


def parse(paths: list[str]) -> list[dict]:
    rows: list[dict] = []
    for path in paths:
        header: list[str] | None = None
        with open(path, "r", errors="replace") as handle:
            for line_number, line in enumerate(handle, 1):
                line = line.strip()
                if line.startswith(HEADER_PREFIX):
                    header = next(csv.reader([line]))[1:]
                    continue
                if not line.startswith(PREFIX):
                    continue
                parts = next(csv.reader([line]))
                legacy = False
                if header and len(parts) - 1 == len(header):
                    raw = dict(zip(header, parts[1:]))
                elif len(parts) == 17:
                    raw = dict(zip(LEGACY_FIELDS_17, parts))
                    legacy = True
                elif len(parts) == 13:
                    raw = dict(zip(LEGACY_FIELDS_13, parts))
                    legacy = True
                else:
                    print(
                        f"warning: {path}:{line_number}: malformed csv_hs row",
                        file=sys.stderr,
                    )
                    continue
                try:
                    rows.append(normalize(raw, path, legacy))
                except (TypeError, ValueError) as exc:
                    print(
                        f"warning: {path}:{line_number}: {exc}", file=sys.stderr
                    )
    if not rows:
        raise SystemExit("error: no csv_hs attempt rows found")
    return rows


def incomplete_attempts(paths: list[str], completed: list[dict]) -> list[dict]:
    """Return measured starts with no matching result row.

    This identifies a hang, reset, power loss, or truncated capture, but does
    not incorrectly classify the cause as memory exhaustion.
    """
    starts: dict[tuple[str, str, int, int], dict] = {}
    for path in paths:
        with open(path, "r", errors="replace") as handle:
            for line in handle:
                if not line.startswith(START_PREFIX):
                    continue
                parts = next(csv.reader([line.strip()]))
                if len(parts) != 7 or parse_bool(parts[5]):
                    continue
                key = (parts[1], parts[2], int(parts[3]), int(parts[4]))
                starts[key] = {
                    "scheme": parts[1], "board": parts[2],
                    "campaign": int(parts[3]), "run": int(parts[4]),
                    "start_epoch_ms": int(parts[6]),
                    "status": "hang_reset_or_truncated_capture",
                }
    done = {
        (row["scheme"], row["board"], int(row["campaign"]), row["run"])
        for row in completed if isinstance(row["campaign"], int)
    }
    return [starts[key] for key in sorted(starts) if key not in done]


def f(value) -> str:
    return f"{value:.3f}" if isinstance(value, float) else str(value)


def print_table(columns: list[str], rows: list[dict]) -> None:
    if not rows:
        return
    widths = {
        column: max(len(column), *(len(f(row.get(column, ""))) for row in rows)) + 2
        for column in columns
    }
    print("".join(column.ljust(widths[column]) for column in columns))
    for row in rows:
        print("".join(f(row.get(column, "")).ljust(widths[column]) for column in columns))


def summarize(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    campaigns: dict[tuple[str, str, object], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["scheme"], row["board"])].append(row)
        campaigns[(row["scheme"], row["board"], row["campaign"])].append(row)

    overview = []
    for (scheme, board), group in sorted(grouped.items()):
        successful = [row for row in group if row["success"]]
        failures = Counter(row["failure_stage"] for row in group if not row["success"])
        overview.append({
            "scheme": scheme,
            "board": board,
            "attempted": len(group),
            "successful": len(successful),
            "failures": len(group) - len(successful),
            "timeouts": sum(row["timeout"] for row in group),
            "success_rate": 100.0 * len(successful) / len(group),
            "failure_stages": ";".join(f"{k}:{v}" for k, v in sorted(failures.items())) or "none",
            "legacy_success_only": int(any(row["legacy_success_only"] for row in group)),
        })

    campaign_rows = []
    for (scheme, board, campaign), group in sorted(
        campaigns.items(), key=lambda item: (item[0][0], item[0][1], str(item[0][2]))
    ):
        successful = [row for row in group if row["success"]]
        campaign_rows.append({
            "scheme": scheme,
            "board": board,
            "campaign": campaign,
            "attempted": len(group),
            "successful": len(successful),
            "success_rate": 100.0 * len(successful) / len(group),
            "median_total_ms": (
                robust_stats([row["total_ms"] for row in successful])["median"]
                if successful else math.nan
            ),
        })
    return overview, campaign_rows


def latency_summary(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        if row["success"]:
            grouped[(row["scheme"], row["board"])].append(row)
    output = []
    for (scheme, board), group in sorted(grouped.items()):
        for metric in LATENCY_FIELDS:
            output.append({
                "scheme": scheme,
                "board": board,
                "metric": metric,
                **robust_stats([row[metric] for row in group]),
            })
    return output


def memory_traffic_summary(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["scheme"], row["board"])].append(row)
    output = []
    for (scheme, board), group in sorted(grouped.items()):
        successful = [row for row in group if row["success"]]
        # Memory pressure is often highest on failed handshakes; excluding
        # failures here would hide the evidence this report is meant to show.
        sample = group
        traffic = [row["total_tx_bytes"] + row["total_rx_bytes"] for row in successful]
        output.append({
            "scheme": scheme,
            "board": board,
            "peak_heap_bytes": max(row["heap_peak_in_use_bytes"] for row in sample),
            "peak_heap_delta_bytes": max(row["heap_peak_delta_bytes"] for row in sample),
            "peak_stack_bytes": max(row["stack_high_water_bytes"] for row in sample),
            "minimum_free_bytes": min(row["min_free_bytes"] for row in sample),
            "maximum_allocation_request_bytes": max(
                row["maximum_allocation_request_bytes"] for row in sample
            ),
            "failed_allocations": sum(row["failed_allocations"] for row in group),
            "stack_guard_corruptions": sum(
                row["stack_guard_corrupted"] for row in group
            ),
            "maximum_post_cleanup_heap_bytes": max(
                row["heap_in_use_after_bytes"] for row in group
            ),
            "maximum_heap_baseline_growth_bytes": max(
                row["heap_in_use_after_bytes"] - row["heap_in_use_before_bytes"]
                for row in group
            ),
            "minimum_free_before_tls_bytes": min(
                (row["free_before_tls_bytes"] for row in sample
                 if row["free_before_tls_bytes"] > 0),
                default=0,
            ),
            "allocation_failures": sum(row["alloc_failed"] for row in group),
            "median_traffic_bytes": quantile(sorted(traffic), 0.5) if traffic else math.nan,
            "median_hs_tx_bytes": quantile(
                sorted(row["hs_tx_bytes"] for row in successful), 0.5
            ) if successful else math.nan,
            "median_hs_rx_bytes": quantile(
                sorted(row["hs_rx_bytes"] for row in successful), 0.5
            ) if successful else math.nan,
        })
    return output


def derived_summary(
    rows: list[dict], build_status_paths: list[str] | None = None,
    resource_paths: list[str] | None = None,
) -> list[dict]:
    resources: dict[tuple[str, str], dict[str, str]] = {}
    for path in resource_paths or []:
        with open(path, newline="") as handle:
            for resource in csv.DictReader(handle):
                scheme = TARGET_SCHEMES.get(resource.get("target", ""))
                if scheme:
                    resources[(scheme, resource["board"])] = resource
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["scheme"], row["board"])].append(row)
    base: dict[tuple[str, str], dict] = {}
    for key, group in grouped.items():
        successful = [row for row in group if row["success"]]
        if not successful:
            continue
        base[key] = {
            "latency": quantile(sorted(row["total_ms"] for row in successful), 0.5),
            "traffic": quantile(sorted(
                row["total_tx_bytes"] + row["total_rx_bytes"] for row in successful
            ), 0.5),
            "heap": max(row["heap_peak_in_use_bytes"] for row in successful),
            "headroom": min(row["min_free_bytes"] for row in successful),
        }

    output = []
    for (scheme, board), group in sorted(grouped.items()):
        successful = [row for row in group if row["success"]]
        values = base.get((scheme, board))
        plain = base.get(("Plain-MQTT", board))
        ecdsa = base.get(("ECDSA-P256", board))
        peak_heap = max(row["heap_peak_in_use_bytes"] for row in group)
        peak_stack = max(row["stack_high_water_bytes"] for row in group)
        resource = resources.get((scheme, board))
        static_ram = int(resource["static_ram_bytes"]) if resource else math.nan
        peak_total = static_ram + peak_heap + peak_stack if resource else math.nan
        sram_region = int(resource["sram_region_bytes"]) if resource else math.nan
        output.append({
            "scheme": scheme,
            "board": board,
            "primitive_benchmark": "",
            "firmware_build": "yes",
            "build_reason": "none",
            "mtls_completion": (
                "not_applicable" if scheme == "Plain-MQTT"
                else "yes" if successful else "no"
            ),
            "attempted": len(group),
            "successful": len(successful),
            "success_rate": 100.0 * len(successful) / len(group),
            "median_latency_ms": values["latency"] if values else math.nan,
            "median_traffic_bytes": values["traffic"] if values else math.nan,
            "peak_heap_bytes": peak_heap,
            "peak_stack_bytes": peak_stack,
            "minimum_heap_free_bytes": min(row["min_free_bytes"] for row in group),
            "flash_bytes": int(resource["flash_bytes"]) if resource else math.nan,
            "static_ram_bytes": static_ram,
            "stack_reserved_bytes": (
                int(resource["stack_reserved_bytes"]) if resource else math.nan
            ),
            # Heap and stack maxima need not be simultaneous; adding both to
            # static RAM is deliberately a conservative upper bound.
            "peak_total_ram_upper_bound_bytes": peak_total,
            "ram_headroom_lower_bound_bytes": (
                sram_region - peak_total if resource else math.nan
            ),
            "latency_over_plain": (
                values["latency"] / plain["latency"]
                if values and plain and plain["latency"] else math.nan
            ),
            "latency_over_ecdsa": (
                values["latency"] / ecdsa["latency"]
                if values and ecdsa and ecdsa["latency"] else math.nan
            ),
            "traffic_over_ecdsa": (
                values["traffic"] / ecdsa["traffic"]
                if values and ecdsa and ecdsa["traffic"] else math.nan
            ),
            "traffic_per_latency": (
                values["traffic"] / values["latency"]
                if values and values["latency"] else math.nan
            ),
            "pareto": "",
        })

    for board in {row["board"] for row in output}:
        candidates = [(key, value) for key, value in base.items() if key[1] == board]
        frontier = set()
        for key, value in candidates:
            dominated = any(
                other_key != key
                and other["latency"] <= value["latency"]
                and other["traffic"] <= value["traffic"]
                and other["heap"] <= value["heap"]
                and (other["latency"] < value["latency"]
                     or other["traffic"] < value["traffic"]
                     or other["heap"] < value["heap"])
                for other_key, other in candidates
            )
            if not dominated:
                frontier.add(key)
        for row in output:
            if (row["scheme"], row["board"]) in frontier:
                row["pareto"] = "yes"
            elif row["board"] == board:
                row["pareto"] = "no"

    build_status: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for path in build_status_paths or []:
        with open(path, newline="") as handle:
            for status in csv.DictReader(handle):
                scheme = TARGET_SCHEMES.get(status.get("target", ""))
                if scheme:
                    build_status[(scheme, status["board"])].append(status)
    by_key = {(row["scheme"], row["board"]): row for row in output}
    for key, statuses in sorted(build_status.items()):
        built = any(status.get("status") == "success" for status in statuses)
        reason = ";".join(sorted({
            status.get("reason", "build_failed")
            for status in statuses if status.get("status") != "success"
        })) or "none"
        if key in by_key:
            by_key[key]["firmware_build"] = "yes" if built else "no"
            by_key[key]["build_reason"] = reason
            continue
        scheme, board = key
        output.append({
            "scheme": scheme, "board": board, "primitive_benchmark": "",
            "firmware_build": "yes" if built else "no", "build_reason": reason,
            "mtls_completion": "not_run" if built else "not_applicable",
            "attempted": 0, "successful": 0, "success_rate": math.nan,
            "median_latency_ms": math.nan, "median_traffic_bytes": math.nan,
            "peak_heap_bytes": math.nan, "peak_stack_bytes": math.nan,
            "minimum_heap_free_bytes": math.nan,
            "flash_bytes": math.nan, "static_ram_bytes": math.nan,
            "stack_reserved_bytes": math.nan,
            "peak_total_ram_upper_bound_bytes": math.nan,
            "ram_headroom_lower_bound_bytes": math.nan,
            "latency_over_plain": math.nan, "latency_over_ecdsa": math.nan,
            "traffic_over_ecdsa": math.nan, "traffic_per_latency": math.nan,
            "pareto": "not_applicable",
        })
    by_key = {(row["scheme"], row["board"]): row for row in output}
    for key, resource in resources.items():
        if key not in by_key:
            continue
        row = by_key[key]
        row["flash_bytes"] = int(resource["flash_bytes"])
        row["static_ram_bytes"] = int(resource["static_ram_bytes"])
        row["stack_reserved_bytes"] = int(resource["stack_reserved_bytes"])
    output.sort(key=lambda row: (row["scheme"], row["board"]))
    return output


def write_csv(path: str, rows: list[dict]) -> None:
    if not rows:
        return
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", help="USB serial capture files")
    parser.add_argument("--csv", metavar="OUT", help="write latency summary CSV")
    parser.add_argument("--attempts-csv", metavar="OUT", help="write normalized attempt rows")
    parser.add_argument("--derived-csv", metavar="OUT", help="write deployment metrics CSV")
    parser.add_argument(
        "--build-status", action="append", default=[], metavar="CSV",
        help="add build-only feasibility rows; repeat for multiple boards/campaigns",
    )
    parser.add_argument(
        "--firmware-resources", action="append", default=[], metavar="CSV",
        help="join ELF FLASH/static-RAM data; repeat for multiple boards",
    )
    args = parser.parse_args()

    rows = parse(args.files)
    overview, campaigns = summarize(rows)
    latency = latency_summary(rows)
    memory_traffic = memory_traffic_summary(rows)
    derived = derived_summary(rows, args.build_status, args.firmware_resources)
    incomplete = incomplete_attempts(args.files, rows)

    print("Attempt reliability (legacy=1 means failures were not observable):")
    print_table(
        ["scheme", "board", "attempted", "successful", "failures", "timeouts",
         "success_rate", "failure_stages", "legacy_success_only"],
        overview,
    )
    print("\nPer-campaign reproducibility:")
    print_table(
        ["scheme", "board", "campaign", "attempted", "successful",
         "success_rate", "median_total_ms"],
        campaigns,
    )
    print("\nLatency over successful attempts (95% CI is distribution-free):")
    print_table(
        ["scheme", "board", "metric", "n", "median", "q1", "q3", "iqr",
         "p90", "min", "max", "median_ci_low", "median_ci_high",
         "median_ci_coverage"],
        latency,
    )
    print("\nRuntime memory and client-observed traffic:")
    print_table(
        ["scheme", "board", "peak_heap_bytes", "peak_heap_delta_bytes",
         "peak_stack_bytes", "minimum_free_bytes", "allocation_failures",
         "failed_allocations", "maximum_allocation_request_bytes",
         "stack_guard_corruptions", "maximum_post_cleanup_heap_bytes",
         "maximum_heap_baseline_growth_bytes",
         "minimum_free_before_tls_bytes",
         "median_traffic_bytes", "median_hs_tx_bytes", "median_hs_rx_bytes"],
        memory_traffic,
    )
    if incomplete:
        print("\nStarted attempts without a result (cause not yet classified):")
        print_table(
            ["scheme", "board", "campaign", "run", "start_epoch_ms", "status"],
            incomplete,
        )
    print("\nDerived deployment metrics:")
    print_table(
        ["scheme", "board", "firmware_build", "build_reason", "mtls_completion",
         "attempted", "successful", "success_rate", "median_latency_ms",
         "median_traffic_bytes", "peak_heap_bytes", "peak_stack_bytes",
         "minimum_heap_free_bytes", "flash_bytes", "static_ram_bytes",
         "stack_reserved_bytes", "peak_total_ram_upper_bound_bytes",
         "ram_headroom_lower_bound_bytes",
         "latency_over_plain", "latency_over_ecdsa", "traffic_over_ecdsa",
         "traffic_per_latency", "pareto"],
        derived,
    )

    if args.csv:
        write_csv(args.csv, latency)
    if args.attempts_csv:
        write_csv(args.attempts_csv, rows)
    if args.derived_csv:
        write_csv(args.derived_csv, derived)


if __name__ == "__main__":
    main()
