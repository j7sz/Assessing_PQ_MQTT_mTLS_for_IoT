#!/usr/bin/env python3
"""Extract per-connection TCP/TLS quality and traffic metrics with tshark.

Input is a manifest CSV with columns:
  pcap,scheme,board,campaign,client_ip,server_ip

Each capture should contain one scheme/board/campaign. TCP streams are ordered
by their initial client SYN and assigned run numbers, which makes the output
joinable to ``analyze_hs_csv.py --attempts-csv``. Passing that attempt file
enables epoch-time matching, which remains correct when a DNS/allocation
failure produces no TCP stream.
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import statistics
import subprocess
import sys
from collections import defaultdict

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "ip.src", "ip.dst",
    "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.len", "tcp.flags.syn",
    "tcp.flags.ack", "tcp.flags.reset", "tcp.analysis.retransmission",
    "tcp.analysis.duplicate_ack", "tcp.analysis.out_of_order",
    "tcp.analysis.ack_rtt", "tls.record.length", "tls.alert_message",
]


def truthy(value: str) -> bool:
    return value not in {"", "0", "False", "false"}


def integer(value: str) -> int:
    return int(value or 0)


def extract(tshark: str, pcap: str) -> list[dict]:
    command = [
        tshark, "-r", pcap, "-Y", "tcp", "-T", "fields",
        "-E", "separator=\\t", "-E", "quote=n", "-E", "occurrence=a",
        "-E", "aggregator=|",
    ]
    for field in FIELDS:
        command.extend(["-e", field])
    completed = subprocess.run(command, check=True, text=True, capture_output=True)
    rows = []
    for line in completed.stdout.splitlines():
        values = line.split("\t")
        values.extend([""] * (len(FIELDS) - len(values)))
        rows.append(dict(zip(FIELDS, values)))
    return rows


def summarize_capture(meta: dict, packets: list[dict], full_segment: int) -> list[dict]:
    streams = defaultdict(list)
    for packet in packets:
        if packet["tcp.stream"]:
            streams[integer(packet["tcp.stream"])].append(packet)

    candidates = []
    for stream, group in streams.items():
        initial_syn = [
            packet for packet in group
            if packet["ip.src"] == meta["client_ip"]
            and packet["ip.dst"] == meta["server_ip"]
            and truthy(packet["tcp.flags.syn"])
            and not truthy(packet["tcp.flags.ack"])
        ]
        if initial_syn:
            candidates.append((float(initial_syn[0]["frame.time_epoch"]), stream, group))
    candidates.sort()

    output = []
    for run, (_, stream, group) in enumerate(candidates):
        client_packets = [p for p in group if p["ip.src"] == meta["client_ip"]]
        server_packets = [p for p in group if p["ip.src"] == meta["server_ip"]]
        rtts = [float(p["tcp.analysis.ack_rtt"]) * 1000.0 for p in group
                if p["tcp.analysis.ack_rtt"]]
        tls_lengths = []
        alerts = []
        for packet in group:
            tls_lengths.extend(
                integer(value) for value in packet["tls.record.length"].split("|") if value
            )
            alerts.extend(value for value in packet["tls.alert_message"].split("|") if value)
        times = [float(packet["frame.time_epoch"]) for packet in group]
        retransmissions = sum(truthy(p["tcp.analysis.retransmission"]) for p in group)
        syn_retries = sum(
            truthy(p["tcp.analysis.retransmission"])
            and truthy(p["tcp.flags.syn"])
            and not truthy(p["tcp.flags.ack"])
            for p in client_packets
        )
        output.append({
            "scheme": meta["scheme"],
            "board": meta["board"],
            "campaign": meta["campaign"],
            "run": run,
            "run_match_method": "sequential",
            "tcp_stream": stream,
            "stream_start_epoch_ms": min(times) * 1000.0,
            "duration_ms": (max(times) - min(times)) * 1000.0,
            "client_to_server_payload_bytes": sum(integer(p["tcp.len"]) for p in client_packets),
            "server_to_client_payload_bytes": sum(integer(p["tcp.len"]) for p in server_packets),
            "client_to_server_wire_bytes": sum(integer(p["frame.len"]) for p in client_packets),
            "server_to_client_wire_bytes": sum(integer(p["frame.len"]) for p in server_packets),
            "total_wire_bytes": sum(integer(p["frame.len"]) for p in group),
            "tcp_segment_count": len(group),
            "full_sized_tcp_segments": sum(integer(p["tcp.len"]) >= full_segment for p in group),
            "tls_record_count": len(tls_lengths),
            "largest_tls_record_bytes": max(tls_lengths, default=0),
            "tcp_retransmissions": retransmissions,
            "duplicate_acks": sum(truthy(p["tcp.analysis.duplicate_ack"]) for p in group),
            "out_of_order_segments": sum(truthy(p["tcp.analysis.out_of_order"]) for p in group),
            "estimated_rtt_ms": statistics.median(rtts) if rtts else "",
            "tcp_connection_retries": syn_retries,
            "connection_resets": sum(truthy(p["tcp.flags.reset"]) for p in group),
            "tls_alerts": "|".join(alerts),
            "has_retransmission": int(retransmissions > 0),
        })
    return output


def match_attempt_runs(
    capture_rows: list[dict], attempt_rows: list[dict[str, str]],
    meta: dict[str, str], window_ms: float,
) -> None:
    candidates = [
        row for row in attempt_rows
        if row.get("scheme") == meta["scheme"]
        and row.get("board") == meta["board"]
        and str(row.get("campaign")) == str(meta["campaign"])
        and float(row.get("tcp_start_epoch_ms", row.get("start_epoch_ms", 0)) or 0) > 0
    ]
    unused = set(range(len(candidates)))
    for capture in capture_rows:
        stream_start = float(capture["stream_start_epoch_ms"])
        choices = [
            (abs(stream_start - float(
                candidates[index].get("tcp_start_epoch_ms")
                or candidates[index]["start_epoch_ms"]
            )), index)
            for index in unused
        ]
        if not choices:
            capture["run"] = -1
            capture["run_match_method"] = "unmatched"
            continue
        delta, index = min(choices)
        if delta > window_ms:
            capture["run"] = -1
            capture["run_match_method"] = "unmatched"
            continue
        capture["run"] = candidates[index]["run"]
        capture["run_match_method"] = "epoch"
        unused.remove(index)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("manifest", help="capture manifest CSV")
    parser.add_argument("--csv", required=True, help="per-attempt output CSV")
    parser.add_argument(
        "--attempts-csv",
        help="normalized firmware attempts for robust epoch-time run matching",
    )
    parser.add_argument(
        "--match-window-ms", type=float, default=1000.0,
        help="maximum firmware TCP-start/pcap SYN difference (default: 1000)",
    )
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument(
        "--full-segment-payload", type=int, default=1460,
        help="TCP payload threshold for a full-sized segment (default: 1460)",
    )
    args = parser.parse_args()
    if not shutil.which(args.tshark):
        raise SystemExit(f"error: tshark executable not found: {args.tshark}")

    output = []
    attempt_rows = []
    if args.attempts_csv:
        with open(args.attempts_csv, newline="") as handle:
            attempt_rows = list(csv.DictReader(handle))
    with open(args.manifest, newline="") as handle:
        for meta in csv.DictReader(handle):
            missing = {"pcap", "scheme", "board", "campaign", "client_ip", "server_ip"} - set(meta)
            if missing:
                raise SystemExit(f"error: manifest missing columns: {sorted(missing)}")
            pcap = os.path.expanduser(meta["pcap"])
            try:
                packets = extract(args.tshark, pcap)
            except subprocess.CalledProcessError as exc:
                print(exc.stderr, file=sys.stderr)
                raise SystemExit(f"error: tshark failed for {pcap}") from exc
            capture_rows = summarize_capture(meta, packets, args.full_segment_payload)
            if attempt_rows:
                match_attempt_runs(capture_rows, attempt_rows, meta, args.match_window_ms)
            output.extend(capture_rows)

    if not output:
        raise SystemExit("error: no client-initiated TCP streams found")
    with open(args.csv, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(output[0]))
        writer.writeheader()
        writer.writerows(output)
    print(f"wrote {len(output)} connection rows to {args.csv}")


if __name__ == "__main__":
    main()
