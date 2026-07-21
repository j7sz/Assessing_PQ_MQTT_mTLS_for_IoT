#!/usr/bin/env python3
import csv
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def write_csv(path: pathlib.Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    attempts = []
    captures = []
    for scheme, latency, segments, wire in (
        ("ECDSA-P256", 100, 10, 1000),
        ("HAWK-512", 160, 13, 1500),
    ):
        for run, retransmission in enumerate((0, 1)):
            attempts.append({
                "scheme": scheme, "board": "pico2_w", "campaign": 1,
                "run": run, "success": 1, "total_ms": latency + 20 * retransmission,
                "net_wait_ms": 20 + 10 * retransmission,
                "total_tx_bytes": 300, "total_rx_bytes": 700,
            })
            captures.append({
                "scheme": scheme, "board": "pico2_w", "campaign": 1,
                "run": run, "has_retransmission": retransmission,
                "tcp_segment_count": segments + retransmission,
                "total_wire_bytes": wire,
            })

    with tempfile.TemporaryDirectory() as directory:
        directory = pathlib.Path(directory)
        attempts_path = directory / "attempts.csv"
        captures_path = directory / "captures.csv"
        output_path = directory / "effects.csv"
        sizes_path = directory / "sizes.csv"
        write_csv(attempts_path, attempts)
        write_csv(captures_path, captures)
        write_csv(sizes_path, [
            {"scheme": "ECDSA-P256", "certificate_chain_bytes": 200},
            {"scheme": "HAWK-512", "certificate_chain_bytes": 400},
        ])
        subprocess.run([
            sys.executable, str(ROOT / "tools" / "summarize_tls_capture_effects.py"),
            str(attempts_path), str(captures_path), "--csv", str(output_path),
            "--certificate-sizes", str(sizes_path),
        ], check=True, capture_output=True, text=True)
        with output_path.open(newline="") as handle:
            rows = {row["scheme"]: row for row in csv.DictReader(handle)}

    assert rows["HAWK-512"]["success_with_retransmissions"] == "1"
    assert rows["HAWK-512"]["median_total_ms_without_retransmissions"] == "160.000"
    assert rows["HAWK-512"]["wire_traffic_multiplier_over_ecdsa"] == "1.500"
    assert rows["HAWK-512"]["additional_segments_over_ecdsa"] == "3.000"
    assert rows["HAWK-512"]["certificate_percent_of_tls_mqtt_bytes"] == "40.000"
    print("PASS: firmware/pcap join and network-effect metrics")


if __name__ == "__main__":
    main()
