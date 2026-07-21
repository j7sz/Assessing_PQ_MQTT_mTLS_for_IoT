#!/usr/bin/env python3
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "analyze_tls_pcaps", ROOT / "tools" / "analyze_tls_pcaps.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def main() -> None:
    meta = {"scheme": "HAWK-512", "board": "pico2_w", "campaign": "1"}
    attempts = [
        {**meta, "run": "0", "start_epoch_ms": "500", "tcp_start_epoch_ms": "1000"},
        {**meta, "run": "1", "start_epoch_ms": "2000", "tcp_start_epoch_ms": "0"},
        {**meta, "run": "2", "start_epoch_ms": "3000", "tcp_start_epoch_ms": "4000"},
    ]
    captures = [
        {"stream_start_epoch_ms": 1010, "run": 0, "run_match_method": "sequential"},
        {"stream_start_epoch_ms": 4010, "run": 1, "run_match_method": "sequential"},
    ]
    MODULE.match_attempt_runs(captures, attempts, meta, 500)
    assert [row["run"] for row in captures] == ["0", "2"]
    assert all(row["run_match_method"] == "epoch" for row in captures)
    print("PASS: epoch pcap matching survives an attempt with no TCP stream")


if __name__ == "__main__":
    main()
