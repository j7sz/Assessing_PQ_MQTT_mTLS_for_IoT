#!/usr/bin/env python3
import importlib.util
import os
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "analyze_hs_csv", ROOT / "tools" / "analyze_hs_csv.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def main() -> None:
    values = [float(i) for i in range(1, 31)]
    stats = MODULE.robust_stats(values)
    assert stats["median"] == 15.5
    assert stats["p90"] == 27.1
    assert stats["median_ci_coverage"] >= 0.95

    header = (
        "csv_hs_header,scheme,board,campaign,run,dns_ms,tcp_ms,tls_ms,mqtt_ms,"
        "total_ms,crypto_ms,net_wait_ms,success,failure_stage,error_code,timeout,"
        "heap_capacity_bytes,heap_in_use_before_bytes,heap_peak_in_use_bytes,"
        "heap_peak_delta_bytes,heap_in_use_after_bytes,free_before_bytes,"
        "free_before_tls_bytes,min_free_bytes,free_after_bytes,"
        "maximum_allocation_request_bytes,allocation_calls,free_calls,failed_allocations,"
        "stack_capacity_bytes,stack_high_water_bytes,stack_unused_bytes,"
        "stack_guard_corrupted,alloc_failed,alloc_failure_stage,"
        "alloc_failure_bytes,hs_tx_bytes,hs_rx_bytes,hs_tx_writes,hs_rx_reads,"
        "total_tx_bytes,total_rx_bytes\n"
    )
    success = (
        "csv_hs,ECDSA-P256,pico2_w,1,0,1,2,3,4,9,1,2,1,none,0,0,"
        "1000,100,300,200,110,900,800,700,890,64,4,3,0,4096,400,3696,"
        "0,0,none,0,10,20,1,2,12,22\n"
    )
    failure = (
        "csv_hs,ECDSA-P256,pico2_w,1,1,1,2,30,0,32,1,29,0,tls_handshake,"
        "-1001,1,1000,100,990,890,120,900,20,10,880,256,5,3,1,4096,500,3596,"
        "0,1,tls_handshake,256,10,20,1,2,10,20\n"
    )
    with tempfile.NamedTemporaryFile("w", delete=False) as capture:
        capture.write(
            header
            + "csv_hs_start,ECDSA-P256,pico2_w,1,0,0,1000\n"
            + "csv_hs_start,ECDSA-P256,pico2_w,1,1,0,2000\n"
            + "csv_hs_start,ECDSA-P256,pico2_w,1,2,0,3000\n"
            + success + failure
        )
        path = capture.name
    rows = MODULE.parse([path])
    incomplete = MODULE.incomplete_attempts([path], rows)
    os.unlink(path)
    overview, campaigns = MODULE.summarize(rows)
    assert len(rows) == 2
    assert overview[0]["attempted"] == 2
    assert overview[0]["successful"] == 1
    assert overview[0]["timeouts"] == 1
    assert campaigns[0]["median_total_ms"] == 9.0
    assert len(incomplete) == 1
    assert incomplete[0]["run"] == 2
    assert incomplete[0]["status"] == "hang_reset_or_truncated_capture"
    memory = MODULE.memory_traffic_summary(rows)[0]
    assert memory["failed_allocations"] == 1
    assert memory["maximum_allocation_request_bytes"] == 256
    assert memory["maximum_heap_baseline_growth_bytes"] == 20
    with tempfile.NamedTemporaryFile("w", delete=False) as status:
        status.write(
            "board,campaign,target,status,reason,artifact\n"
            "pico_w,1,mqtt_client_snova_24_5_16_4,failure,ram_overflow,\n"
        )
        status_path = status.name
    with tempfile.NamedTemporaryFile("w", delete=False) as resources:
        resources.write(
            "board,target,flash_bytes,static_ram_bytes,stack_reserved_bytes,sram_region_bytes\n"
            "pico2_w,mqtt_client_ecdsa_p256,700000,90000,4096,532480\n"
        )
        resources_path = resources.name
    derived = MODULE.derived_summary(rows, [status_path], [resources_path])
    os.unlink(status_path)
    os.unlink(resources_path)
    assert derived[0]["attempted"] == 2
    assert derived[0]["successful"] == 1
    assert derived[0]["success_rate"] == 50.0
    assert derived[0]["firmware_build"] == "yes"
    assert derived[0]["static_ram_bytes"] == 90000
    assert derived[0]["peak_total_ram_upper_bound_bytes"] == 91490
    assert derived[0]["ram_headroom_lower_bound_bytes"] == 440990
    snova = next(row for row in derived if row["scheme"] == "SNOVA-24-5-16-4")
    assert snova["firmware_build"] == "no"
    assert snova["build_reason"] == "ram_overflow"
    assert snova["mtls_completion"] == "not_applicable"
    print("PASS: attempt parser, reliability, robust statistics, and median CI")


if __name__ == "__main__":
    main()
