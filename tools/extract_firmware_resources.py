#!/usr/bin/env python3
"""Extract linked FLASH/SRAM quantities from Pico firmware ELF files.

All ``*_kb`` columns use decimal kilobytes (1 kB = 1000 B). Linked resource
figures are build-time quantities, not runtime peak-memory measurements.
"""

from __future__ import annotations

import argparse
import csv
import pathlib
import shutil
import subprocess
import sys


BOARD_MEMORY = {
    "pico_w": {"flash": 2 * 1024 * 1024, "sram": 264 * 1024},
    "pico2_w": {"flash": 4 * 1024 * 1024, "sram": 520 * 1024},
}
RAM_BASE = 0x20000000


def tool(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    fallback = pathlib.Path(
        "/Applications/ArmGNUToolchain/15.2.rel1/arm-none-eabi/bin"
    ) / name
    if fallback.exists():
        return str(fallback)
    raise SystemExit(f"error: {name} was not found")


def output(*command: str) -> str:
    return subprocess.run(
        command, check=True, text=True, stdout=subprocess.PIPE
    ).stdout


def sections(elf: pathlib.Path) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for line in output(tool("arm-none-eabi-size"), "-A", str(elf)).splitlines():
        parts = line.split()
        if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
            continue
        result[parts[0]] = (int(parts[1]), int(parts[2]))
    return result


def symbols(elf: pathlib.Path) -> dict[str, int]:
    wanted = {"__heap_start", "__heap_end", "__HeapLimit",
              "__StackBottom", "__StackTop"}
    result: dict[str, int] = {}
    for line in output(tool("arm-none-eabi-nm"), "-an", str(elf)).splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-1] in wanted:
            result[parts[-1]] = int(parts[0], 16)
    return result


def kb(value: int) -> str:
    return f"{value / 1000:.3f}"


def usable_heap_capacity(sym: dict[str, int]) -> int:
    """Return heap bytes that cannot overlap the configured main stack."""
    heap_start = sym.get("__heap_start")
    heap_end = sym.get("__heap_end", sym.get("__HeapLimit"))
    stack_bottom = sym.get("__StackBottom")
    if heap_start is None or heap_end is None:
        return 0
    usable_end = min(heap_end, stack_bottom) if stack_bottom is not None else heap_end
    return max(0, usable_end - heap_start)


def extract(elf: pathlib.Path, board: str) -> dict[str, object]:
    sec = sections(elf)
    sym = symbols(elf)
    limits = BOARD_MEMORY[board]
    ram_limit = RAM_BASE + limits["sram"]
    excluded = {".heap", ".stack_dummy"}
    static_ram = sum(
        size for name, (size, address) in sec.items()
        if RAM_BASE <= address < ram_limit and name not in excluded
    )
    heap_reserved = sec.get(".heap", (0, 0))[0]
    stack_reserved = sec.get(".stack_dummy", (0, 0))[0]
    heap_arena = usable_heap_capacity(sym)
    linked_ram_minimum = static_ram + heap_reserved + stack_reserved

    binary = elf.with_suffix(".bin")
    flash = binary.stat().st_size if binary.exists() else 0
    return {
        "board": board,
        "target": elf.stem,
        "status": "success",
        "flash_bytes": flash,
        "flash_kb": kb(flash),
        "flash_region_bytes": limits["flash"],
        "flash_headroom_bytes": limits["flash"] - flash,
        "static_ram_bytes": static_ram,
        "static_ram_kb": kb(static_ram),
        "heap_reserved_minimum_bytes": heap_reserved,
        "heap_arena_capacity_bytes": heap_arena,
        "stack_reserved_bytes": stack_reserved,
        "linked_ram_minimum_bytes": linked_ram_minimum,
        "linked_ram_minimum_kb": kb(linked_ram_minimum),
        "sram_region_bytes": limits["sram"],
        "linked_ram_headroom_bytes": limits["sram"] - linked_ram_minimum,
        "elf": str(elf),
        "bin": str(binary) if binary.exists() else "",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--board", required=True, choices=sorted(BOARD_MEMORY))
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("elf", nargs="+", type=pathlib.Path)
    args = parser.parse_args()

    rows = []
    for elf in args.elf:
        if not elf.exists():
            print(f"warning: missing ELF: {elf}", file=sys.stderr)
            continue
        rows.append(extract(elf, args.board))
    if not rows:
        raise SystemExit("error: no ELF files were found")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {args.output} ({len(rows)} firmware images)")


if __name__ == "__main__":
    main()
