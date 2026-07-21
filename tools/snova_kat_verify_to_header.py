#!/usr/bin/env python3
"""Extract SNOVA KAT pk/signed-message fields into a verify-only C header."""

import argparse
import re
from pathlib import Path


def field(text: str, name: str) -> bytes:
    match = re.search(rf"(?m)^{re.escape(name)}\s*=\s*([0-9A-Fa-f]+)\s*$", text)
    if not match:
        raise SystemExit(f"missing '{name} = ...' field")
    return bytes.fromhex(match.group(1))


def c_array(name: str, data: bytes) -> str:
    rows = []
    for offset in range(0, len(data), 12):
        chunk = data[offset:offset + 12]
        rows.append("    " + ", ".join(f"0x{x:02x}" for x in chunk))
    return (
        f"static const uint8_t {name}[{len(data)}] = {{\n"
        + ",\n".join(rows)
        + "\n};\n"
    )


def selected_record(path: Path, count: int) -> str:
    records = re.split(r"(?m)^\s*count\s*=\s*", path.read_text())
    for record in records[1:]:
        first, _, rest = record.partition("\n")
        if int(first.strip()) == count:
            return rest
    raise SystemExit(f"count = {count} not found")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("rsp", type=Path)
    parser.add_argument("base_header")
    parser.add_argument("output", type=Path)
    parser.add_argument("--count", type=int, default=0)
    args = parser.parse_args()

    record = selected_record(args.rsp, args.count)
    msg = field(record, "msg")
    sm = field(record, "sm")
    if len(sm) < len(msg) or sm[-len(msg):] != msg:
        raise SystemExit("expected SNOVA KAT sm field to be signature || message")
    sig = sm[:-len(msg)]

    guard = re.sub(r"\W+", "_", args.output.name.upper())
    text = (
        f"#ifndef {guard}\n#define {guard}\n\n#include <stdint.h>\n\n"
        f"#include \"{args.base_header}\"\n\n"
        f"/* Imported from {args.rsp.name}, count={args.count}. */\n"
        + c_array("STATIC_MSG", msg)
        + "\n"
        + c_array("STATIC_SIG", sig)
        + f"\n#endif /* {guard} */\n"
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text)


if __name__ == "__main__":
    main()
