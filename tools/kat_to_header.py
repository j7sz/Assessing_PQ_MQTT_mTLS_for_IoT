#!/usr/bin/env python3
"""Extract one pk/sk pair from a NIST-style .rsp KAT file into a C header."""

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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("rsp", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--count", type=int, default=0)
    args = parser.parse_args()

    records = re.split(r"(?m)^\s*count\s*=\s*", args.rsp.read_text())
    selected = None
    for record in records[1:]:
        first, _, rest = record.partition("\n")
        if int(first.strip()) == args.count:
            selected = rest
            break
    if selected is None:
        raise SystemExit(f"count = {args.count} not found")

    pk, sk = field(selected, "pk"), field(selected, "sk")
    guard = re.sub(r"\W+", "_", args.output.name.upper())
    text = (
        f"#ifndef {guard}\n#define {guard}\n\n#include <stdint.h>\n\n"
        f"/* Imported from {args.rsp.name}, count={args.count}. */\n"
        + c_array("STATIC_PK", pk)
        + "\n"
        + c_array("STATIC_SK", sk)
        + f"\n#endif /* {guard} */\n"
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text)


if __name__ == "__main__":
    main()
