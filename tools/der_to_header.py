#!/usr/bin/env python3
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("input", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
data = args.input.read_bytes()
rows = []
for i in range(0, len(data), 12):
    rows.append("    " + ", ".join(f"0x{x:02x}" for x in data[i:i + 12]))
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(
    "#ifndef STATIC_ECDSA_KEY_DER_H\n#define STATIC_ECDSA_KEY_DER_H\n"
    "#include <stdint.h>\n"
    f"static const uint8_t STATIC_KEY_DER[{len(data)}] = {{\n"
    + ",\n".join(rows)
    + "\n};\n#endif\n"
)
