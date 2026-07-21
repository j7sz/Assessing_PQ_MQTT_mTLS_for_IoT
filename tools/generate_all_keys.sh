#!/bin/sh
# Generate deterministic, test-only keys for the public benchmark targets.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

python3 "$root/tools/generate_pqclean_keys.py" mldsa44 falcon512
sh "$root/tools/generate_hawk512_key.sh"
python3 "$root/tools/kat_to_header.py" \
    "$root/third_party/mayo-m4/submodules/MAYO-C/KAT/PQCsignKAT_24_MAYO_1.rsp" \
    "$root/keys/keys_mayo1.h"
sh "$root/tools/generate_snova_keys.sh"
