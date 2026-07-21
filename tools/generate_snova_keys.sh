#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SRC="$ROOT/third_party/snova/src"

generate() {
    name=$1
    shift
    make -C "$SRC" clean all OPT=REF P="$*"
    python3 "$ROOT/tools/kat_to_header.py" \
        "$SRC/PQCsignKAT_${name}.rsp" \
        "$ROOT/keys/keys_$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]').h"
    lower=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
    python3 "$ROOT/tools/snova_kat_verify_to_header.py" \
        "$SRC/PQCsignKAT_${name}.rsp" \
        "keys_${lower}.h" \
        "$ROOT/keys/keys_${lower}_verify.h"
}

generate SNOVA_24_5_16_4 \
    -D SNOVA_v=24 -D SNOVA_o=5 -D SNOVA_q=16 -D SNOVA_l=4
