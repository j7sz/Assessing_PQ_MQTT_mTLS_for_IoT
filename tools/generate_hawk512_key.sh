#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
hawk=${HAWK_ROOT:-"$root/third_party/hawk"}
tmp="${TMPDIR:-/tmp}/gen_hawk512_key"

cc -std=c99 -O2 -DHAWK_AVX2=0 -DLOGN=9 \
    -DKEY_GUARD='"KEYS_HAWK512_H"' -I"$hawk/src" \
    "$root/tools/gen_hawk512_key.c" \
    "$hawk/src/hawk_kgen.c" "$hawk/src/hawk_sign.c" \
    "$hawk/src/hawk_vrfy.c" "$hawk/src/ng_fxp.c" \
    "$hawk/src/ng_hawk.c" "$hawk/src/ng_mp31.c" \
    "$hawk/src/ng_ntru.c" "$hawk/src/ng_poly.c" \
    "$hawk/src/ng_zint31.c" "$hawk/src/sha3.c" \
    -o "$tmp"
"$tmp" > "$root/keys/keys_hawk512.h"
echo "wrote $root/keys/keys_hawk512.h"
