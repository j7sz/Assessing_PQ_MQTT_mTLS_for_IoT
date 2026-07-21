#!/bin/sh
# Build the seven primitive-signature images used by the public assessment.
set -eu

BOARD="${1:?usage: $0 <pico_w|pico2_w>}"
BUILD="build-${BOARD}-sigbench"

case "$BOARD" in
    pico_w|pico2_w) ;;
    *) echo "error: board must be pico_w or pico2_w" >&2; exit 2 ;;
esac

TARGETS="sigbench_rsa2048 sigbench_ecdsa_p256 sigbench_mldsa44 \
sigbench_falcon512 sigbench_hawk512 sigbench_mayo1"
if [ "$BOARD" = pico2_w ]; then
    TARGETS="$TARGETS sigbench_snova_24_5_16_4"
else
    TARGETS="$TARGETS sigbench_snova_24_5_16_4_opt \
sigbench_snova_24_5_16_4_verify"
fi

cmake -S . -B "$BUILD" \
    -DPICO_BOARD="$BOARD" \
    -DCMAKE_BUILD_TYPE=Release

STATUS="$BUILD/signature-build-status.csv"
printf 'board,target,status,reason,artifact\n' > "$STATUS"
failures=0
for target in $TARGETS; do
    echo "=== building $target ($BOARD) ==="
    log="$BUILD/${target}-build.log"
    if cmake --build "$BUILD" --target "$target" -j > "$log" 2>&1; then
        cat "$log"
        printf '%s,%s,success,none,%s/%s.uf2\n' \
            "$BOARD" "$target" "$BUILD" "$target" >> "$STATUS"
    else
        cat "$log"
        reason=build_failed
        if grep -q 'will not fit in region.*RAM\|region.*RAM.*overflowed' "$log"; then
            reason=ram_overflow
        elif grep -q 'will not fit in region.*FLASH\|region.*FLASH.*overflowed' "$log"; then
            reason=flash_overflow
        elif grep -q 'undefined reference\|ld returned.*exit status' "$log"; then
            reason=link_failed
        elif grep -q 'error:' "$log"; then
            reason=compile_failed
        fi
        printf '%s,%s,failure,%s,\n' "$BOARD" "$target" "$reason" >> "$STATUS"
        failures=$((failures + 1))
    fi
done

set -- "$BUILD"/sigbench_*.elf
if [ -e "$1" ]; then
    python3 tools/extract_firmware_resources.py \
        --board "$BOARD" \
        --output "$BUILD/signature-firmware-resources.csv" \
        "$@"
fi

echo "Build status: $STATUS"
if [ "$failures" -ne 0 ]; then
    echo "$failures target(s) failed; keep the status and logs as results."
    exit 1
fi
