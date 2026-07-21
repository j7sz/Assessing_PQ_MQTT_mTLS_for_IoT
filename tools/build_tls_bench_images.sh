#!/bin/sh
# Build all mqtt_client_* firmware images in TLS handshake benchmark mode.
#
# Usage:   sh tools/build_tls_bench_images.sh <pico_w|pico2_w> [ITERS] [WARMUP] [CAMPAIGN]
# Example: sh tools/build_tls_bench_images.sh pico2_w 30 3 1
#
# Requires PICO_SDK_PATH, the ARM toolchain, and tools/fetch_sources.sh.
# Wi-Fi credentials must be supplied through environment variables.
#
# UF2s and tls-build-status.csv land in build-<board>-tlsbench-c<campaign>/.
# Flash one image at a time,
# capture USB serial to a log file, then analyze with:
#   python3 tools/analyze_hs_csv.py --csv summary.csv *.log
set -e

BOARD="${1:?usage: $0 <pico_w|pico2_w> [ITERS] [WARMUP] [CAMPAIGN]}"
ITERS="${2:-30}"
WARMUP="${3:-3}"
CAMPAIGN="${4:-1}"
BUILD="build-${BOARD}-tlsbench-c${CAMPAIGN}"

# Keep credentials out of source control and, importantly, prevent a fresh
# campaign directory from silently compiling the placeholder credentials from
# mqtt_client/config.h.  Existing CMake caches are not treated as the source of
# truth because every campaign has its own build directory.
if [ -z "${MQTT_WIFI_SSID:-}" ] || [ -z "${MQTT_WIFI_PASS:-}" ] || \
   [ -z "${MQTT_BROKER_HOST:-}" ]; then
    echo "error: export MQTT_WIFI_SSID, MQTT_WIFI_PASS, and MQTT_BROKER_HOST" >&2
    exit 2
fi

TARGETS="mqtt_client_plain \
         mqtt_client_ecdsa_p256 mqtt_client_rsa2048 \
         mqtt_client_mldsa44 mqtt_client_hawk512 mqtt_client_falcon512 \
         mqtt_client_mayo1 mqtt_client_snova_24_5_16_4"
STATUS="$BUILD/tls-build-status.csv"

cmake -S . -B "$BUILD" \
    -DPICO_BOARD="$BOARD" \
    -DPQCLEAN_ROOT="$PWD/third_party/PQClean" \
    -DMQTT_WIFI_SSID="$MQTT_WIFI_SSID" \
    -DMQTT_WIFI_PASS="$MQTT_WIFI_PASS" \
    -DMQTT_BROKER_HOST="$MQTT_BROKER_HOST" \
    -DTLS_BENCH_ITERS="$ITERS" \
    -DTLS_BENCH_WARMUP="$WARMUP" \
    -DTLS_BENCH_CAMPAIGN="$CAMPAIGN" \
    -DCMAKE_BUILD_TYPE=Release

printf 'board,campaign,target,status,reason,artifact\n' > "$STATUS"
failures=0
for t in $TARGETS; do
    echo "=== building $t ($BOARD, campaign=$CAMPAIGN, attempts=$ITERS) ==="
    log="$BUILD/${t}-build.log"
    if cmake --build "$BUILD" --target "$t" -j > "$log" 2>&1; then
        cat "$log"
        artifact="$BUILD/mqtt_client/$t.uf2"
        printf '%s,%s,%s,success,none,%s\n' \
            "$BOARD" "$CAMPAIGN" "$t" "$artifact" >> "$STATUS"
    else
        cat "$log"
        reason=build_failed
        if grep -q 'region `FLASH.*overflowed\|will not fit in region `FLASH' "$log"; then
            reason=flash_overflow
        elif grep -q 'region `RAM.*overflowed\|will not fit in region `RAM' "$log"; then
            reason=ram_overflow
        elif grep -q 'undefined reference\|collect2: error\|ld returned.*exit status' "$log"; then
            reason=link_failed
        elif grep -q 'error: ' "$log"; then
            reason=compile_failed
        fi
        printf '%s,%s,%s,failure,%s,\n' \
            "$BOARD" "$CAMPAIGN" "$t" "$reason" >> "$STATUS"
        failures=$((failures + 1))
    fi
done

echo
echo "Done. UF2 images:"
find "$BUILD" -name "mqtt_client_*.uf2" 2>/dev/null || true
echo "Build status: $STATUS"
set -- "$BUILD"/mqtt_client/mqtt_client_*.elf
if [ -e "$1" ]; then
    python3 tools/extract_firmware_resources.py \
        --board "$BOARD" \
        --output "$BUILD/tls-firmware-resources.csv" \
        "$@"
    echo "Firmware resources: $BUILD/tls-firmware-resources.csv"
fi
if [ "$failures" -ne 0 ]; then
    echo "$failures target(s) failed; see per-target logs and build status."
    exit 1
fi
