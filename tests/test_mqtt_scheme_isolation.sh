#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ "$#" -eq 0 ]; then
    set -- "$root/build-pico2w-demo" "$root/build-picow-demo"
fi

symbols_for()
{
    arm-none-eabi-nm "$1" | awk 'BEGIN { IGNORECASE=1 } /mldsa|dilith|falcon|hawk|mayo|snova/'
}

assert_only()
{
    elf=$1
    expected=$2
    symbols=$(symbols_for "$elf")

    for scheme in mldsa falcon hawk mayo snova; do
        case "$scheme:$expected" in
            mldsa:mldsa)
                printf '%s\n' "$symbols" | grep -Eqi 'mldsa|dilith'
                ;;
            "$scheme:$scheme")
                printf '%s\n' "$symbols" | grep -Eqi "$scheme"
                ;;
            mldsa:*)
                ! printf '%s\n' "$symbols" | grep -Eqi 'mldsa|dilith'
                ;;
            *)
                ! printf '%s\n' "$symbols" | grep -Eqi "$scheme"
                ;;
        esac
    done
}

checked=0
for build in "$@"; do
    dir="$build/mqtt_client"
    [ -d "$dir" ] || continue

    for entry in \
        mqtt_client_mldsa44:mldsa \
        mqtt_client_falcon512:falcon \
        mqtt_client_hawk512:hawk \
        mqtt_client_mayo1:mayo \
        mqtt_client_snova_24_5_16_4:snova \
        mqtt_client_ecdsa_p256:none \
        mqtt_client_rsa2048:none \
        mqtt_client_plain:none
    do
        target=${entry%%:*}
        expected=${entry#*:}
        elf="$dir/$target.elf"
        [ -f "$elf" ] || continue
        assert_only "$elf" "$expected"
        checked=$((checked + 1))
    done
done

if [ "$checked" -eq 0 ]; then
    echo "FAIL: no MQTT client ELF files found" >&2
    exit 1
fi

echo "PASS: $checked MQTT client ELF files contain only their selected PQ signature scheme"
