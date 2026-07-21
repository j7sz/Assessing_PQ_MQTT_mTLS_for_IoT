#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cc=${CC:-/opt/homebrew/bin/arm-none-eabi-gcc}

if [ ! -x "$cc" ]; then
    echo "SKIP: arm-none-eabi-gcc is unavailable"
    exit 0
fi

assert_capacity() {
    scheme_define=$1
    key_header=$2
    signature_size=$3
    extra_define=$4

    printf '%s\n' \
        "#include \"$key_header\"" \
        '#include "wolfssl/wolfcrypt/asn.h"' \
        "_Static_assert(WC_MAX_CERT_VERIFY_SZ >= $signature_size," \
        '    "TLS CertificateVerify output is too small");' | \
        "$cc" -x c -std=gnu11 -fsyntax-only \
            -DWOLFSSL_USER_SETTINGS -D"$scheme_define" -DHAVE_ECC \
            $extra_define \
            -I"$root/third_party/wolfssl" \
            -I"$root/config/wolfssl/tls" \
            -I"$root/mqtt_client" \
            -I"$root" \
            -I"$root/third_party/hawk/src" -
}

assert_capacity MQTT_LIB_SCHEME_HAWK512 mqtt_client/hawk512_tls.h WC_HAWK512_SIG_SIZE ''
assert_capacity MQTT_LIB_SCHEME_MAYO1 mqtt_client/mayo1_tls.h WC_MAYO1_SIG_SIZE ''
assert_capacity MQTT_LIB_SCHEME_SNOVA2454 mqtt_client/snova2454_tls.h WC_SNOVA2454_SIG_SIZE -DWOLFSSL_SNOVA2454

assert_sigalgo_list_capacity() {
    scheme_define=$1
    extra_define=$2

    printf '%s\n' \
        '#include "wolfssl/internal.h"' \
        '_Static_assert(WOLFSSL_MAX_SIGALGO >= 128,' \
        '    "PQC TLS SignatureScheme list is truncated");' | \
        "$cc" -x c -std=gnu11 -fsyntax-only \
            -DWOLFSSL_USER_SETTINGS -D"$scheme_define" -DHAVE_ECC \
            $extra_define \
            -I"$root/third_party/wolfssl" \
            -I"$root/config/wolfssl/tls" \
            -I"$root/mqtt_client" \
            -I"$root" \
            -I"$root/third_party/hawk/src" -
}

assert_sigalgo_list_capacity MQTT_LIB_SCHEME_MAYO1 ''
assert_sigalgo_list_capacity MQTT_LIB_SCHEME_SNOVA2454 -DWOLFSSL_SNOVA2454

echo "PASS: TLS CertificateVerify and PQC SignatureScheme buffers cover HAWK, MAYO, and SNOVA"
