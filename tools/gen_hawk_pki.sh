#!/usr/bin/env bash
#
# Generate a proper HAWK-512 MQTT PKI:
#   - HAWK Root CA certificate/key
#   - HAWK broker/server certificate/key signed by the Root CA
#   - HAWK client-device certificate/key signed by the Root CA
# and regenerate mqtt_client/certs/certs_hawk512.h from the CA + client-device
# material consumed by the Pico MQTT client.
#
# Usage:
#   tools/gen_hawk_pki.sh [certlab/hawk512]
#
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUTDIR="${1:-"$ROOT/certlab/hawk512"}"
BUILD_DIR="${TMPDIR:-/tmp}/hawk-pki-build"
GEN="$BUILD_DIR/gen_hawk_pki"
HAWK_SRC="$ROOT/third_party/hawk/src"
HAWK_PROVIDER_DIR="${HAWK_PROVIDER_DIR:-/private/tmp/hawk_provider_inspect/hawk_provider}"
HAWK_MODULE_DIR="${HAWK_MODULE_DIR:-"$HAWK_PROVIDER_DIR/build"}"
OPENSSL="${OPENSSL:-openssl}"

mkdir -p "$BUILD_DIR"

cc -std=c11 -O2 -Wall -Wextra -I"$HAWK_SRC" \
  "$ROOT/tools/gen_hawk_pki.c" \
  "$HAWK_SRC/hawk_kgen.c" \
  "$HAWK_SRC/hawk_sign.c" \
  "$HAWK_SRC/hawk_vrfy.c" \
  "$HAWK_SRC/ng_fxp.c" \
  "$HAWK_SRC/ng_hawk.c" \
  "$HAWK_SRC/ng_mp31.c" \
  "$HAWK_SRC/ng_ntru.c" \
  "$HAWK_SRC/ng_poly.c" \
  "$HAWK_SRC/ng_zint31.c" \
  "$HAWK_SRC/sha3.c" \
  -o "$GEN"

"$GEN" "$OUTDIR"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/hawk-pki-header.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

"$OPENSSL" x509 -in "$OUTDIR/ca.cert.pem" \
  -outform DER -out "$WORKDIR/ca.der"
"$OPENSSL" x509 -in "$OUTDIR/client_hawk512.cert.pem" \
  -outform DER -out "$WORKDIR/client.der"
"$OPENSSL" pkey \
  -provider-path "$HAWK_MODULE_DIR" \
  -provider hawk_provider \
  -provider default \
  -in "$OUTDIR/client_hawk512.key.pem" \
  -outform DER -out "$WORKDIR/client.key.der"

mkdir -p "$ROOT/mqtt_client/certs"
cp "$OUTDIR/ca.cert.pem" "$ROOT/mqtt_client/certs/hawk512_cert.pem"
cp "$OUTDIR/client_hawk512.key.pem" "$ROOT/mqtt_client/certs/hawk512_key.pem"

emit_array() {
  local label="$1"
  local file="$2"
  printf "static const uint8_t %s[] = {\n" "$label"
  xxd -i < "$file"
  printf "};\n"
  printf "static const size_t %s_LEN = sizeof(%s);\n\n" "$label" "$label"
}

{
  printf "/* AUTO-GENERATED from certlab/hawk512 HAWK Root CA/client-device material */\n"
  printf "/* HAWK OID: 1.3.6.1.4.1.99999.1.1, TLS SignatureScheme: 0xFE09 */\n"
  printf "#pragma once\n#include <stdint.h>\n#include <stddef.h>\n\n"
  emit_array "MQTT_CA_CERT_DER" "$WORKDIR/ca.der"
  emit_array "MQTT_CLIENT_CERT_DER" "$WORKDIR/client.der"
  emit_array "MQTT_CLIENT_KEY_DER" "$WORKDIR/client.key.der"
} > "$ROOT/mqtt_client/certs/certs_hawk512.h"

echo "[+] Wrote $OUTDIR"
echo "[+] Wrote $ROOT/mqtt_client/certs/certs_hawk512.h"
