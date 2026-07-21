#!/usr/bin/env bash
#
# gen_oqs_pki.sh - generate a disposable CA/server/client PKI for an
# oqs-provider signature algorithm.
#
# Usage:
#   ./tools/gen_oqs_pki.sh <scheme-dir> <openssl-algorithm> [outdir] [port]
#
# Example:
#   ./tools/gen_oqs_pki.sh snova_24_5_16_4 snova2454 certlab/snova_24_5_16_4 8882
#
set -euo pipefail

SCHEME="${1:?Usage: $0 <scheme-dir> <openssl-algorithm> [outdir] [port]}"
ALG="${2:?Usage: $0 <scheme-dir> <openssl-algorithm> [outdir] [port]}"
OUTDIR="${3:-certlab/$SCHEME}"
PORT="${4:-8882}"

OPENSSL="${OPENSSL:-openssl}"
OPENSSL_MODULES_DIR="${OPENSSL_MODULES_DIR:-/opt/homebrew/Cellar/openssl@3/3.6.2/lib/ossl-modules}"
PROV_ARGS=(-provider-path "$OPENSSL_MODULES_DIR" -provider oqsprovider -provider default)

mkdir -p "$OUTDIR"

echo "[+] Checking oqs-provider from $OPENSSL_MODULES_DIR"
"$OPENSSL" list -providers "${PROV_ARGS[@]}" | grep -q oqsprovider

echo "[+] Generating CA key/certificate"
"$OPENSSL" genpkey "${PROV_ARGS[@]}" -algorithm "$ALG" \
    -out "$OUTDIR/ca.key.pem"
"$OPENSSL" req "${PROV_ARGS[@]}" -new -x509 -days 3650 \
    -key "$OUTDIR/ca.key.pem" \
    -subj "/CN=pico-pqc-sigbench ${SCHEME} CA/O=PicoMQTT" \
    -addext "basicConstraints=critical,CA:true,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
    -out "$OUTDIR/ca.cert.pem"

echo "[+] Generating server key/certificate"
"$OPENSSL" genpkey "${PROV_ARGS[@]}" -algorithm "$ALG" \
    -out "$OUTDIR/server.key.pem"
"$OPENSSL" req "${PROV_ARGS[@]}" -new \
    -key "$OUTDIR/server.key.pem" \
    -subj "/CN=localhost/O=PicoMQTT" \
    -addext "basicConstraints=critical,CA:false" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -out "$OUTDIR/server.csr"
"$OPENSSL" x509 "${PROV_ARGS[@]}" -req -days 3650 \
    -in "$OUTDIR/server.csr" \
    -CA "$OUTDIR/ca.cert.pem" \
    -CAkey "$OUTDIR/ca.key.pem" \
    -CAcreateserial \
    -copy_extensions copy \
    -out "$OUTDIR/server.cert.pem"

echo "[+] Generating client key/certificate"
"$OPENSSL" genpkey "${PROV_ARGS[@]}" -algorithm "$ALG" \
    -out "$OUTDIR/client_${SCHEME}.key.pem"
"$OPENSSL" req "${PROV_ARGS[@]}" -new \
    -key "$OUTDIR/client_${SCHEME}.key.pem" \
    -subj "/CN=pico2w-${SCHEME}/O=PicoMQTT" \
    -addext "basicConstraints=critical,CA:false" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=clientAuth" \
    -out "$OUTDIR/client_${SCHEME}.csr"
"$OPENSSL" x509 "${PROV_ARGS[@]}" -req -days 3650 \
    -in "$OUTDIR/client_${SCHEME}.csr" \
    -CA "$OUTDIR/ca.cert.pem" \
    -CAkey "$OUTDIR/ca.key.pem" \
    -CAcreateserial \
    -copy_extensions copy \
    -out "$OUTDIR/client_${SCHEME}.cert.pem"

echo "[+] Converting PEM certificates/keys to DER"
"$OPENSSL" x509 -in "$OUTDIR/ca.cert.pem" -outform DER \
    -out "$OUTDIR/ca.cert.der"
"$OPENSSL" x509 -in "$OUTDIR/server.cert.pem" -outform DER \
    -out "$OUTDIR/server.cert.der"
"$OPENSSL" x509 -in "$OUTDIR/client_${SCHEME}.cert.pem" -outform DER \
    -out "$OUTDIR/client_${SCHEME}.cert.der"
"$OPENSSL" pkey "${PROV_ARGS[@]}" -in "$OUTDIR/server.key.pem" -outform DER \
    -out "$OUTDIR/server.key.der"
"$OPENSSL" pkey "${PROV_ARGS[@]}" -in "$OUTDIR/client_${SCHEME}.key.pem" -outform DER \
    -out "$OUTDIR/client_${SCHEME}.key.der"

cat > "$OUTDIR/mosquitto-${SCHEME}.conf" <<EOF
listener $PORT
protocol mqtt
cafile /path/to/pico-pqc-sigbench/$OUTDIR/ca.cert.pem
certfile /path/to/pico-pqc-sigbench/$OUTDIR/server.cert.pem
keyfile /path/to/pico-pqc-sigbench/$OUTDIR/server.key.pem
require_certificate true
use_identity_as_username true
tls_version tlsv1.3
EOF

echo "[+] Verifying generated certificates"
"$OPENSSL" verify "${PROV_ARGS[@]}" -CAfile "$OUTDIR/ca.cert.pem" \
    "$OUTDIR/server.cert.pem" "$OUTDIR/client_${SCHEME}.cert.pem"

echo "[+] Written PKI under $OUTDIR"
