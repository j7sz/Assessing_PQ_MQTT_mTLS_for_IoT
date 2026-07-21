# Mosquitto broker setup

The Pico firmware expects one Mosquitto listener per certificate scheme. This
keeps the broker certificate, client certificate, port, and firmware target
from being mixed accidentally.

## Important limitation

ECDSA and RSA work with normal OpenSSL. ML-DSA, Falcon, MAYO, and SNOVA need an
OpenSSL 3 build with an `oqsprovider`/liboqs version that exposes the matching
TLS signature algorithm. HAWK used a separate experimental `hawk_provider` in
the original testbed. That provider's source is **not present in this
repository and no public upstream was identified**, so the HAWK mTLS campaign
cannot yet be reproduced from this branch alone. The Pico HAWK primitive and
client code remain reproducible; the broker-provider gap is recorded rather
than hidden.

Upstream references: [liboqs](https://github.com/open-quantum-safe/liboqs),
[oqs-provider](https://github.com/open-quantum-safe/oqs-provider), and the
[HAWK project](https://hawk-sign.info/).

## Disposable lab certificates

`certlab/` contains the exact public test certificates and private keys used
for the assessment. They authenticate nothing outside this experiment. Never
reuse them for a real broker or device.

Replace `/path/to/pico-pqc-sigbench` in each `mosquitto-*.conf` file with the
absolute checkout path. You may combine all listener blocks into one broker
configuration if the same OpenSSL provider process can load every certificate.

Plain MQTT needs no certificate:

```conf
listener 1883 0.0.0.0
protocol mqtt
allow_anonymous true
```

An mTLS listener has this shape:

```conf
listener 8883 0.0.0.0
protocol mqtt
cafile /path/to/pico-pqc-sigbench/certlab/mldsa44/ca.cert.pem
certfile /path/to/pico-pqc-sigbench/certlab/mldsa44/server.cert.pem
keyfile /path/to/pico-pqc-sigbench/certlab/mldsa44/server.key.pem
require_certificate true
use_identity_as_username false
tls_version tlsv1.3
```

Use the configuration in the corresponding `certlab/<scheme>/` directory.

## Provider-based schemes

Build and install an OpenSSL-compatible liboqs and oqs-provider, then confirm
that the algorithms used here are visible:

```sh
export OPENSSL_MODULES=/absolute/path/to/ossl-modules
export OPENSSL_CONF="$PWD/certlab/openssl-oqs.cnf"

openssl list -providers
openssl list -signature-algorithms | \
  grep -Ei 'mldsa44|falcon512|mayo1|snova2454'
```

Start Mosquitto from the same environment so it loads the same OpenSSL modules:

```sh
mosquitto -c /absolute/path/to/mosquitto-all.conf -v
```

If Mosquitto runs as a system service, put `OPENSSL_CONF` and
`OPENSSL_MODULES` in the service environment. Exporting them only in a shell
does not change an already-running service.

Before flashing a board, check that the broker accepts the selected server
certificate and client certificate. A certificate that passes `openssl
verify` can still be rejected by the TLS stack if that OpenSSL/provider build
does not expose the algorithm for TLS 1.3.

## Scheme and port map

| Scheme | Directory | Port | Provider |
|---|---|---:|---|
| Plain MQTT | none | 1883 | none |
| ECDSA P-256 | `certlab/ecdsa-p256` | 8880 | OpenSSL default |
| RSA-2048 | `certlab/rsa2048` | 8881 | OpenSSL default |
| SNOVA-24-5-16-4 | `certlab/snova_24_5_16_4` | 8882 | oqs-provider |
| ML-DSA-44 | `certlab/mldsa44` | 8883 | oqs-provider/default OpenSSL PQ support |
| MAYO-1 | `certlab/mayo1` | 8884 | oqs-provider |
| HAWK-512 | `certlab/hawk512` | 8885 | unavailable experimental provider |
| Falcon-512 | `certlab/falcon512` | 8886 | oqs-provider |

The broker certificate must be signed by the CA in the same row. The Pico
firmware target embeds the matching client certificate and CA.
