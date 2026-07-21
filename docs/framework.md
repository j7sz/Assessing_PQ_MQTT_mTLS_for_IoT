# Framework and architecture

This document explains how the benchmark is assembled, which parts belong to
this repository, and which parts come from pinned upstream projects.

The root [`README.md`](../README.md) gives the short layered view. This page
adds implementation detail without turning the reproduction guide into a code
walkthrough.

## 1. Two assessment workloads

The repository contains two related workloads built for Pico W and Pico 2 W.
They share board settings, generated test keys, build rules, and pinned source
revisions.

### Isolated signature benchmark

Each `sigbench_<scheme>` image measures one scheme without Wi-Fi or TLS. It
signs and verifies a fixed 32-byte message using an embedded test key.

The normal campaign discards three warm-up operations and measures the next
30. Retained exceptions are marked in the result file.

The long FAEST-EM-128f feasibility run contains one measured operation. Key
generation, startup, USB output, and flashing are outside the timed region.

### MQTT connection benchmark

Each `mqtt_client_<scheme>` image connects through Wi-Fi to Mosquitto. The
encrypted targets use TLS 1.3 mutual authentication and the same
`X25519MLKEM768` hybrid key exchange.

Only the certificate signature scheme changes between encrypted targets. The
Plain MQTT image provides an unencrypted network baseline.

## 2. Responsibilities by layer

| Layer | Repository components | Responsibility |
|---|---|---|
| Applications | `benchmark_main.c`, `snova_verify_main.c`, `mqtt_client/main.c` | Run a primitive or connection campaign and emit machine-readable rows. |
| Benchmark support | `bench.c/h`, `mqtt_client/runtime_memory.c` | Measure time, cycles, heap use, stack high-water marks, and allocation failures. |
| Common crypto interface | `scheme.h`, `adapters/` | Give every primitive benchmark the same sign and verify calls. |
| MQTT and transport | `mqtt_client/mqtt.c`, `plain_transport.c`, `tls_transport.c` | Build MQTT 3.1.1 packets and drive plain TCP or wolfSSL over lwIP callbacks. |
| TLS and cryptography | Patched wolfSSL plus PQClean, HAWK, MAYO-M4, and SNOVA | Perform TLS 1.3, X.509 checks, key exchange, signing, and verification. |
| Platform and network | Pico SDK, lwIP, CYW43 driver | Provide clocks, USB serial, RNG, DNS, SNTP, raw TCP, and Wi-Fi. |
| Hardware and broker | Pico W, Pico 2 W, Mosquitto, OpenSSL providers | Run the firmware and accept the matching client certificate. |

Most application logic above the third-party libraries is repository-owned.
The benchmark harness, adapter interface, MQTT encoder, transport bridge, and
measurement instrumentation are not copied from the Pico SDK or lwIP.

## 3. Current dependency inventory

Exact commit hashes are recorded in
[`third_party/versions.txt`](../third_party/versions.txt). The fetch script
checks out those revisions instead of following moving branches.

| Source | Role | Local treatment |
|---|---|---|
| Pico SDK 2.2.0 | Board support, Wi-Fi, lwIP, USB, clocks, and RNG | Upstream source is unchanged. CMake derives target-specific linker scripts when a larger stack is required. |
| wolfSSL 5.9.1-stable | TLS 1.3, X.509, ML-KEM, RSA, ECDSA, and ML-DSA | A tracked patch adds the experimental certificate schemes and Pico-specific integration described below. |
| PQClean | ML-DSA-44 and Falcon-512 primitives | Upstream clean implementations are wrapped by the common adapter. Falcon is also compiled into its isolated TLS library. |
| HAWK reference | HAWK-512 | Upstream source is unchanged. A benchmark adapter and a wolfCrypt-style TLS shim integrate it. |
| MAYO-M4 | MAYO-1 | The memory-reduced reference code is unchanged. Repository CMake selects its low-stack evaluator. |
| SNOVA 2.3 | SNOVA-24-5-16-4 | Upstream source is unchanged. The repository supplies its adapter, RNG bridge, TLS shim, and large-stack build rules. |

## 4. Local wolfSSL integration

ML-DSA and `X25519MLKEM768` use wolfSSL's post-quantum support. HAWK, MAYO,
and SNOVA were not available as TLS certificate algorithms in the pinned
wolfSSL revision.

The tracked `tools/patches/pq_mqtt_wolfssl_tls.patch` adds their X.509 and TLS
1.3 identifiers. It also connects Falcon to the PQClean implementation and
aligns its certificate identifiers with the broker tooling.

| Scheme | X.509 object identifier | TLS SignatureScheme |
|---|---|---:|
| HAWK-512 | `1.3.6.1.4.1.99999.1.1` | `0xFE09` |
| MAYO-1 | `1.3.9999.8.1.3` | `0xFF32` |
| SNOVA-24-5-16-4 | `1.3.9999.10.1.1` | `0xFF3A` |

The Pico does not load an OpenSSL provider. Its algorithms are compiled into
the firmware. OpenSSL providers exist only on the broker side for certificate
handling and TLS negotiation.

### Two wolfSSL configurations

`config/wolfssl/user_settings.h` creates a crypto-only wolfSSL build for the
RSA and ECDSA primitive benchmarks. It excludes TLS and filesystem support.

`config/wolfssl/tls/user_settings.h` creates the MQTT TLS build. It enables TLS
1.3, the hybrid key exchange, buffer-based X.509, user I/O callbacks, and only
the signature scheme selected for that firmware.

### One TLS library per scheme

Every MQTT target receives its own wolfSSL library variant. It compiles only
the selected signature implementation instead of carrying every algorithm in
every image.

This isolation is important for fair flash and SRAM comparisons. The
`tests/test_mqtt_scheme_isolation.sh` check examines the linked images for
accidental cross-scheme symbols.

## 5. Network and measurement flow

The encrypted connection follows this sequence:

```text
SNTP clock sync
      ↓
DNS lookup → raw TCP connection → wolfSSL TLS 1.3 handshake
                                      ↓
                         MQTT CONNECT → CONNACK
                                      ↓
                    close connection and print CSV rows
```

`tls_transport.c` connects wolfSSL to lwIP through send and receive callbacks.
There is no BSD socket layer and no filesystem in the firmware.

The callbacks count transmitted and received bytes and record time spent
waiting for network input. This separates TLS wall time into device work and
network waiting without claiming that every delay is cryptographic work.

The firmware emits one row per connection attempt. It includes success or
failure, failure stage, phase timings, allocation state, heap and stack use,
and client-observed traffic.

## 6. Memory design

The Pico SDK normally places the main stack in a small scratch bank. MAYO,
Falcon, and SNOVA need larger contiguous call frames, so their build rules
reserve stack space from normal SRAM.

| Current target | Relevant reservation |
|---|---:|
| MAYO-1 primitive | 220 KiB stack |
| SNOVA primitive reference build | 420 KiB stack |
| SNOVA Pico W optimized or verify-only build | Target-specific RAM stack, up to 232 KiB |
| Normal encrypted MQTT target | 128 KiB heap plus a target-specific stack |
| Falcon-512 MQTT | 8 KiB stack on Pico W; 64 KiB on Pico 2 W |
| MAYO-1 MQTT | 16 KiB stack |
| SNOVA MQTT | 256 KiB stack plus 128 KiB heap |

The linker proves that static data, heap boundary, and reserved stack do not
overlap. Runtime wrappers then measure allocation peaks and stack high-water
marks during the operation.

This is why a link failure is a result rather than a build nuisance. For
example, the SNOVA MQTT image fits Pico 2 W but exceeds Pico W SRAM.

## 7. Certificates and broker boundary

The board has no filesystem. Its CA certificate, client certificate, and
private key are compiled as DER byte arrays in `mqtt_client/certs/`.

The matching PEM files under `certlab/<scheme>/` belong to the Mosquitto side.
They are deliberately public test credentials and must never secure a real
device.

`mqtt_client/tls_transport.c` loads the embedded buffers, requires peer
verification, selects `X25519MLKEM768`, and drives `wolfSSL_connect()` over the
raw TCP callbacks.

See [`broker.md`](broker.md) for provider limitations, listener ports, and
Mosquitto configuration. See [`../certlab/README.md`](../certlab/README.md) for
the certificate-file layout.

## 8. Measurement boundaries

| Measurement | Start and end |
|---|---|
| Primitive signing | Only the selected implementation's signing call. |
| Primitive verification | Only verification of a fixed valid signature. |
| DNS | Hostname lookup request through completion or failure. |
| TCP | Connection attempt through the lwIP connection callback. |
| TLS | Entry to `wolfSSL_connect()` through success or failure. |
| MQTT | CONNECT write through receipt of a valid CONNACK. |
| Total connection | Start of the attempt through MQTT completion or failure. |
| Traffic | Callback byte and call counts, both for the handshake and complete connection. |
| Memory | Heap and protected-stack observations around the measured attempt. |

The result parsers preserve failed and incomplete attempts. A missing value is
not converted to zero, and TCP variability is not presented as signature
computation time.

## 9. Current firmware target map

| Target family | Boards | Purpose |
|---|---|---|
| `sigbench_rsa2048`, `sigbench_ecdsa_p256` | Both | Classical primitive baselines. |
| `sigbench_mldsa44`, `sigbench_falcon512`, `sigbench_hawk512`, `sigbench_mayo1` | Both | Selected post-quantum primitive measurements. |
| `sigbench_snova_24_5_16_4` | Pico 2 W | SNOVA signing and verification with the reference build. |
| `sigbench_snova_24_5_16_4_opt`, `sigbench_snova_24_5_16_4_verify` | Pico W | Record the constrained-board signing and verify-only outcomes. |
| `mqtt_client_<scheme>` | Both when memory permits | Plain MQTT or one isolated certificate scheme per firmware image. |

Build and data-collection commands live in
[`reproduce.md`](reproduce.md). Generated measurements are kept in the local,
Git-ignored `benchmark-results/` directory.

## 10. Full primitive assessment coverage

The primitive study was broader than the later MQTT-over-mTLS selection. It
asked whether each candidate could sign and verify on each board, and how long
successful operations took.

A resource limit or verify-only implementation is an assessment result, not
missing documentation.

| Candidate family | Parameter sets and recorded outcome |
|---|---|
| SLH-DSA | SHA2-128f, SHA2-128s, SHAKE-128f, and SHAKE-128s completed on both boards. |
| FAEST | FAEST-EM-128f completed one sign and verify operation on Pico 2 W. The latest table has no Pico W timing. |
| MQOM | L1-GF(16)-fast-3r signing and verification completed on both boards. |
| SDitH | L1-GF(2)-fast signing and verification completed on Pico 2 W. It is unsupported on Pico W. |
| SQIsign | SQIsign-I verification completed on both boards. Signing was not implemented by the tested Cortex-M reference path. |
| UOV | Ip-pkc and Is-pkc were tested with expanded and 32-byte compressed secret keys. Both forms completed on Pico 2 W; only expanded-key signing has a Pico W timing. |
| QR-UOV | All four Level-1 parameter sets completed signing and verification on both boards. |
| SNOVA | 24-5-16-4 completed both operations on Pico 2 W and verification on Pico W. Three additional sets completed on Pico 2 W. |

The clean branch ships the buildable core used by the selected public matrix.
Some older targets are available only in development history.

Store generated result CSV files and raw serial logs locally. For UOV, use
separate rows for expanded and compressed secret-key measurements.
