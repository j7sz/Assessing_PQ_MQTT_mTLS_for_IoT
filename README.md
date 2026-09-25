# Post-quantum signatures on Raspberry Pi Pico boards

This repository contains the code and data used to compare classical and post-quantum (PQ) signature
schemes on two IoT boards:

- **Raspberry Pi Pico W** (Cortex-M0+, 125 MHz in this benchmark, 264 KB SRAM)
- **Raspberry Pi Pico 2 W** (Cortex-M33, 150 MHz, 520 KB SRAM)

It answers two practical questions:

1. How long does each board take to sign and verify a signature?
2. What happens when the scheme is used as X.509 certificate for authentication over MQTT connection
   using mutual TLS 1.3 (mTLS) to a Mosquitto broker?

“Mutual TLS” means that the board checks the broker certificate and the broker
checks the board certificate. Every encrypted test uses the same hybrid
`X25519MLKEM768` key exchange; only the certificate signature scheme changes.

## What is included

The isolated signing and verification study covers every candidate assessed
during the project:

- classical baselines: RSA-2048 and ECDSA P-256;
- standardized schemes: ML-DSA-44 and four Level-1 SLH-DSA variants;
- Falcon-512, HAWK-512, MAYO-1, and four SNOVA parameter sets;
- two UOV public-key modes, each with expanded and compressed secret-key
  timings, plus four QR-UOV parameter sets; and
- MQOM, SDitH, SQIsign, and FAEST.

Some experiments completed both operations; others exposed a memory limit,
stalled, or supported verification only. Those outcomes are part of the
feasibility assessment and remain visible in the results.

The later MQTT-over-mTLS study selected seven certificate schemes and one
no-encryption baseline:

| Scheme | Why it is here |
|---|---|
| ECDSA P-256 | Common classical baseline |
| RSA-2048 | Common classical baseline |
| ML-DSA-44 | Standardized post-quantum signature |
| Falcon-512 | Compact post-quantum signature candidate |
| HAWK-512 | Post-quantum candidate (Withdrawn, https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures) |
| MAYO-1 | Post-quantum candidate with high memory demand |
| SNOVA-24-5-16-4 | Post-quantum candidate with high memory demand |
| Plain MQTT | Network baseline without TLS |

The current artifact builds one firmware file per selected scheme. This keeps
one scheme's code or keys from changing another scheme's flash and memory
result.

The complete primitive assessment, including targets retained only in
development history, is explained in
[`Full primitive assessment coverage`](docs/framework.md#10-full-primitive-assessment-coverage).

## Layered architecture

The project is arranged in layers. Each layer has one job, so a reader can
follow a measurement from the physical board to the final CSV row.

```text
┌──────────────────────────────────────────────────────────────────────┐
│ Benchmark applications                                               │
│  benchmark_main.c                  mqtt_client/main.c                │
│  isolated sign + verify            Wi-Fi + MQTT connection campaign │
├──────────────────────────────────────────────────────────────────────┤
│ Repository middleware                                                │
│  bench.c/h + scheme.h + adapters/  mqtt.c + tls_transport.c         │
│  common timing and crypto API      MQTT packets and TLS measurements│
├──────────────────────────────────────────────────────────────────────┤
│ Security and protocol libraries                                      │
│  wolfSSL TLS 1.3 + wolfCrypt       compiled-in PQ implementations   │
│  mutual certificate checking       PQClean, HAWK, MAYO-M4, SNOVA    │
├──────────────────────────────────────────────────────────────────────┤
│ Pico SDK networking and platform                                     │
│  lwIP raw TCP, DNS, SNTP, CYW43 Wi-Fi, clocks, USB serial, RNG       │
├──────────────────────────────────────────────────────────────────────┤
│ Test hardware                                                        │
│  Pico W / Pico 2 W                  Mosquitto broker + OpenSSL       │
└──────────────────────────────────────────────────────────────────────┘
```

The isolated benchmark stops above the networking layers. The MQTT workload
uses the full stack and reports DNS, TCP, TLS, MQTT, memory, and traffic data.
See [`docs/framework.md`](docs/framework.md) for ownership and customization
details.

## Results

Benchmark output is intentionally local and ignored by Git. Run the
reproduction guide to generate your own primitive and MQTT result CSV files.
Keep raw serial logs with those files so each result can be checked later.

## Reproduce the assessment

Start with [`docs/reproduce.md`](docs/reproduce.md). It covers:

1. installing the Pico SDK and ARM compiler;
2. fetching the exact upstream source revisions;
3. building and flashing each board-specific firmware;
4. setting up Mosquitto and its test certificates;
5. capturing USB serial output; and
6. generating local result CSV files.

Broker setup is separated into [`docs/broker.md`](docs/broker.md) because the
experimental certificate schemes need special OpenSSL providers.

## Repository map

```text
adapters/       Small wrappers giving every signature scheme one common API
certlab/        Disposable test certificates and Mosquitto listener examples
cmake/          Build rules for the seven selected signature schemes
docs/           Architecture, reproduction, and broker instructions
mqtt_client/    Pico W/Pico 2 W MQTT-over-mTLS firmware
tests/          Host-side checks for parsing and build isolation
tools/          Dependency, key, build, capture-analysis, and summary scripts
```

All keys and certificates in this repository are public test material. Never
reuse them to secure a real device.
