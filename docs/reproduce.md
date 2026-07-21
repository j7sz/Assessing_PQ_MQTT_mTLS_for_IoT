# Reproducing the Pico W and Pico 2 W assessment

This guide starts from a clean checkout and ends with local CSV files. The
`benchmark-results/` directory is ignored by Git, so your results stay local.

## 1. Equipment and software

You need:

- one Pico W and/or Pico 2 W plus a data-capable USB cable;
- a Wi-Fi access point;
- another computer running Mosquitto (the original broker was a Raspberry Pi
  5 at `192.168.1.50`);
- CMake, Git, Python 3, an Arm embedded GCC toolchain, and a serial terminal;
- Raspberry Pi Pico SDK 2.2.0 at commit
  `a1438dff1d38bd9c65dbd693f0e5db4b9ae91779`.

The clean-build verification for this branch used Arm GNU Toolchain
15.2.Rel1. Record your compiler version because a different release can change
firmware size and whether a memory-limited image links.

Keep the broker, access point, distance, Wi-Fi channel, board power supply,
and firmware settings unchanged while comparing schemes.

## 2. Prepare a clean checkout

```sh
git clone --branch manuscript-artifact REPOSITORY_URL pico-pqc-sigbench
cd pico-pqc-sigbench

git clone https://github.com/raspberrypi/pico-sdk.git ../pico-sdk
git -C ../pico-sdk checkout a1438dff1d38bd9c65dbd693f0e5db4b9ae91779
git -C ../pico-sdk submodule update --init --recursive
export PICO_SDK_PATH="$PWD/../pico-sdk"

sh tools/fetch_sources.sh
sh tools/generate_all_keys.sh
```

`fetch_sources.sh` checks every dependency against the commit in
[`../third_party/versions.txt`](../third_party/versions.txt) and applies the
tracked wolfSSL MQTT/mTLS patch. It stops instead of silently using a different
revision.

The generated signature keys are deterministic test keys. MQTT firmware uses
the disposable certificate bundles already stored in `mqtt_client/certs/`.
Never use any of these keys or certificates outside a lab.

## 3. Isolated signing and verification

Build each board in its own directory:

```sh
sh tools/build_signature_bench_images.sh pico_w
sh tools/build_signature_bench_images.sh pico2_w
```

The output is one `.uf2` file per scheme. The script also records build status
and firmware resource use. A failed build is a result; keep its log.

For every `.uf2` file:

1. Hold BOOTSEL while connecting the board.
2. Copy the file to the `RPI-RP2` USB drive (or use `picotool load -v -x`).
3. Capture the USB serial output at 115200 baud until `=== DONE`.
4. Name the log with the board and scheme, for example
   `pico2_w-hawk512.log`.

On macOS, a simple capture looks like:

```sh
mkdir -p captures/signature
stty -f /dev/cu.usbmodemXXXX 115200 raw -echo
cat /dev/cu.usbmodemXXXX | tee captures/signature/pico2_w-hawk512.log
```

Turn the completed logs into one CSV:

```sh
python3 tools/analyze_signature_logs.py \
  --csv benchmark-results/my-primitive-runs.csv captures/signature/*.log
```

The firmware uses a fixed 32-byte message, three warm-ups, and 30 measured
operations. It times signing and verification separately, then confirms that
a valid signature passes and a modified signature fails. Key generation,
printing, startup, and flashing are outside the timed section.

Pico W SNOVA signing is expected not to complete within its SRAM limit. Keep
the serial log and report `not_completed`; do not turn it into a zero.

## 4. MQTT and mutual TLS

First configure Mosquitto by following [`broker.md`](broker.md). The default
ports are:

| Target | Port |
|---|---:|
| `mqtt_client_plain` | 1883 |
| `mqtt_client_ecdsa_p256` | 8880 |
| `mqtt_client_rsa2048` | 8881 |
| `mqtt_client_snova_24_5_16_4` | 8882 |
| `mqtt_client_mldsa44` | 8883 |
| `mqtt_client_mayo1` | 8884 |
| `mqtt_client_hawk512` | 8885 |
| `mqtt_client_falcon512` | 8886 |

Keep Wi-Fi credentials out of Git and supply the broker address at build time:

```sh
export MQTT_WIFI_SSID='lab-network'
read -s MQTT_WIFI_PASS
export MQTT_WIFI_PASS
export MQTT_BROKER_HOST='192.168.1.50'
```

Build one 30-attempt campaign for each board:

```sh
sh tools/build_tls_bench_images.sh pico_w 30 3 1
sh tools/build_tls_bench_images.sh pico2_w 30 3 1
```

Repeat with campaign numbers `2`, `3`, and so on for independent runs. Flash
and capture every image as in the primitive test. Wait for `[bench] done`.
Pico W SNOVA is expected to be recorded as a link failure, and Pico W MAYO-1
may fail during the protocol even though its isolated signature works.

Normalize captured MQTT logs with:

```sh
mkdir -p benchmark-results/reproduction
python3 tools/analyze_hs_csv.py \
  --csv benchmark-results/reproduction/mtls-summary.csv \
  --attempts-csv benchmark-results/reproduction/mtls-attempts.csv \
  captures/mqtt/*.log
```

The normalized attempt file also keeps the board-reported transmitted and
received byte counts. To measure complete packets on the network instead,
capture traffic on the broker, install Wireshark's `tshark`, and create a CSV
manifest with these columns:

```text
pcap,scheme,board,campaign,client_ip,server_ip
```

Then match TCP streams to the firmware attempts by their timestamps:

```sh
python3 tools/analyze_tls_pcaps.py captures/pcaps.csv \
  --attempts-csv benchmark-results/reproduction/mtls-attempts.csv \
  --csv benchmark-results/reproduction/mtls-packets.csv
```

The most useful comparison is the `tls` phase. TCP time varies with Wi-Fi and
must not be attributed to the signature scheme. Keep total connection time,
failures, heap/stack measurements, and traffic counts as separate fields.

## 5. What to keep with a replication

Archive these together:

- the Git commit and `third_party/versions.txt`;
- board model and physical board identifier;
- every build log, build-status CSV, and firmware-resource CSV;
- every complete or incomplete serial log;
- campaign number, run order, broker/Mosquitto/OpenSSL/provider versions;
- access-point model, channel, distance, and power arrangement; and
- packet captures if network traffic is part of the comparison.

This information makes a failed run explainable and a successful run
repeatable.
