# Disposable broker certificates

This directory contains the certificate chains used by the Mosquitto test
broker. Each scheme has four PEM files:

- `ca.cert.pem` and `ca.key.pem`: the test certificate authority;
- `server.cert.pem` and `server.key.pem`: the Mosquitto identity; and
- `client_<scheme>.cert.pem` and `client_<scheme>.key.pem`: the board identity.

It also contains one `mosquitto-*.conf` example per scheme. Replace
`/path/to/pico-pqc-sigbench` in a configuration file with the absolute path to
your checkout before starting Mosquitto.

All private keys here are intentionally public, disposable test data. They are
included so another lab can run the same certificate chain. Never deploy them
on a real broker or device.

The board firmware does not read these PEM files. Equivalent DER bytes are
already embedded in the matching header under `mqtt_client/certs/`. To test a
new certificate chain, run:

```sh
sh tools/import_client_cert.sh --scheme mldsa44 \
  certlab/mldsa44/ca.cert.pem \
  certlab/mldsa44/client_mldsa44.cert.pem \
  certlab/mldsa44/client_mldsa44.key.pem
```

Change `mldsa44` and the paths for the selected scheme. HAWK uses its separate
`tools/gen_hawk_pki.sh` workflow because normal oqs-provider releases do not
expose HAWK. See [`../docs/broker.md`](../docs/broker.md) for provider and port
requirements.
