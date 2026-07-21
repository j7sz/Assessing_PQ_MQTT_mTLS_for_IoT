# Static benchmark keys

The isolated signature firmware uses fixed, public test keys so key generation
is never included in the measured signing or verification time.

Generate every key needed by the seven-scheme assessment with:

```sh
sh tools/generate_all_keys.sh
```

The generated `keys/*.h` files are ignored by Git. The script uses deterministic
test inputs and the upstream revisions recorded in `third_party/versions.txt`.
ECDSA P-256 and RSA-2048 use wolfSSL's embedded test keys.

These keys exist only for repeatable measurements. Never use them in a real
product or to protect real data.
