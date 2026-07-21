#!/usr/bin/env python3
"""Generate deterministic test-only keys for configured PQClean schemes."""

import argparse
import subprocess
import tempfile
from pathlib import Path


SCHEMES = {
    "mldsa44": ("ml-dsa-44", "PQCLEAN_MLDSA44_CLEAN_", "keys_mldsa44.h"),
    "falcon512": ("falcon-512", "PQCLEAN_FALCON512_CLEAN_", "keys_falcon512.h"),
}


SOURCE = r'''
#include <stdint.h>
#include <stdio.h>
#include "api.h"
#include "randombytes.h"
#define J2_(a,b) a##b
#define J2(a,b) J2_(a,b)
#define P(x) J2(PREFIX,x)
static uint64_t state = UINT64_C(0x7069636f70716331);
int randombytes(uint8_t *out, size_t n) {
    while (n--) {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        *out++ = (uint8_t)state;
    }
    return 0;
}
static void array(const char *name, const uint8_t *data, size_t n) {
    printf("static const uint8_t %s[%zu] = {", name, n);
    for (size_t i = 0; i < n; i++) {
        const char *sep = i == 0 ? "\n    " : i % 12 == 0 ? ",\n    " : ", ";
        printf("%s0x%02x", sep, data[i]);
    }
    puts("\n};");
}
int main(void) {
    uint8_t pk[P(CRYPTO_PUBLICKEYBYTES)], sk[P(CRYPTO_SECRETKEYBYTES)];
    if (P(crypto_sign_keypair)(pk, sk) != 0) return 1;
    puts("#ifndef GENERATED_STATIC_KEYS_H");
    puts("#define GENERATED_STATIC_KEYS_H");
    puts("#include <stdint.h>");
    puts("/* Deterministic test-only PQClean key. */");
    array("STATIC_PK", pk, sizeof pk); array("STATIC_SK", sk, sizeof sk);
    puts("#endif");
    return 0;
}
'''


def generate(root: Path, pqclean: Path, name: str) -> None:
    directory, prefix, output = SCHEMES[name]
    impl = pqclean / "crypto_sign" / directory / "clean"
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        source = td_path / "gen.c"
        binary = td_path / "gen"
        source.write_text(SOURCE)
        command = [
            "cc", "-O2", f"-DPREFIX={prefix}", f"-I{impl}",
            f"-I{pqclean / 'common'}", str(source),
            *map(str, sorted(impl.glob("*.c"))),
            str(pqclean / "common" / "fips202.c"),
            str(pqclean / "common" / "sha2.c"),
            "-lm", "-o", str(binary),
        ]
        subprocess.run(command, check=True)
        data = subprocess.check_output([str(binary)])
    destination = root / "keys" / output
    destination.write_bytes(data)
    print(f"wrote {destination}")


def main() -> None:
    parser = argparse.ArgumentParser()
    # nargs="*" + choices rejects the empty default on recent argparse;
    # treat "no arguments" as "generate every scheme".
    parser.add_argument("schemes", nargs="*", choices=sorted(SCHEMES) + [[]],
                        default=[])
    args = parser.parse_args()
    if not args.schemes:
        args.schemes = sorted(SCHEMES)
    root = Path(__file__).resolve().parent.parent
    pqclean = Path(
        __import__("os").environ.get("PQCLEAN_ROOT", root / "third_party/PQClean")
    )
    selected = args.schemes or list(SCHEMES)
    for name in selected:
        generate(root, pqclean, name)


if __name__ == "__main__":
    main()
