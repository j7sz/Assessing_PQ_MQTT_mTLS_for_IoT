#include <stdint.h>
#include <stdio.h>

#include "hawk.h"

#ifndef LOGN
#define LOGN 9
#endif
#ifndef KEY_GUARD
#define KEY_GUARD "KEYS_HAWK512_H"
#endif

static shake_context rng;

static void array(const char *name, const uint8_t *data, size_t n) {
    printf("static const uint8_t %s[%zu] = {", name, n);
    for (size_t i = 0; i < n; i++) {
        const char *sep = (i == 0) ? "\n    " :
                          (i % 12 == 0) ? ",\n    " : ", ";
        printf("%s0x%02x", sep, data[i]);
    }
    puts("\n};");
}

int main(void) {
    uint8_t pk[HAWK_PUBKEY_SIZE(LOGN)];
    uint8_t sk[HAWK_PRIVKEY_SIZE(LOGN)];
    uint8_t tmp[HAWK_TMPSIZE_KEYGEN(LOGN)];
    static const uint8_t seed[] = "pico-sigbench-hawk-512-static-key";

    shake_init(&rng, 256);
    shake_inject(&rng, seed, sizeof seed - 1);
    shake_flip(&rng);
    if (!hawk_keygen(LOGN, sk, pk, (hawk_rng)&shake_extract, &rng,
                     tmp, sizeof tmp))
        return 1;

    printf("#ifndef %s\n#define %s\n", KEY_GUARD, KEY_GUARD);
    puts("#include <stdint.h>");
    puts("/* Deterministic test-only HAWK key generated on the host. */");
    array("STATIC_PK", pk, sizeof(pk));
    array("STATIC_SK", sk, sizeof(sk));
    puts("#endif");
    return 0;
}
