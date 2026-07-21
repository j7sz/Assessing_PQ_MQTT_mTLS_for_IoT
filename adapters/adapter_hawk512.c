#include "scheme.h"

#include <string.h>
#include "pico/rand.h"
#include "hawk.h"
#include HAWK_KEYS_HEADER

#ifndef HAWK_LOGN
#define HAWK_LOGN 9
#endif

static uint8_t tmp[HAWK_TMPSIZE_VERIFY(HAWK_LOGN)]
    __attribute__((aligned(8)));

static void pico_rng(void *ctx, void *dst, size_t len) {
    (void)ctx;
    uint8_t *out = dst;
    while (len >= 8) {
        uint64_t value = get_rand_64();
        memcpy(out, &value, 8);
        out += 8;
        len -= 8;
    }
    if (len) {
        uint64_t value = get_rand_64();
        memcpy(out, &value, len);
    }
}

const char *scheme_name(void)           { return HAWK_DISPLAY_NAME; }
const char *scheme_implementation(void) { return "HAWK reference portable C"; }
const char *scheme_parameter_set(void)  { return HAWK_DISPLAY_NAME; }
const char *scheme_status(void)         { return "NIST additional signatures Round 3"; }
unsigned scheme_nist_level(void)        { return HAWK_NIST_LEVEL; }
int scheme_init(void)                   { return 0; }

size_t scheme_pk_bytes(void)      { return sizeof(STATIC_PK); }
size_t scheme_sk_bytes(void)      { return sizeof(STATIC_SK); }
size_t scheme_sig_max_bytes(void) { return HAWK_SIG_SIZE(HAWK_LOGN); }
const uint8_t *scheme_pk(void)    { return STATIC_PK; }
const uint8_t *scheme_sk(void)    { return STATIC_SK; }

int scheme_do_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen) {
    shake_context sc;
    hawk_sign_start(&sc);
    shake_inject(&sc, m, mlen);
    int ok = hawk_sign_finish(HAWK_LOGN, pico_rng, NULL, sig, &sc,
        STATIC_SK, tmp, HAWK_TMPSIZE_SIGN(HAWK_LOGN));
    *siglen = HAWK_SIG_SIZE(HAWK_LOGN);
    return ok ? 0 : -1;
}

int scheme_do_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen) {
    shake_context sc;
    hawk_verify_start(&sc);
    shake_inject(&sc, m, mlen);
    return hawk_verify_finish(HAWK_LOGN, sig, siglen, &sc,
        STATIC_PK, sizeof(STATIC_PK), tmp, sizeof(tmp)) ? 0 : -1;
}
