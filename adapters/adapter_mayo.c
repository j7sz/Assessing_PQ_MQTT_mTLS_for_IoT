#include "scheme.h"

#include MAYO_API_HEADER
#include STATIC_KEYS_HEADER

const char *scheme_name(void)           { return MAYO_DISPLAY_NAME; }
const char *scheme_implementation(void) { return "MAYO-M4 memory-reduced reference C"; }
const char *scheme_parameter_set(void)  { return MAYO_DISPLAY_NAME; }
const char *scheme_status(void)         { return "NIST additional signatures Round 3"; }
unsigned scheme_nist_level(void)        { return MAYO_NIST_LEVEL; }
int scheme_init(void)                   { return 0; }

size_t scheme_pk_bytes(void)      { return CRYPTO_PUBLICKEYBYTES; }
size_t scheme_sk_bytes(void)      { return CRYPTO_SECRETKEYBYTES; }
size_t scheme_sig_max_bytes(void) { return CRYPTO_BYTES; }
const uint8_t *scheme_pk(void)    { return STATIC_PK; }
const uint8_t *scheme_sk(void)    { return STATIC_SK; }

int scheme_do_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen) {
    return crypto_sign_signature(sig, siglen, m, mlen, STATIC_SK);
}

int scheme_do_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen) {
    return crypto_sign_verify(sig, siglen, m, mlen, STATIC_PK);
}
