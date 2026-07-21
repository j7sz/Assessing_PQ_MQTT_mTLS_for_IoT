#include "scheme.h"
#ifndef SCHEME_API_HEADER
#define SCHEME_API_HEADER "api.h"
#endif
#include SCHEME_API_HEADER
#include STATIC_KEYS_HEADER

#define SB_JOIN_INNER(a, b) a##b
#define SB_JOIN(a, b) SB_JOIN_INNER(a, b)
#define P(symbol) SB_JOIN(SCHEME_PREFIX, symbol)

const char *scheme_name(void)           { return SCHEME_DISPLAY_NAME; }
const char *scheme_implementation(void) { return "PQClean clean"; }
const char *scheme_parameter_set(void)  { return SCHEME_PARAMETER_SET; }
const char *scheme_status(void)         { return SCHEME_STATUS; }
unsigned scheme_nist_level(void)        { return SCHEME_NIST_LEVEL; }
int scheme_init(void)                   { return 0; }

size_t scheme_pk_bytes(void)      { return P(CRYPTO_PUBLICKEYBYTES); }
size_t scheme_sk_bytes(void)      { return P(CRYPTO_SECRETKEYBYTES); }
size_t scheme_sig_max_bytes(void) { return P(CRYPTO_BYTES); }
const uint8_t *scheme_pk(void)    { return STATIC_PK; }
const uint8_t *scheme_sk(void)    { return STATIC_SK; }

int scheme_do_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen) {
#ifdef SCHEME_CONTEXT_API
    return P(crypto_sign_signature_ctx)(sig, siglen, m, mlen, NULL, 0, STATIC_SK);
#else
    return P(crypto_sign_signature)(sig, siglen, m, mlen, STATIC_SK);
#endif
}

int scheme_do_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen) {
#ifdef SCHEME_CONTEXT_API
    return P(crypto_sign_verify_ctx)(sig, siglen, m, mlen, NULL, 0, STATIC_PK);
#else
    return P(crypto_sign_verify)(sig, siglen, m, mlen, STATIC_PK);
#endif
}
