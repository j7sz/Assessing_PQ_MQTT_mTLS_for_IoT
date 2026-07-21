#include <string.h>

#include "scheme.h"
#include "api.h"
#include STATIC_KEYS_HEADER

const char *scheme_name(void)           { return SNOVA_DISPLAY_NAME; }
#ifndef SNOVA_IMPL_NAME
#define SNOVA_IMPL_NAME "SNOVA 2.3 portable reference C (SHAKE)"
#endif
const char *scheme_implementation(void) { return SNOVA_IMPL_NAME; }
const char *scheme_parameter_set(void)  { return CRYPTO_ALGNAME; }
const char *scheme_status(void)         { return "NIST additional signatures Round 3"; }
unsigned scheme_nist_level(void)        { return 1; }
int scheme_init(void)                   { return 0; }

size_t scheme_pk_bytes(void)      { return CRYPTO_PUBLICKEYBYTES; }
size_t scheme_sk_bytes(void)      { return CRYPTO_SECRETKEYBYTES; }
size_t scheme_sig_max_bytes(void) { return CRYPTO_BYTES; }
const uint8_t *scheme_pk(void)    { return STATIC_PK; }
const uint8_t *scheme_sk(void)    { return STATIC_SK; }

int scheme_do_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen) {
    uint8_t signed_message[CRYPTO_BYTES + MSG_LEN];
    unsigned long long signed_len = 0;
    if (mlen > MSG_LEN) return -1;
    int rc = crypto_sign(signed_message, &signed_len, m, mlen, STATIC_SK);
    if (rc != 0 || signed_len != CRYPTO_BYTES + mlen) return rc ? rc : -1;
    memcpy(sig, signed_message, CRYPTO_BYTES);
    *siglen = CRYPTO_BYTES;
    return 0;
}

int scheme_do_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen) {
    uint8_t signed_message[CRYPTO_BYTES + MSG_LEN];
    uint8_t recovered[MSG_LEN];
    unsigned long long recovered_len = 0;
    if (siglen != CRYPTO_BYTES || mlen > MSG_LEN) return -1;
    memcpy(signed_message, sig, siglen);
    memcpy(signed_message + siglen, m, mlen);
    int rc = crypto_sign_open(recovered, &recovered_len, signed_message,
                              siglen + mlen, STATIC_PK);
    if (rc != 0 || recovered_len != mlen) return rc ? rc : -1;
    return memcmp(recovered, m, mlen) == 0 ? 0 : -1;
}
