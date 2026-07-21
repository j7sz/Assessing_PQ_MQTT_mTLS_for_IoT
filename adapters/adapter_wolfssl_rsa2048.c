#include "scheme.h"

#include <string.h>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/certs_test.h>

#ifndef RSA_DISPLAY_NAME
#define RSA_DISPLAY_NAME "RSA-2048 PKCS#1 v1.5 SHA-256"
#endif
#ifndef RSA_PARAMETER_SET
#define RSA_PARAMETER_SET "RSA-2048-SHA-256"
#endif
#ifndef RSA_KEY_BYTES
#define RSA_KEY_BYTES 256
#endif
#ifndef RSA_HASH_TYPE
#define RSA_HASH_TYPE WC_HASH_TYPE_SHA256
#endif
#ifndef RSA_MGF_TYPE
#define RSA_MGF_TYPE WC_MGF1SHA256
#endif
#ifndef RSA_KEY_DER
#define RSA_KEY_DER client_key_der_2048
#endif
#ifndef RSA_KEY_DER_SIZE
#define RSA_KEY_DER_SIZE sizeof_client_key_der_2048
#endif

static RsaKey key;
static WC_RNG rng;

const char *scheme_name(void)           { return RSA_DISPLAY_NAME; }
const char *scheme_implementation(void) { return "wolfSSL 5.9.1"; }
const char *scheme_parameter_set(void)  { return RSA_PARAMETER_SET; }
const char *scheme_status(void)         { return "classical"; }
unsigned scheme_nist_level(void)        { return 0; }

size_t scheme_pk_bytes(void)      { return RSA_KEY_BYTES; }
size_t scheme_sk_bytes(void)      { return RSA_KEY_BYTES; }
size_t scheme_sig_max_bytes(void) { return RSA_KEY_BYTES; }
const uint8_t *scheme_pk(void)    { return RSA_KEY_DER; }
const uint8_t *scheme_sk(void)    { return RSA_KEY_DER; }

int scheme_init(void) {
    word32 idx = 0;
    int ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0)
        ret = wc_RsaPrivateKeyDecode(RSA_KEY_DER, &idx, &key,
                                     RSA_KEY_DER_SIZE);
    if (ret == 0)
        ret = wc_InitRng(&rng);
    return ret;
}

int scheme_do_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen) {
    word32 out = (word32)scheme_sig_max_bytes();
#ifdef RSA_USE_PSS
    uint8_t digest[WC_MAX_DIGEST_SIZE];
    int digest_len = wc_HashGetDigestSize(RSA_HASH_TYPE);
    if (digest_len <= 0 || digest_len > (int)sizeof(digest))
        return BAD_FUNC_ARG;

    int ret = wc_Hash(RSA_HASH_TYPE, m, (word32)mlen, digest,
                      (word32)digest_len);
    if (ret == 0) {
        ret = wc_RsaPSS_Sign(digest, (word32)digest_len, sig, out,
                             RSA_HASH_TYPE, RSA_MGF_TYPE, &key, &rng);
    }
    if (ret > 0) {
        *siglen = (size_t)ret;
        return 0;
    }
    return ret;
#else
    int ret = wc_SignatureGenerate_ex(RSA_HASH_TYPE,
        WC_SIGNATURE_TYPE_RSA_W_ENC, m, (word32)mlen, sig, &out,
        &key, sizeof(key), &rng, 0);
    *siglen = out;
    return ret;
#endif
}

int scheme_do_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen) {
#ifdef RSA_USE_PSS
    uint8_t digest[WC_MAX_DIGEST_SIZE];
    uint8_t sig_copy[RSA_KEY_BYTES];
    byte *plain = NULL;
    int digest_len = wc_HashGetDigestSize(RSA_HASH_TYPE);
    if (digest_len <= 0 || digest_len > (int)sizeof(digest))
        return BAD_FUNC_ARG;
    if (siglen > sizeof(sig_copy))
        return BUFFER_E;

    int ret = wc_Hash(RSA_HASH_TYPE, m, (word32)mlen, digest,
                      (word32)digest_len);
    if (ret != 0)
        return ret;

    memcpy(sig_copy, sig, siglen);
    ret = wc_RsaPSS_VerifyInline(sig_copy, (word32)siglen, &plain,
                                 RSA_HASH_TYPE, RSA_MGF_TYPE, &key);
    if (ret <= 0)
        return ret;

    return wc_RsaPSS_CheckPadding(digest, (word32)digest_len, plain,
                                  (word32)ret, RSA_HASH_TYPE);
#else
    return wc_SignatureVerify(RSA_HASH_TYPE,
        WC_SIGNATURE_TYPE_RSA_W_ENC, m, (word32)mlen, sig, (word32)siglen,
        &key, sizeof(key));
#endif
}
