#include "scheme.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/certs_test.h>

static ecc_key key;
static WC_RNG rng;

const char *scheme_name(void)           { return "ECDSA P-256 SHA-256"; }
const char *scheme_implementation(void) { return "wolfSSL 5.9.1"; }
const char *scheme_parameter_set(void)  { return "ECDSA-P256-SHA-256"; }
const char *scheme_status(void)         { return "classical"; }
unsigned scheme_nist_level(void)        { return 0; }

size_t scheme_pk_bytes(void)      { return 64; }
size_t scheme_sk_bytes(void)      { return 32; }
size_t scheme_sig_max_bytes(void) { return 80; }
const uint8_t *scheme_pk(void)    { return ecc_key_der_256; }
const uint8_t *scheme_sk(void)    { return ecc_key_der_256; }

int scheme_init(void) {
    word32 idx = 0;
    int ret = wc_ecc_init(&key);
    if (ret == 0)
        ret = wc_EccPrivateKeyDecode(ecc_key_der_256, &idx, &key,
                                     sizeof_ecc_key_der_256);
    if (ret == 0)
        ret = wc_InitRng(&rng);
    return ret;
}

int scheme_do_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen) {
    word32 out = (word32)scheme_sig_max_bytes();
    int ret = wc_SignatureGenerate_ex(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC, m, (word32)mlen, sig, &out,
        &key, sizeof(key), &rng, 0);
    *siglen = out;
    return ret;
}

int scheme_do_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen) {
    return wc_SignatureVerify(WC_HASH_TYPE_SHA256,
        WC_SIGNATURE_TYPE_ECC, m, (word32)mlen, sig, (word32)siglen,
        &key, sizeof(key));
}
