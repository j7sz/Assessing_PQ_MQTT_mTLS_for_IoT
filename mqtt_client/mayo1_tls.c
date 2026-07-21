#include "mayo1_tls.h"

#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include "../third_party/mayo-m4/crypto_sign/mayo1/ref/api.h"

int wc_Mayo1_Init(wc_Mayo1Key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    memset(key, 0, sizeof(*key));
    return 0;
}

void wc_Mayo1_Free(wc_Mayo1Key* key)
{
    if (key != NULL) {
        wc_ForceZero(key, sizeof(*key));
    }
}

int wc_Mayo1_ImportPublic(const byte* pub, word32 pubLen, wc_Mayo1Key* key)
{
    if (key == NULL || pub == NULL) {
        return BAD_FUNC_ARG;
    }
    if (pubLen != WC_MAYO1_PUB_SIZE) {
        return BUFFER_E;
    }

    memcpy(key->pub, pub, WC_MAYO1_PUB_SIZE);
    key->hasPub = 1;
    return 0;
}

int wc_Mayo1_ImportPrivateKey(const byte* priv, word32 privLen,
    const byte* pub, word32 pubLen, wc_Mayo1Key* key)
{
    int ret;

    if (key == NULL || priv == NULL || pub == NULL) {
        return BAD_FUNC_ARG;
    }
    if (privLen != WC_MAYO1_PRIV_SIZE) {
        return BUFFER_E;
    }

    ret = wc_Mayo1_ImportPublic(pub, pubLen, key);
    if (ret != 0) {
        return ret;
    }

    memcpy(key->priv, priv, WC_MAYO1_PRIV_SIZE);
    key->hasPriv = 1;
    return 0;
}

int wc_Mayo1_ImportPrivateKeyPair(const byte* keyPair, word32 keyPairLen,
    wc_Mayo1Key* key)
{
    if (keyPair == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keyPairLen != WC_MAYO1_KEYPAIR_SIZE) {
        return BUFFER_E;
    }

    return wc_Mayo1_ImportPrivateKey(keyPair, WC_MAYO1_PRIV_SIZE,
        keyPair + WC_MAYO1_PRIV_SIZE, WC_MAYO1_PUB_SIZE, key);
}

int wc_Mayo1_UnwrapPrivateKeyData(const byte* input, word32 inputLen,
    const byte** keyPair, word32* keyPairLen)
{
    word32 idx = 0;
    word32 len = 0;
    byte lenByte;
    byte lenBytes;

    if ((input == NULL) || (keyPair == NULL) || (keyPairLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (inputLen == WC_MAYO1_KEYPAIR_SIZE) {
        *keyPair = input;
        *keyPairLen = inputLen;
        return 0;
    }

    /* oqs-provider stores the raw MAYO sk||pk in an inner OCTET STRING. */
    if ((inputLen < 2u) || (input[idx++] != 0x04u)) {
        return ASN_PARSE_E;
    }

    lenByte = input[idx++];
    if ((lenByte & 0x80u) == 0u) {
        len = lenByte;
    }
    else {
        lenBytes = lenByte & 0x7fu;
        if ((lenBytes == 0u) || (lenBytes > 4u) ||
                ((idx + lenBytes) > inputLen)) {
            return ASN_PARSE_E;
        }
        while (lenBytes-- > 0u) {
            len = (len << 8) | input[idx++];
        }
    }

    if ((len != WC_MAYO1_KEYPAIR_SIZE) || ((idx + len) != inputLen)) {
        return ASN_PARSE_E;
    }

    *keyPair = input + idx;
    *keyPairLen = len;
    return 0;
}

int wc_Mayo1_Sign(const byte* msg, word32 msgLen, byte* sig,
    word32* sigLen, wc_Mayo1Key* key, WC_RNG* rng)
{
    size_t outLen = WC_MAYO1_SIG_SIZE;
    int ret;

    (void)rng;

    if (sigLen == NULL || key == NULL || msg == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sig == NULL) {
        *sigLen = WC_MAYO1_SIG_SIZE;
        return 0;
    }
    if (*sigLen < WC_MAYO1_SIG_SIZE) {
        *sigLen = WC_MAYO1_SIG_SIZE;
        return BUFFER_E;
    }
    if (!key->hasPriv) {
        return BAD_FUNC_ARG;
    }

    ret = crypto_sign_signature(sig, &outLen, msg, msgLen, key->priv);
    if (ret != 0) {
        return ret;
    }

    *sigLen = (word32)outLen;
    return 0;
}

int wc_Mayo1_Verify(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* result, wc_Mayo1Key* key)
{
    int ret;

    if (result == NULL || key == NULL || sig == NULL || msg == NULL) {
        return BAD_FUNC_ARG;
    }

    *result = 0;
    if (!key->hasPub || sigLen != WC_MAYO1_SIG_SIZE) {
        return BAD_FUNC_ARG;
    }

    ret = crypto_sign_verify(sig, sigLen, msg, msgLen, key->pub);
    *result = (ret == 0) ? 1 : 0;
    return 0;
}
