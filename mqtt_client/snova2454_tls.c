#include "snova2454_tls.h"

#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include "../third_party/snova/src/api.h"

int wc_Snova2454_Init(wc_Snova2454Key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    memset(key, 0, sizeof(*key));
    return 0;
}

void wc_Snova2454_Free(wc_Snova2454Key* key)
{
    if (key != NULL) {
        wc_ForceZero(key, sizeof(*key));
    }
}

int wc_Snova2454_ImportPublic(const byte* pub, word32 pubLen,
    wc_Snova2454Key* key)
{
    if (key == NULL || pub == NULL) {
        return BAD_FUNC_ARG;
    }
    if (pubLen != WC_SNOVA2454_PUB_SIZE) {
        return BUFFER_E;
    }

    memcpy(key->pub, pub, WC_SNOVA2454_PUB_SIZE);
    key->hasPub = 1;
    return 0;
}

int wc_Snova2454_ImportPrivateKey(const byte* priv, word32 privLen,
    const byte* pub, word32 pubLen, wc_Snova2454Key* key)
{
    int ret;

    if (key == NULL || priv == NULL || pub == NULL) {
        return BAD_FUNC_ARG;
    }
    if (privLen != WC_SNOVA2454_PRIV_SIZE) {
        return BUFFER_E;
    }

    ret = wc_Snova2454_ImportPublic(pub, pubLen, key);
    if (ret != 0) {
        return ret;
    }

    memcpy(key->priv, priv, WC_SNOVA2454_PRIV_SIZE);
    key->hasPriv = 1;
    return 0;
}

int wc_Snova2454_ImportPrivateKeyPair(const byte* keyPair, word32 keyPairLen,
    wc_Snova2454Key* key)
{
    if (keyPair == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keyPairLen != WC_SNOVA2454_KEYPAIR_SIZE) {
        return BUFFER_E;
    }

    return wc_Snova2454_ImportPrivateKey(keyPair, WC_SNOVA2454_PRIV_SIZE,
        keyPair + WC_SNOVA2454_PRIV_SIZE, WC_SNOVA2454_PUB_SIZE, key);
}

int wc_Snova2454_UnwrapPrivateKeyData(const byte* input, word32 inputLen,
    const byte** keyPair, word32* keyPairLen)
{
    word32 idx = 0;
    word32 len = 0;
    byte lenByte;
    byte lenBytes;

    if ((input == NULL) || (keyPair == NULL) || (keyPairLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (inputLen == WC_SNOVA2454_KEYPAIR_SIZE) {
        *keyPair = input;
        *keyPairLen = inputLen;
        return 0;
    }

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

    if ((len != WC_SNOVA2454_KEYPAIR_SIZE) || ((idx + len) != inputLen)) {
        return ASN_PARSE_E;
    }

    *keyPair = input + idx;
    *keyPairLen = len;
    return 0;
}

int wc_Snova2454_Sign(const byte* msg, word32 msgLen, byte* sig,
    word32* sigLen, wc_Snova2454Key* key, WC_RNG* rng)
{
    byte* sm = NULL;
    unsigned long long smLen = 0;
    int ret;

    (void)rng;

    if (sigLen == NULL || key == NULL || msg == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sig == NULL) {
        *sigLen = WC_SNOVA2454_SIG_SIZE;
        return 0;
    }
    if (*sigLen < WC_SNOVA2454_SIG_SIZE) {
        *sigLen = WC_SNOVA2454_SIG_SIZE;
        return BUFFER_E;
    }
    if (!key->hasPriv) {
        return BAD_FUNC_ARG;
    }

    sm = (byte*)XMALLOC(WC_SNOVA2454_SIG_SIZE + msgLen, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (sm == NULL) {
        return MEMORY_E;
    }

    ret = crypto_sign(sm, &smLen, msg, msgLen, key->priv);
    if ((ret == 0) && (smLen >= WC_SNOVA2454_SIG_SIZE)) {
        memcpy(sig, sm, WC_SNOVA2454_SIG_SIZE);
        *sigLen = WC_SNOVA2454_SIG_SIZE;
    }

    XFREE(sm, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

int wc_Snova2454_Verify(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* result, wc_Snova2454Key* key)
{
    byte* sm = NULL;
    byte* out = NULL;
    unsigned long long outLen = 0;
    int ret;

    if (result == NULL || key == NULL || sig == NULL || msg == NULL) {
        return BAD_FUNC_ARG;
    }

    *result = 0;
    if (!key->hasPub || sigLen != WC_SNOVA2454_SIG_SIZE) {
        return BAD_FUNC_ARG;
    }

    sm = (byte*)XMALLOC(sigLen + msgLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    out = (byte*)XMALLOC(msgLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sm == NULL || out == NULL) {
        XFREE(sm, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    memcpy(sm, sig, sigLen);
    memcpy(sm + sigLen, msg, msgLen);
    ret = crypto_sign_open(out, &outLen, sm, sigLen + msgLen, key->pub);
    *result = (ret == 0 && outLen == msgLen &&
        memcmp(out, msg, msgLen) == 0) ? 1 : 0;

    XFREE(sm, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}
