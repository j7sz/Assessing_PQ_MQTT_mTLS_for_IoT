#include "hawk512_tls.h"

#include <string.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include "hawk.h"

#define WC_HAWK512_LOGN 9u

static void wc_hawk512_rng(void* ctx, void* dst, size_t len)
{
    WC_RNG* rng = (WC_RNG*)ctx;

    if (rng == NULL || wc_RNG_GenerateBlock(rng, (byte*)dst, (word32)len) != 0) {
        memset(dst, 0, len);
    }
}

int wc_Hawk512_Init(wc_Hawk512Key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    memset(key, 0, sizeof(*key));
    return 0;
}

void wc_Hawk512_Free(wc_Hawk512Key* key)
{
    if (key != NULL) {
        wc_ForceZero(key, sizeof(*key));
    }
}

int wc_Hawk512_ImportPublic(const byte* pub, word32 pubLen,
    wc_Hawk512Key* key)
{
    if (key == NULL || pub == NULL) {
        return BAD_FUNC_ARG;
    }
    if (pubLen != WC_HAWK512_PUB_SIZE) {
        return BUFFER_E;
    }

    memcpy(key->pub, pub, WC_HAWK512_PUB_SIZE);
    key->hasPub = 1;
    return 0;
}

int wc_Hawk512_ImportPrivateKey(const byte* priv, word32 privLen,
    const byte* pub, word32 pubLen, wc_Hawk512Key* key)
{
    int ret;

    if (key == NULL || priv == NULL || pub == NULL) {
        return BAD_FUNC_ARG;
    }
    if (privLen != WC_HAWK512_PRIV_SIZE) {
        return BUFFER_E;
    }

    ret = wc_Hawk512_ImportPublic(pub, pubLen, key);
    if (ret != 0) {
        return ret;
    }

    memcpy(key->priv, priv, WC_HAWK512_PRIV_SIZE);
    key->hasPriv = 1;
    return 0;
}

int wc_Hawk512_ImportPrivateKeyPair(const byte* keyPair, word32 keyPairLen,
    wc_Hawk512Key* key)
{
    if (keyPair == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keyPairLen != WC_HAWK512_KEYPAIR_SIZE) {
        return BUFFER_E;
    }

    return wc_Hawk512_ImportPrivateKey(keyPair, WC_HAWK512_PRIV_SIZE,
        keyPair + WC_HAWK512_PRIV_SIZE, WC_HAWK512_PUB_SIZE, key);
}

int wc_Hawk512_Sign(const byte* msg, word32 msgLen, byte* sig,
    word32* sigLen, wc_Hawk512Key* key, WC_RNG* rng)
{
    shake_context sc;
    void* tmp;
    size_t tmpLen = HAWK_TMPSIZE_SIGN(WC_HAWK512_LOGN);
    int ok;

    if (sigLen == NULL || key == NULL || msg == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sig == NULL) {
        *sigLen = WC_HAWK512_SIG_SIZE;
        return 0;
    }
    if (*sigLen < WC_HAWK512_SIG_SIZE) {
        *sigLen = WC_HAWK512_SIG_SIZE;
        return BUFFER_E;
    }
    if (!key->hasPriv || rng == NULL) {
        return BAD_FUNC_ARG;
    }

    tmp = XMALLOC(tmpLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL) {
        return MEMORY_E;
    }

    hawk_sign_start(&sc);
    shake_inject(&sc, msg, msgLen);
    shake_flip(&sc);

    ok = hawk_sign_finish(WC_HAWK512_LOGN, wc_hawk512_rng, rng, sig, &sc,
        key->priv, tmp, tmpLen);
    XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (!ok) {
        return RNG_FAILURE_E;
    }

    *sigLen = WC_HAWK512_SIG_SIZE;
    return 0;
}

int wc_Hawk512_Verify(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* result, wc_Hawk512Key* key)
{
    shake_context sc;
    void* tmp;
    size_t tmpLen = HAWK_TMPSIZE_VERIFY_FAST(WC_HAWK512_LOGN);
    int ok;

    if (result == NULL || key == NULL || sig == NULL || msg == NULL) {
        return BAD_FUNC_ARG;
    }

    *result = 0;
    if (!key->hasPub || sigLen != WC_HAWK512_SIG_SIZE) {
        return BAD_FUNC_ARG;
    }

    tmp = XMALLOC(tmpLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL) {
        return MEMORY_E;
    }

    hawk_verify_start(&sc);
    shake_inject(&sc, msg, msgLen);
    shake_flip(&sc);

    ok = hawk_verify_finish(WC_HAWK512_LOGN, sig, sigLen, &sc,
        key->pub, WC_HAWK512_PUB_SIZE, tmp, tmpLen);
    XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    *result = ok ? 1 : 0;
    return 0;
}
