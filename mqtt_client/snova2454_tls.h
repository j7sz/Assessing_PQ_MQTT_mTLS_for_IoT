#pragma once

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WC_SNOVA2454_OID_STR       "1.3.9999.10.1.1"
#define WC_SNOVA2454_TLS_SIGALG    0xFF3Au
#define WC_SNOVA2454_PRIV_SIZE     48u
#define WC_SNOVA2454_PUB_SIZE      1016u
#define WC_SNOVA2454_SIG_SIZE      248u
#define WC_SNOVA2454_KEYPAIR_SIZE  (WC_SNOVA2454_PRIV_SIZE + WC_SNOVA2454_PUB_SIZE)

typedef struct wc_Snova2454Key {
    byte priv[WC_SNOVA2454_PRIV_SIZE];
    byte pub[WC_SNOVA2454_PUB_SIZE];
    byte hasPriv;
    byte hasPub;
} wc_Snova2454Key;

int wc_Snova2454_Init(wc_Snova2454Key* key);
void wc_Snova2454_Free(wc_Snova2454Key* key);
int wc_Snova2454_ImportPublic(const byte* pub, word32 pubLen,
    wc_Snova2454Key* key);
int wc_Snova2454_ImportPrivateKey(const byte* priv, word32 privLen,
    const byte* pub, word32 pubLen, wc_Snova2454Key* key);
int wc_Snova2454_ImportPrivateKeyPair(const byte* keyPair, word32 keyPairLen,
    wc_Snova2454Key* key);
int wc_Snova2454_UnwrapPrivateKeyData(const byte* input, word32 inputLen,
    const byte** keyPair, word32* keyPairLen);
int wc_Snova2454_Sign(const byte* msg, word32 msgLen, byte* sig,
    word32* sigLen, wc_Snova2454Key* key, WC_RNG* rng);
int wc_Snova2454_Verify(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* result, wc_Snova2454Key* key);

#ifdef __cplusplus
}
#endif
