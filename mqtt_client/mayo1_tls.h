#pragma once

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WC_MAYO1_OID_STR       "1.3.9999.8.1.3"
#define WC_MAYO1_TLS_SIGALG    0xFF32u
#define WC_MAYO1_PRIV_SIZE     24u
#define WC_MAYO1_PUB_SIZE      1420u
#define WC_MAYO1_SIG_SIZE      454u
#define WC_MAYO1_KEYPAIR_SIZE  (WC_MAYO1_PRIV_SIZE + WC_MAYO1_PUB_SIZE)

typedef struct wc_Mayo1Key {
    byte priv[WC_MAYO1_PRIV_SIZE];
    byte pub[WC_MAYO1_PUB_SIZE];
    byte hasPriv;
    byte hasPub;
} wc_Mayo1Key;

int wc_Mayo1_Init(wc_Mayo1Key* key);
void wc_Mayo1_Free(wc_Mayo1Key* key);
int wc_Mayo1_ImportPublic(const byte* pub, word32 pubLen, wc_Mayo1Key* key);
int wc_Mayo1_ImportPrivateKey(const byte* priv, word32 privLen,
    const byte* pub, word32 pubLen, wc_Mayo1Key* key);
int wc_Mayo1_ImportPrivateKeyPair(const byte* keyPair, word32 keyPairLen,
    wc_Mayo1Key* key);
int wc_Mayo1_UnwrapPrivateKeyData(const byte* input, word32 inputLen,
    const byte** keyPair, word32* keyPairLen);
int wc_Mayo1_Sign(const byte* msg, word32 msgLen, byte* sig,
    word32* sigLen, wc_Mayo1Key* key, WC_RNG* rng);
int wc_Mayo1_Verify(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* result, wc_Mayo1Key* key);

#ifdef __cplusplus
}
#endif
