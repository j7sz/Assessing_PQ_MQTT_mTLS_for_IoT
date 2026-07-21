#pragma once

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WC_HAWK512_OID_STR      "1.3.6.1.4.1.99999.1.1"
#define WC_HAWK512_TLS_SIGALG   0xFE09u
#define WC_HAWK512_PRIV_SIZE    184u
#define WC_HAWK512_PUB_SIZE     1024u
#define WC_HAWK512_SIG_SIZE     555u
#define WC_HAWK512_KEYPAIR_SIZE (WC_HAWK512_PRIV_SIZE + WC_HAWK512_PUB_SIZE)

typedef struct wc_Hawk512Key {
    byte priv[WC_HAWK512_PRIV_SIZE];
    byte pub[WC_HAWK512_PUB_SIZE];
    byte hasPriv;
    byte hasPub;
} wc_Hawk512Key;

int wc_Hawk512_Init(wc_Hawk512Key* key);
void wc_Hawk512_Free(wc_Hawk512Key* key);
int wc_Hawk512_ImportPublic(const byte* pub, word32 pubLen,
    wc_Hawk512Key* key);
int wc_Hawk512_ImportPrivateKey(const byte* priv, word32 privLen,
    const byte* pub, word32 pubLen, wc_Hawk512Key* key);
int wc_Hawk512_ImportPrivateKeyPair(const byte* keyPair, word32 keyPairLen,
    wc_Hawk512Key* key);
int wc_Hawk512_Sign(const byte* msg, word32 msgLen, byte* sig,
    word32* sigLen, wc_Hawk512Key* key, WC_RNG* rng);
int wc_Hawk512_Verify(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* result, wc_Hawk512Key* key);

#ifdef __cplusplus
}
#endif
