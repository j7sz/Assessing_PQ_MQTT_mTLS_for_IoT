#ifndef PICO_MQTT_WOLFSSL_USER_SETTINGS_H
#define PICO_MQTT_WOLFSSL_USER_SETTINGS_H

/*
 * wolfSSL TLS 1.3 + ML-DSA-44 configuration for the Pico 2W MQTT client.
 * This is separate from the benchmark's crypto-only wolfssl target.
 */

/* Bare-metal, single-threaded */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_RPIPICO

/* Custom I/O — we provide wolfSSL_SetIORecv/Send callbacks over lwIP raw TCP */
#define WOLFSSL_USER_IO

/* Pico RNG (RP2040 PRNG or RP2350 hardware TRNG) */
#define WC_NO_HASHDRBG
#define CUSTOM_RAND_GENERATE_BLOCK wc_pico_rng_gen_block
#define WC_RESEED_INTERVAL 1000000

/* ------------------------------------------------------------------ */
/* TLS 1.3 only                                                         */
/* ------------------------------------------------------------------ */
#define WOLFSSL_TLS13
#define NO_OLD_TLS
#define HAVE_HKDF                       /* required by tls13.c         */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_SERVER_RENEGOTIATION_INFO
/* HAVE_SESSION_TICKET omitted: session resumption is not needed for this
 * MQTT client. USER_TICKS uses the Pico transport timer hooks.        */
#define USER_TICKS
#define WOLFSSL_32BIT_MILLI_TIME

/* ------------------------------------------------------------------ */
/* Per-scheme PQ signature feature gating                              */
/* ------------------------------------------------------------------ */
/* IMPORTANT — flash/SRAM isolation:
 * These HAVE_DILITHIUM / HAVE_FALCON / WOLFSSL_HAWK512 / WOLFSSL_MAYO1
 * macros are what pull wolfCrypt's dilithium.c / falcon.c TLS+X.509 glue
 * (and the matching third-party algorithm sources added in
 * mqtt_client/CMakeLists.txt) into the build. Previously they were all
 * defined unconditionally, so every mqtt_client_* target — even
 * mqtt_client_rsa2048 — linked in ML-DSA, Falcon, HAWK and MAYO code it
 * never calls. Each add_mqtt_wolfssl_tls() library variant now defines
 * exactly one MQTT_LIB_SCHEME_* macro (see CMakeLists.txt) and only that
 * scheme's block below is enabled, so an isolated library only pays for
 * its own signature algorithm.
 */
#if defined(MQTT_LIB_SCHEME_MLDSA44)
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_WC_DILITHIUM        /* use wolfCrypt's built-in impl, not liboqs */
#define HAVE_DILITHIUM              /* enable ML-DSA/Dilithium X.509/TLS glue    */
#define WOLFSSL_ML_DSA              /* enable FIPS 204 OIDs / naming             */
#define HAVE_DILITHIUM_LEVEL2       /* Dilithium Level 2 = ML-DSA-44            */
#endif /* MQTT_LIB_SCHEME_MLDSA44 */

#if defined(MQTT_LIB_SCHEME_FALCON512)
/* Falcon-512 TLS/X.509 plumbing backed by PQClean on Pico. */
#define HAVE_PQC
#define HAVE_FALCON
#define WOLFSSL_FALCON512_PQCLEAN
#define FALCON_LEVEL1_KEY_SIZE      1281
#define FALCON_LEVEL1_SIG_SIZE       752
#define FALCON_LEVEL1_PUB_KEY_SIZE   897
#define FALCON_LEVEL1_PRV_KEY_SIZE \
    (FALCON_LEVEL1_PUB_KEY_SIZE + FALCON_LEVEL1_KEY_SIZE)
/* wolfSSL's generic Falcon decoder still references Level-5 constants.
 * They describe supported wire formats only; the PQClean backend below is
 * restricted to Falcon-512 and falcon_key is sized to Level 1. */
#define FALCON_LEVEL5_KEY_SIZE      2305
#define FALCON_LEVEL5_SIG_SIZE      1462
#define FALCON_LEVEL5_PUB_KEY_SIZE  1793
#define FALCON_LEVEL5_PRV_KEY_SIZE \
    (FALCON_LEVEL5_PUB_KEY_SIZE + FALCON_LEVEL5_KEY_SIZE)
#endif /* MQTT_LIB_SCHEME_FALCON512 */

#if defined(MQTT_LIB_SCHEME_HAWK512)
/* Experimental local HAWK-512 TLS/X.509 plumbing. */
#define WOLFSSL_HAWK512
#endif /* MQTT_LIB_SCHEME_HAWK512 */

#if defined(MQTT_LIB_SCHEME_MAYO1)
/* Experimental local MAYO-1 TLS/X.509 plumbing. */
#define WOLFSSL_MAYO1
#define MAYO1_PRIVATE_KEY_SIZE      24
#define MAYO1_PUBLIC_KEY_SIZE       1420
#define MAYO1_SIGNATURE_SIZE        454
#define MAYO1_KEYPAIR_SIZE \
    (MAYO1_PRIVATE_KEY_SIZE + MAYO1_PUBLIC_KEY_SIZE)
#endif /* MQTT_LIB_SCHEME_MAYO1 */

/* ------------------------------------------------------------------ */
/* Key exchange: X25519MLKEM768 hybrid                                 */
/* ------------------------------------------------------------------ */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_NO_ML_KEM_512
#define WOLFSSL_NO_ML_KEM_1024
#define WOLFSSL_PQC_HYBRIDS

/* X25519 is the classical half of the X25519MLKEM768 hybrid group.
 * HAVE_ECC is required because wolfSSL's TLS code has ECC-guarded helpers
 * even when the negotiated classical group is X25519. */
#define HAVE_CURVE25519
#define HAVE_CURVE25519_SHARED_SECRET
#ifndef HAVE_ECC
#define HAVE_ECC
#endif
#define NO_ECC384   /* P-384 too large for Pico SP_INT_BITS=256 */
#define NO_ECC521   /* P-521 too large for Pico SP_INT_BITS=256 */

/* ------------------------------------------------------------------ */
/* Symmetric — AES-128-GCM and ChaCha20-Poly1305 for TLS 1.3          */
/* ------------------------------------------------------------------ */
#define HAVE_AESGCM
#define WOLFSSL_AES_128
#define WOLFSSL_AES_256
#define HAVE_CHACHA
#define HAVE_POLY1305

/* ------------------------------------------------------------------ */
/* Hash                                                                 */
/* ------------------------------------------------------------------ */
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* ------------------------------------------------------------------ */
/* ASN.1 / X.509 — buffer-based, no filesystem                         */
/* ------------------------------------------------------------------ */
/* ASN parsing enabled by default when not WOLFCRYPT_ONLY.
 * Dilithium X.509 OIDs are recognised via WOLFSSL_ML_DSA above.
 * Certificate date checks remain enabled; main.c syncs UTC with SNTP before TLS.
 */
#define WOLFSSL_ALLOW_ENCODING_CA_FALSE

/* ------------------------------------------------------------------ */
/* Disabled features — reduce flash/RAM                                */
/* ------------------------------------------------------------------ */
/* RSA-PSS-2048 MQTT mTLS target needs RSA X.509 parsing and client auth.
 * Every other scheme (ECDSA and every PQ scheme) has no use for
 * RSA at all, so RSA is now opt-in per library via MQTT_LIB_NEEDS_RSA
 * (set only for wolfssl_tls_rsa2048 in mqtt_client/CMakeLists.txt) instead
 * of being compiled into every target unconditionally. */
#ifdef MQTT_LIB_NEEDS_RSA
#undef NO_RSA
#define WOLFSSL_MIN_RSA_BITS 2048
#define WC_RSA_BLINDING
#define WC_RSA_PSS
#else
#define NO_RSA
#endif
#define NO_DSA
#define NO_DH
#define NO_DES3
#define NO_RC4
#define NO_MD5
#define NO_SHA       /* SHA-1 */
#define NO_PWDBASED
#define NO_WOLFSSL_SERVER
#define WOLFSSL_NO_SOCK  /* no BSD socket layer; we use WOLFSSL_USER_IO */

/* SP math — fast scalar operations on Cortex-M33.
 * Most MQTT schemes only need P-256/X25519-sized integers. RSA-2048 builds
 * override MQTT_TLS_SP_INT_BITS from CMake for X.509 key checks.
 */
#define WOLFSSL_SP_MATH_ALL
#ifndef MQTT_TLS_SP_INT_BITS
#define MQTT_TLS_SP_INT_BITS 256
#endif
#define SP_INT_BITS MQTT_TLS_SP_INT_BITS

/* Classical RSA/ECDSA MQTT targets can opt into wolfSSL's SP RSA/ECC
 * fast paths without changing the PQ MQTT TLS library. */
#ifdef MQTT_TLS_CLASSICAL_SP_OPT
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define ECC_USER_CURVES
#undef NO_ECC256
#define ECC_TIMING_RESISTANT
#define WOLFSSL_SP_CACHE_RESISTANT
#endif

/* Optional: uncomment to print wolfSSL errors via printf on USB-CDC */
/* #define DEBUG_WOLFSSL */

#endif /* PICO_MQTT_WOLFSSL_USER_SETTINGS_H */
