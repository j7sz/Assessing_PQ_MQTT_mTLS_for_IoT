#ifndef PICO_SIGBENCH_WOLFSSL_USER_SETTINGS_H
#define PICO_SIGBENCH_WOLFSSL_USER_SETTINGS_H

/* wolfCrypt-only, bare-metal Pico signature benchmark configuration. */
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define WOLFSSL_RPIPICO
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG 8

/* Pico SDK RNG: optimized PRNG on RP2040, hardware TRNG on RP2350. */
#define WC_NO_HASHDRBG
#define CUSTOM_RAND_GENERATE_BLOCK wc_pico_rng_gen_block
#define WC_RESEED_INTERVAL 1000000

/* Signature primitives used by this benchmark. */
#undef NO_RSA
#define WC_RSA_BLINDING
#define WC_RSA_PSS
#define WOLFSSL_SP_CACHE_RESISTANT
#define HAVE_ECC
#define HAVE_ECC_SIGN
#define HAVE_ECC_VERIFY
#define ECC_USER_CURVES
#undef NO_ECC256
#define NO_ECC192
#define NO_ECC224
#define HAVE_ECC384
#define HAVE_ECC521
#define WOLFSSL_SP_384
#define WOLFSSL_SP_521
#define ECC_TIMING_RESISTANT
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_4096

/* Hashes paired with the enabled ECDSA parameter sets. In WOLFCRYPT_ONLY
 * mode SHA-384/SHA-512 must be opted in explicitly. */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_NO_SHAKE128
#define HAVE_ED25519
#define ED25519_SMALL
#define HAVE_ED448
#define ED448_SMALL

/* ASN.1 DigestInfo encoding and algorithms excluded from this benchmark. */
#define NO_MD5
#define NO_SHA
#define NO_DSA
#define NO_DH
#define NO_AES
#define NO_DES3
#define NO_RC4
#define NO_PWDBASED

/* wolfSSL's repository-provided static benchmark keys. */
#define USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_3072
#define USE_CERT_BUFFERS_4096
#define USE_CERT_BUFFERS_256

#endif
