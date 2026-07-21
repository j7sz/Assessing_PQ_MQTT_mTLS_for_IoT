/* scheme.h - the generic benchmark main talks ONLY to this interface.
 *
 * Each signature scheme provides one adapter .c file implementing these
 * functions. All PQClean-version-specific details (namespaced symbol names,
 * the ML-DSA context-string argument, etc.) live inside the adapter, so the
 * harness stays scheme-agnostic and every scheme is cleanly separated.
 */
#ifndef SCHEME_H
#define SCHEME_H

#include <stdint.h>
#include <stddef.h>

const char *scheme_name(void);          /* human-readable scheme name        */
const char *scheme_implementation(void);/* source/version label              */
const char *scheme_parameter_set(void); /* exact parameter-set identifier    */
const char *scheme_status(void);        /* classical/FIPS/selected/candidate */
unsigned    scheme_nist_level(void);    /* 0 when not applicable             */

/* Decode/import the embedded key and initialize implementation state.
 * Called once before all measured operations. */
int scheme_init(void);

size_t scheme_pk_bytes(void);           /* public key length (bytes)         */
size_t scheme_sk_bytes(void);           /* secret key length (bytes)         */
size_t scheme_sig_max_bytes(void);      /* max signature length (bytes)      */

const uint8_t *scheme_pk(void);         /* pointer to embedded static PK     */
const uint8_t *scheme_sk(void);         /* pointer to embedded static SK     */

/* Sign message m (mlen bytes) using the embedded static SK.
 * Writes detached signature to sig and its length to *siglen. Returns 0 ok. */
int scheme_do_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen);

/* Verify detached signature against the embedded static PK. Returns 0 ok. */
int scheme_do_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen);

#endif /* SCHEME_H */
