#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "hawk.h"
#include "sha3.h"

#define HAWK_LOGN 9
#define HAWK_PRIV_LEN HAWK_PRIVKEY_SIZE(HAWK_LOGN)
#define HAWK_PUB_LEN  HAWK_PUBKEY_SIZE(HAWK_LOGN)
#define HAWK_SIG_LEN  HAWK_SIG_SIZE(HAWK_LOGN)
#define HAWK_KEYPAIR_LEN (HAWK_PRIV_LEN + HAWK_PUB_LEN)

#define BUF_CAP 32768

typedef struct {
    uint8_t b[BUF_CAP];
    size_t len;
} derbuf;

typedef struct {
    uint8_t priv[HAWK_PRIV_LEN];
    uint8_t pub[HAWK_PUB_LEN];
} hawk_keypair;

static const uint8_t OID_HAWK[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01, 0x01
};
static const uint8_t OID_CN[] = { 0x55, 0x04, 0x03 };
static const uint8_t OID_BASIC_CONSTRAINTS[] = { 0x55, 0x1d, 0x13 };
static const uint8_t OID_KEY_USAGE[] = { 0x55, 0x1d, 0x0f };
static const uint8_t OID_EXT_KEY_USAGE[] = { 0x55, 0x1d, 0x25 };
static const uint8_t OID_SUBJECT_ALT_NAME[] = { 0x55, 0x1d, 0x11 };
static const uint8_t OID_SERVER_AUTH[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01
};
static const uint8_t OID_CLIENT_AUTH[] = {
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02
};

static void die(const char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(1);
}

static void rng_urandom(void *ctx, void *dst, size_t len)
{
    (void)ctx;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) die("open /dev/urandom");
    if (fread(dst, 1, len, f) != len) die("read /dev/urandom");
    fclose(f);
}

static void put(derbuf *d, const void *src, size_t n)
{
    if (d->len + n > sizeof(d->b)) die("DER buffer overflow");
    memcpy(d->b + d->len, src, n);
    d->len += n;
}

static void put_u8(derbuf *d, uint8_t v)
{
    put(d, &v, 1);
}

static size_t enc_len(uint8_t out[4], size_t n)
{
    if (n < 0x80) {
        out[0] = (uint8_t)n;
        return 1;
    }
    if (n < 0x100) {
        out[0] = 0x81;
        out[1] = (uint8_t)n;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (uint8_t)(n >> 8);
    out[2] = (uint8_t)n;
    return 3;
}

static void tlv(derbuf *out, uint8_t tag, const uint8_t *val, size_t n)
{
    uint8_t lb[4];
    size_t ln = enc_len(lb, n);
    put_u8(out, tag);
    put(out, lb, ln);
    put(out, val, n);
}

static void seq(derbuf *out, const derbuf *in)
{
    tlv(out, 0x30, in->b, in->len);
}

static void set(derbuf *out, const derbuf *in)
{
    tlv(out, 0x31, in->b, in->len);
}

static void oid(derbuf *out, const uint8_t *val, size_t n)
{
    tlv(out, 0x06, val, n);
}

static void nullv(derbuf *out)
{
    uint8_t v[] = { 0x05, 0x00 };
    put(out, v, sizeof(v));
}

static void integer_small(derbuf *out, unsigned v)
{
    uint8_t b[5];
    size_t n = 0;
    if (v <= 0x7f) {
        b[n++] = (uint8_t)v;
    } else if (v <= 0xff) {
        b[n++] = 0x00;
        b[n++] = (uint8_t)v;
    } else {
        b[n++] = (uint8_t)(v >> 8);
        b[n++] = (uint8_t)v;
        if (b[0] & 0x80) {
            memmove(b + 1, b, n);
            b[0] = 0x00;
            n++;
        }
    }
    tlv(out, 0x02, b, n);
}

static void boolean(derbuf *out, int v)
{
    uint8_t b = v ? 0xff : 0x00;
    tlv(out, 0x01, &b, 1);
}

static void octet_string(derbuf *out, const uint8_t *val, size_t n)
{
    tlv(out, 0x04, val, n);
}

static void bit_string(derbuf *out, const uint8_t *val, size_t n)
{
    derbuf tmp = {0};
    put_u8(&tmp, 0x00);
    put(&tmp, val, n);
    tlv(out, 0x03, tmp.b, tmp.len);
}

static void bit_string_raw(derbuf *out, uint8_t unused, const uint8_t *val, size_t n)
{
    derbuf tmp = {0};
    put_u8(&tmp, unused);
    put(&tmp, val, n);
    tlv(out, 0x03, tmp.b, tmp.len);
}

static void alg_id(derbuf *out)
{
    derbuf inner = {0};
    oid(&inner, OID_HAWK, sizeof(OID_HAWK));
    nullv(&inner);
    seq(out, &inner);
}

static void name_cn(derbuf *out, const char *cn)
{
    derbuf atv = {0}, rdn = {0}, name = {0};
    oid(&atv, OID_CN, sizeof(OID_CN));
    tlv(&atv, 0x13, (const uint8_t *)cn, strlen(cn));
    seq(&rdn, &atv);
    set(&name, &rdn);
    seq(out, &name);
}

static void generalized_time(derbuf *out, time_t t)
{
    struct tm tmv;
    char s[16];
    gmtime_r(&t, &tmv);
    snprintf(s, sizeof(s), "%04d%02d%02d%02d%02d%02dZ",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    tlv(out, 0x18, (const uint8_t *)s, 15);
}

static void validity(derbuf *out, time_t nb, time_t na)
{
    derbuf inner = {0};
    generalized_time(&inner, nb);
    generalized_time(&inner, na);
    seq(out, &inner);
}

static void spki(derbuf *out, const uint8_t pub[HAWK_PUB_LEN])
{
    derbuf inner = {0};
    alg_id(&inner);
    bit_string(&inner, pub, HAWK_PUB_LEN);
    seq(out, &inner);
}

static void extension(derbuf *out, const uint8_t *oidv, size_t oidn,
                      int critical, const derbuf *value)
{
    derbuf inner = {0};
    oid(&inner, oidv, oidn);
    if (critical) boolean(&inner, 1);
    octet_string(&inner, value->b, value->len);
    seq(out, &inner);
}

static void basic_constraints_value(derbuf *out, int is_ca)
{
    derbuf inner = {0};
    boolean(&inner, is_ca);
    seq(out, &inner);
}

static void key_usage_value(derbuf *out, int is_ca)
{
    uint8_t bits;
    if (is_ca) {
        bits = 0x06; /* keyCertSign + cRLSign */
        bit_string_raw(out, 1, &bits, 1);
    } else {
        bits = 0x80; /* digitalSignature */
        bit_string_raw(out, 7, &bits, 1);
    }
}

static void eku_value(derbuf *out, int server_auth)
{
    derbuf inner = {0};
    if (server_auth)
        oid(&inner, OID_SERVER_AUTH, sizeof(OID_SERVER_AUTH));
    else
        oid(&inner, OID_CLIENT_AUTH, sizeof(OID_CLIENT_AUTH));
    seq(out, &inner);
}

static void san_value(derbuf *out)
{
    derbuf inner = {0};
    const char dns[] = "pico-mqtt-broker";
    uint8_t ip[] = { 192, 168, 1, 50 };
    tlv(&inner, 0x82, (const uint8_t *)dns, strlen(dns));
    tlv(&inner, 0x87, ip, sizeof(ip));
    seq(out, &inner);
}

static void v3_extensions(derbuf *out, int is_ca, int is_server)
{
    derbuf all = {0}, val = {0}, seqbuf = {0};

    basic_constraints_value(&val, is_ca);
    extension(&all, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS),
              1, &val);

    memset(&val, 0, sizeof(val));
    key_usage_value(&val, is_ca);
    extension(&all, OID_KEY_USAGE, sizeof(OID_KEY_USAGE), 1, &val);

    if (!is_ca) {
        memset(&val, 0, sizeof(val));
        eku_value(&val, is_server);
        extension(&all, OID_EXT_KEY_USAGE, sizeof(OID_EXT_KEY_USAGE), 0, &val);
    }

    if (is_server) {
        memset(&val, 0, sizeof(val));
        san_value(&val);
        extension(&all, OID_SUBJECT_ALT_NAME, sizeof(OID_SUBJECT_ALT_NAME),
                  0, &val);
    }

    seq(&seqbuf, &all);
    tlv(out, 0xa3, seqbuf.b, seqbuf.len);
}

static void pkcs8(derbuf *out, const hawk_keypair *kp)
{
    derbuf inner = {0};
    uint8_t keypair[HAWK_KEYPAIR_LEN];
    memcpy(keypair, kp->priv, HAWK_PRIV_LEN);
    memcpy(keypair + HAWK_PRIV_LEN, kp->pub, HAWK_PUB_LEN);
    integer_small(&inner, 0);
    alg_id(&inner);
    octet_string(&inner, keypair, sizeof(keypair));
    seq(out, &inner);
}

static void make_tbs(derbuf *out, unsigned serial, const char *issuer_cn,
                     const char *subject_cn, const hawk_keypair *subject_key,
                     int is_ca, int is_server)
{
    derbuf inner = {0}, ver = {0};
    time_t now = time(NULL);
    integer_small(&ver, 2);
    tlv(&inner, 0xa0, ver.b, ver.len);
    integer_small(&inner, serial);
    alg_id(&inner);
    name_cn(&inner, issuer_cn);
    validity(&inner, now, now + (time_t)3650 * 24 * 3600);
    name_cn(&inner, subject_cn);
    spki(&inner, subject_key->pub);
    v3_extensions(&inner, is_ca, is_server);
    seq(out, &inner);
}

static void sign_tbs(uint8_t sig[HAWK_SIG_LEN], const derbuf *tbs,
                     const hawk_keypair *issuer)
{
    shake_context sc;
    void *tmp = malloc(HAWK_TMPSIZE_SIGN(HAWK_LOGN));
    if (!tmp) die("malloc sign tmp");
    hawk_sign_start(&sc);
    shake_inject(&sc, tbs->b, tbs->len);
    /*
     * Match hawk_provider's OpenSSL signature implementation. The upstream
     * HAWK API comment says the context is normally unflipped, but this
     * provider flips before both signing and verification; TLS certificate
     * validation therefore expects this convention.
     */
    shake_flip(&sc);
    if (!hawk_sign_finish(HAWK_LOGN, rng_urandom, NULL, sig, &sc,
                          issuer->priv, tmp, HAWK_TMPSIZE_SIGN(HAWK_LOGN)))
        die("hawk_sign_finish");
    free(tmp);
}

static void make_cert(derbuf *out, unsigned serial, const char *issuer_cn,
                      const hawk_keypair *issuer_key, const char *subject_cn,
                      const hawk_keypair *subject_key, int is_ca,
                      int is_server)
{
    derbuf tbs = {0}, inner = {0};
    uint8_t sig[HAWK_SIG_LEN];
    make_tbs(&tbs, serial, issuer_cn, subject_cn, subject_key, is_ca,
             is_server);
    sign_tbs(sig, &tbs, issuer_key);
    put(&inner, tbs.b, tbs.len);
    alg_id(&inner);
    bit_string(&inner, sig, sizeof(sig));
    seq(out, &inner);
}

static void gen_key(hawk_keypair *kp)
{
    void *tmp = malloc(HAWK_TMPSIZE_KEYGEN(HAWK_LOGN));
    if (!tmp) die("malloc keygen tmp");
    if (!hawk_keygen(HAWK_LOGN, kp->priv, kp->pub, rng_urandom, NULL, tmp,
                     HAWK_TMPSIZE_KEYGEN(HAWK_LOGN)))
        die("hawk_keygen");
    free(tmp);
}

static const char b64tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void write_pem(const char *path, const char *type,
                      const uint8_t *der, size_t der_len)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        perror(path);
        exit(1);
    }
    fprintf(f, "-----BEGIN %s-----\n", type);
    size_t col = 0;
    for (size_t i = 0; i < der_len; i += 3) {
        uint32_t v = (uint32_t)der[i] << 16;
        int n = 1;
        if (i + 1 < der_len) { v |= (uint32_t)der[i + 1] << 8; n++; }
        if (i + 2 < der_len) { v |= der[i + 2]; n++; }
        char out[4];
        out[0] = b64tab[(v >> 18) & 0x3f];
        out[1] = b64tab[(v >> 12) & 0x3f];
        out[2] = (n > 1) ? b64tab[(v >> 6) & 0x3f] : '=';
        out[3] = (n > 2) ? b64tab[v & 0x3f] : '=';
        for (int j = 0; j < 4; j++) {
            fputc(out[j], f);
            if (++col == 64) {
                fputc('\n', f);
                col = 0;
            }
        }
    }
    if (col) fputc('\n', f);
    fprintf(f, "-----END %s-----\n", type);
    fclose(f);
}

static void write_pair(const char *cert_path, const char *key_path,
                       const derbuf *cert, const hawk_keypair *kp)
{
    derbuf key = {0};
    pkcs8(&key, kp);
    write_pem(cert_path, "CERTIFICATE", cert->b, cert->len);
    write_pem(key_path, "PRIVATE KEY", key.b, key.len);
}

int main(int argc, char **argv)
{
    const char *outdir = (argc > 1) ? argv[1] : "certlab/hawk512";
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", outdir);
    if (system(cmd) != 0) die("mkdir output directory");

    hawk_keypair ca, server, client;
    derbuf ca_cert = {0}, server_cert = {0}, client_cert = {0};

    fprintf(stderr, "[+] Generating HAWK-512 Root CA key\n");
    gen_key(&ca);
    fprintf(stderr, "[+] Generating HAWK-512 server key\n");
    gen_key(&server);
    fprintf(stderr, "[+] Generating HAWK-512 client-device key\n");
    gen_key(&client);

    fprintf(stderr, "[+] Building CA certificate\n");
    make_cert(&ca_cert, 1, "hawk512-root-ca", &ca, "hawk512-root-ca",
              &ca, 1, 0);
    fprintf(stderr, "[+] Building server certificate\n");
    make_cert(&server_cert, 2, "hawk512-root-ca", &ca,
              "pico-mqtt-broker", &server, 0, 1);
    fprintf(stderr, "[+] Building client-device certificate\n");
    make_cert(&client_cert, 3, "hawk512-root-ca", &ca,
              "pico-hawk-client", &client, 0, 0);

    char path[1024];
    snprintf(path, sizeof(path), "%s/ca.cert.pem", outdir);
    write_pem(path, "CERTIFICATE", ca_cert.b, ca_cert.len);
    snprintf(path, sizeof(path), "%s/ca.key.pem", outdir);
    derbuf ca_key = {0};
    pkcs8(&ca_key, &ca);
    write_pem(path, "PRIVATE KEY", ca_key.b, ca_key.len);

    char cert_path[1024], key_path[1024];
    snprintf(cert_path, sizeof(cert_path), "%s/server.cert.pem", outdir);
    snprintf(key_path, sizeof(key_path), "%s/server.key.pem", outdir);
    write_pair(cert_path, key_path, &server_cert, &server);

    snprintf(cert_path, sizeof(cert_path), "%s/client_hawk512.cert.pem", outdir);
    snprintf(key_path, sizeof(key_path), "%s/client_hawk512.key.pem", outdir);
    write_pair(cert_path, key_path, &client_cert, &client);

    fprintf(stderr, "[+] Wrote HAWK PKI to %s\n", outdir);
    return 0;
}
