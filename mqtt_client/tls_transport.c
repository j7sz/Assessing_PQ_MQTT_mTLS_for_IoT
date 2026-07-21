#include "tls_transport.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

/* Some newlib packagings guard the 64-bit PRI* macros behind
 * __int64_t_defined while only defining ___int64_t_defined; provide a
 * portable fallback (newlib uint64_t is unsigned long long). */
#ifndef PRIu64
#define PRIu64 "llu"
#endif

#include <sys/time.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "lwip/dns.h"
#include "lwip/err.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "runtime_memory.h"

word32 LowResTimer(void) {
    return to_ms_since_boot(get_absolute_time()) / 1000u;
}

word32 TimeNowInMilliseconds(void) {
    return to_ms_since_boot(get_absolute_time());
}

/* ---- RX ring buffer ------------------------------------------------ */

#define RX_BUF_CAP 16384u

typedef struct {
    uint8_t  data[RX_BUF_CAP];
    uint16_t head;   /* write position */
    uint16_t tail;   /* read position  */
    uint16_t avail;
} rx_ring_t;

static void rx_push(rx_ring_t *r, const uint8_t *src, uint16_t n) {
    for (uint16_t i = 0; i < n && r->avail < RX_BUF_CAP; i++) {
        r->data[r->head] = src[i];
        r->head = (r->head + 1) % RX_BUF_CAP;
        r->avail++;
    }
}

static uint16_t rx_pop(rx_ring_t *r, uint8_t *dst, uint16_t want) {
    uint16_t got = (want < r->avail) ? want : r->avail;
    for (uint16_t i = 0; i < got; i++) {
        dst[i] = r->data[r->tail];
        r->tail = (r->tail + 1) % RX_BUF_CAP;
        r->avail--;
    }
    return got;
}

/* ---- Connection state ---------------------------------------------- */

struct tls_conn {
    struct tcp_pcb *pcb;
    rx_ring_t       rx;
    volatile bool   tcp_connected;
    volatile bool   tcp_error;
    volatile bool   remote_closed;
    volatile bool   io_timed_out;
    volatile err_t  tcp_error_code;
    WOLFSSL_CTX    *ssl_ctx;
    WOLFSSL        *ssl;
    uint64_t        dns_us;
    uint64_t        tcp_connect_us;
    uint64_t        tls_handshake_us;
    uint64_t        tls_rx_bytes;
    uint64_t        tls_tx_bytes;
    uint64_t        tls_handshake_rx_bytes;
    uint64_t        tls_handshake_tx_bytes;
    /* Handshake-scoped instrumentation: in_handshake gates the counters so
     * MQTT application traffic never pollutes the handshake numbers. */
    volatile bool   in_handshake;
    uint64_t        hs_net_wait_us; /* time blocked on peer bytes in wssl_recv */
    uint32_t        hs_tx_calls;
    uint32_t        hs_rx_calls;
};

/* ---- DNS helper ---------------------------------------------------- */

static volatile bool    dns_done;
static volatile bool    dns_err;
static ip_addr_t        dns_result;

static void dns_cb(const char *name, const ip_addr_t *addr, void *arg) {
    (void)name; (void)arg;
    if (addr) { dns_result = *addr; dns_done = true; }
    else       { dns_err   = true;  dns_done = true; }
}

static bool resolve_host(const char *host, ip_addr_t *out, int *error_code,
                         bool *timed_out) {
    dns_done = false;
    dns_err  = false;
    cyw43_arch_lwip_begin();
    err_t e = dns_gethostbyname(host, out, dns_cb, NULL);
    cyw43_arch_lwip_end();
    if (e == ERR_OK) return true;          /* already cached */
    if (e != ERR_INPROGRESS) {
        if (error_code) *error_code = e;
        return false;
    }
    uint32_t deadline = to_ms_since_boot(get_absolute_time()) + 10000;
    while (!dns_done) {
        if (to_ms_since_boot(get_absolute_time()) > deadline) {
            if (error_code) *error_code = TLS_ATTEMPT_ERR_TIMEOUT;
            if (timed_out) *timed_out = true;
            return false;
        }
        sleep_ms(1);
    }
    if (dns_err) {
        if (error_code) *error_code = ERR_VAL;
        return false;
    }
    *out = dns_result;
    return true;
}

/* ---- lwIP TCP callbacks -------------------------------------------- */

static err_t on_connected(void *arg, struct tcp_pcb *pcb, err_t err) {
    (void)pcb;
    tls_conn_t *c = (tls_conn_t *)arg;
    if (err != ERR_OK) {
        c->tcp_error_code = err;
        c->tcp_error = true;
        return err;
    }
    c->tcp_connected = true;
    return ERR_OK;
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    tls_conn_t *c = (tls_conn_t *)arg;
    if (!p || err != ERR_OK) {
        c->remote_closed = true;
        return ERR_OK;
    }
    struct pbuf *cur = p;
    while (cur) {
        rx_push(&c->rx, (const uint8_t *)cur->payload, (uint16_t)cur->len);
        cur = cur->next;
    }
    c->tls_rx_bytes += p->tot_len;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void on_err(void *arg, err_t err) {
    tls_conn_t *c = (tls_conn_t *)arg;
    c->tcp_error_code = err;
    c->tcp_error = true;
    c->pcb = NULL;   /* lwIP frees the PCB on error */
}

/* ---- wolfSSL I/O callbacks ---------------------------------------- */

static int wssl_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    tls_conn_t *c = (tls_conn_t *)ctx;
    uint64_t t_enter = time_us_64();
    uint32_t deadline = to_ms_since_boot(get_absolute_time()) + 15000;
    while (true) {
        cyw43_arch_lwip_begin();
        uint16_t got = rx_pop(&c->rx, (uint8_t *)buf, (uint16_t)sz);
        bool closed = c->tcp_error || c->remote_closed;
        cyw43_arch_lwip_end();

        if (got != 0) {
            if (c->in_handshake) {
                c->hs_net_wait_us += time_us_64() - t_enter;
                c->hs_rx_calls++;
            }
            return (int)got;
        }
        if (closed) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        if (to_ms_since_boot(get_absolute_time()) > deadline) {
            c->io_timed_out = true;
            return WOLFSSL_CBIO_ERR_TIMEOUT;
        }
        sleep_ms(1);
    }
}

static int wssl_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    tls_conn_t *c = (tls_conn_t *)ctx;
    if (!c->pcb || c->tcp_error) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    cyw43_arch_lwip_begin();
    err_t e = tcp_write(c->pcb, buf, (u16_t)sz, TCP_WRITE_FLAG_COPY);
    if (e == ERR_OK) tcp_output(c->pcb);
    cyw43_arch_lwip_end();
    if (e != ERR_OK) return WOLFSSL_CBIO_ERR_GENERAL;
    c->tls_tx_bytes += (uint64_t)sz;
    if (c->in_handshake) c->hs_tx_calls++;
    return sz;
}

/* ---- Public API ---------------------------------------------------- */

const char *tls_failure_stage_name(tls_failure_stage_t stage) {
    switch (stage) {
    case TLS_FAILURE_DNS:           return "dns";
    case TLS_FAILURE_TCP:           return "tcp";
    case TLS_FAILURE_TLS_CONTEXT:   return "tls_context";
    case TLS_FAILURE_CERTIFICATE:   return "certificate";
    case TLS_FAILURE_PRIVATE_KEY:   return "private_key";
    case TLS_FAILURE_KEY_SHARE:     return "key_share";
    case TLS_FAILURE_TLS_HANDSHAKE: return "tls_handshake";
    case TLS_FAILURE_MQTT:          return "mqtt";
    case TLS_FAILURE_NONE:
    default:                        return "none";
    }
}

static void capture_result(tls_attempt_result_t *result, const tls_conn_t *c) {
    if (!result || !c) return;
    result->timings = tls_get_timings(c);
    result->bandwidth = tls_get_bandwidth(c);
}

static tls_conn_t *connect_failed(tls_conn_t *c,
                                  tls_attempt_result_t *result,
                                  tls_failure_stage_t stage,
                                  int error_code,
                                  bool timed_out) {
    if (result) {
        capture_result(result, c);
        result->failure_stage = stage;
        result->error_code = error_code;
        result->timed_out = timed_out;
    }
    tls_close(c);
    return NULL;
}

static tls_conn_t *tls_connect_common(
    const char     *host,    uint16_t port,
    const uint8_t  *ca_der,  size_t ca_der_len,
    const uint8_t  *cert,    size_t cert_len,
    const uint8_t  *key,     size_t key_len,
    tls_attempt_result_t *result)
{
    if (result) memset(result, 0, sizeof(*result));

    runtime_memory_set_stage(RUNTIME_MEM_STAGE_DNS);
    tls_conn_t *c = (tls_conn_t *)calloc(1, sizeof(*c));
    if (!c) {
        runtime_memory_note_allocation_failure(sizeof(*c));
        if (result) {
            result->failure_stage = TLS_FAILURE_DNS;
            result->error_code = TLS_ATTEMPT_ERR_ALLOCATION;
        }
        return NULL;
    }

    /* 1. Resolve hostname */
    ip_addr_t server_ip;
    uint64_t t0 = time_us_64();
    int dns_error = ERR_OK;
    bool dns_timeout = false;
    if (!resolve_host(host, &server_ip, &dns_error, &dns_timeout)) {
        c->dns_us = time_us_64() - t0;
        printf("[tls] DNS resolution failed for %s\n", host);
        return connect_failed(c, result, TLS_FAILURE_DNS,
                              dns_error, dns_timeout);
    }
    c->dns_us = time_us_64() - t0;
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[tls] Resolved %s -> %s (%" PRIu64 " us)\n",
           host, ip4addr_ntoa(ip_2_ip4(&server_ip)), c->dns_us);
#endif

    /* 2. Open TCP connection */
    runtime_memory_set_stage(RUNTIME_MEM_STAGE_TCP);
    if (result) {
        struct timeval tv = {0};
        (void)gettimeofday(&tv, NULL);
        result->tcp_start_epoch_ms = (uint64_t)tv.tv_sec * 1000u +
                                     (uint64_t)tv.tv_usec / 1000u;
    }
    t0 = time_us_64();
    cyw43_arch_lwip_begin();
    c->pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (!c->pcb) {
        cyw43_arch_lwip_end();
        return connect_failed(c, result, TLS_FAILURE_TCP, ERR_MEM, false);
    }
    tcp_arg(c->pcb, c);
    tcp_recv(c->pcb, on_recv);
    tcp_err(c->pcb, on_err);
    err_t e = tcp_connect(c->pcb, &server_ip, port, on_connected);
    cyw43_arch_lwip_end();
    if (e != ERR_OK) {
        return connect_failed(c, result, TLS_FAILURE_TCP, e, false);
    }

    uint32_t deadline = to_ms_since_boot(get_absolute_time()) + 10000;
    while (!c->tcp_connected && !c->tcp_error) {
        if (to_ms_since_boot(get_absolute_time()) > deadline) {
            printf("[tls] TCP connect timeout\n");
            c->tcp_connect_us = time_us_64() - t0;
            return connect_failed(c, result, TLS_FAILURE_TCP,
                                  TLS_ATTEMPT_ERR_TIMEOUT, true);
        }
        sleep_ms(1);
    }
    if (c->tcp_error) {
        c->tcp_connect_us = time_us_64() - t0;
        printf("[tls] TCP connect error\n");
        return connect_failed(c, result, TLS_FAILURE_TCP,
                              c->tcp_error_code, false);
    }
    c->tcp_connect_us = time_us_64() - t0;
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[tls] TCP connected to %s:%u (%" PRIu64 " us)\n",
           host, port, c->tcp_connect_us);
#endif

    /* 3. Initialise wolfSSL */
    runtime_memory_set_stage(RUNTIME_MEM_STAGE_TLS_CONTEXT);
    wolfSSL_SetAllocators(runtime_memory_wolfssl_malloc,
                          runtime_memory_wolfssl_free,
                          runtime_memory_wolfssl_realloc);
    wolfSSL_Init();

    c->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!c->ssl_ctx) {
        return connect_failed(c, result, TLS_FAILURE_TLS_CONTEXT,
                              TLS_ATTEMPT_ERR_ALLOCATION, false);
    }

    wolfSSL_CTX_SetIORecv(c->ssl_ctx, wssl_recv);
    wolfSSL_CTX_SetIOSend(c->ssl_ctx, wssl_send);

    /* Load the CA certificate used to verify the broker. */
    runtime_memory_set_stage(RUNTIME_MEM_STAGE_CERTIFICATE);
    int load_ret = wolfSSL_CTX_load_verify_buffer(c->ssl_ctx,
            ca_der, (long)ca_der_len, SSL_FILETYPE_ASN1);
    if (load_ret != SSL_SUCCESS) {
        printf("[tls] Failed to load CA cert: %s (%d)\n",
               wc_GetErrorString(load_ret), load_ret);
        return connect_failed(c, result, TLS_FAILURE_CERTIFICATE,
                              load_ret, false);
    }
    wolfSSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_PEER, NULL);

    /* Load the board certificate and private key for mutual TLS. */
    load_ret = wolfSSL_CTX_use_certificate_buffer(c->ssl_ctx,
            cert, (long)cert_len, SSL_FILETYPE_ASN1);
    if (load_ret != SSL_SUCCESS) {
        printf("[tls] Failed to load client cert: %s (%d)\n",
               wc_GetErrorString(load_ret), load_ret);
        return connect_failed(c, result, TLS_FAILURE_CERTIFICATE,
                              load_ret, false);
    }
    runtime_memory_set_stage(RUNTIME_MEM_STAGE_PRIVATE_KEY);
    load_ret = wolfSSL_CTX_use_PrivateKey_buffer(c->ssl_ctx,
            key, (long)key_len, SSL_FILETYPE_ASN1);
    if (load_ret != SSL_SUCCESS) {
        printf("[tls] Failed to load client key: %s (%d)\n",
               wc_GetErrorString(load_ret), load_ret);
        return connect_failed(c, result, TLS_FAILURE_PRIVATE_KEY,
                              load_ret, false);
    }

    runtime_memory_set_stage(RUNTIME_MEM_STAGE_TLS_CONTEXT);
    c->ssl = wolfSSL_new(c->ssl_ctx);
    if (!c->ssl) {
        return connect_failed(c, result, TLS_FAILURE_TLS_CONTEXT,
                              TLS_ATTEMPT_ERR_ALLOCATION, false);
    }

    wolfSSL_SetIOReadCtx(c->ssl, c);
    wolfSSL_SetIOWriteCtx(c->ssl, c);

    /* Target the TLS 1.3 hybrid key exchange used by the benchmark:
     * X25519 for the classical half plus ML-KEM-768 for the PQ half. */
    runtime_memory_set_stage(RUNTIME_MEM_STAGE_KEY_SHARE);
    int curve_ret = wolfSSL_UseSupportedCurve(c->ssl, WOLFSSL_X25519MLKEM768);
    if (curve_ret != SSL_SUCCESS) {
        printf("[tls] Failed to set supported group X25519MLKEM768: %s (%d)\n",
               wc_GetErrorString(curve_ret), curve_ret);
        return connect_failed(c, result, TLS_FAILURE_KEY_SHARE,
                              curve_ret, false);
    }
    curve_ret = wolfSSL_UseKeyShare(c->ssl, WOLFSSL_X25519MLKEM768);
    if (curve_ret != SSL_SUCCESS) {
        printf("[tls] Failed to create X25519MLKEM768 key share: %s (%d)\n",
               wc_GetErrorString(curve_ret), curve_ret);
        return connect_failed(c, result, TLS_FAILURE_KEY_SHARE,
                              curve_ret, false);
    }

    /* 4. TLS handshake */
    runtime_memory_set_stage(RUNTIME_MEM_STAGE_TLS_HANDSHAKE);
    runtime_memory_mark_tls_start();
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[tls] Starting TLS 1.3 mTLS handshake with X25519MLKEM768 key share...\n");
#endif
    int ret;
    uint64_t hs_rx_start = c->tls_rx_bytes;
    uint64_t hs_tx_start = c->tls_tx_bytes;
    c->in_handshake = true;
    t0 = time_us_64();
    deadline = to_ms_since_boot(get_absolute_time()) + 30000;
    do {
        ret = wolfSSL_connect(c->ssl);
        if (to_ms_since_boot(get_absolute_time()) > deadline) {
            printf("[tls] TLS handshake timeout\n");
            c->in_handshake = false;
            c->tls_handshake_us = time_us_64() - t0;
            c->tls_handshake_rx_bytes = c->tls_rx_bytes - hs_rx_start;
            c->tls_handshake_tx_bytes = c->tls_tx_bytes - hs_tx_start;
            return connect_failed(c, result, TLS_FAILURE_TLS_HANDSHAKE,
                                  TLS_ATTEMPT_ERR_TIMEOUT, true);
        }
    } while (ret != SSL_SUCCESS &&
             (wolfSSL_get_error(c->ssl, ret) == SSL_ERROR_WANT_READ ||
              wolfSSL_get_error(c->ssl, ret) == SSL_ERROR_WANT_WRITE));
    c->in_handshake = false;

    if (ret != SSL_SUCCESS) {
        char err_buf[80];
        int ssl_err = wolfSSL_get_error(c->ssl, ret);
        wolfSSL_ERR_error_string(ssl_err, err_buf);
        printf("[tls] Handshake failed: %s (ssl_err=%d, ret=%d)\n",
               err_buf, ssl_err, ret);
        c->tls_handshake_us = time_us_64() - t0;
        c->tls_handshake_rx_bytes = c->tls_rx_bytes - hs_rx_start;
        c->tls_handshake_tx_bytes = c->tls_tx_bytes - hs_tx_start;
        return connect_failed(c, result, TLS_FAILURE_TLS_HANDSHAKE,
                              c->io_timed_out ? TLS_ATTEMPT_ERR_TIMEOUT : ssl_err,
                              c->io_timed_out);
    }
    c->tls_handshake_us = time_us_64() - t0;
    c->tls_handshake_rx_bytes = c->tls_rx_bytes - hs_rx_start;
    c->tls_handshake_tx_bytes = c->tls_tx_bytes - hs_tx_start;
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[tls] mTLS handshake complete (%" PRIu64 " us), cipher=%s, group=%s\n",
           c->tls_handshake_us,
           wolfSSL_get_cipher(c->ssl),
           wolfSSL_get_curve_name(c->ssl) ? wolfSSL_get_curve_name(c->ssl) : "unknown");
#endif
    capture_result(result, c);
    return c;
}

tls_conn_t *tls_connect(
    const char     *host,    uint16_t port,
    const uint8_t  *ca_der,  size_t ca_der_len,
    const uint8_t  *cert,    size_t cert_len,
    const uint8_t  *key,     size_t key_len)
{
    return tls_connect_common(
        host, port, ca_der, ca_der_len, cert, cert_len, key, key_len,
        NULL);
}

tls_conn_t *tls_connect_attempt(
    const char *host, uint16_t port,
    const uint8_t *ca_der, size_t ca_der_len,
    const uint8_t *cert, size_t cert_len,
    const uint8_t *key, size_t key_len,
    tls_attempt_result_t *result)
{
    return tls_connect_common(
        host, port, ca_der, ca_der_len, cert, cert_len, key, key_len,
        result);
}

tls_timings_t tls_get_timings(const tls_conn_t *conn) {
    tls_timings_t t = { 0, 0, 0, 0, 0 };
    if (conn) {
        t.dns_us = conn->dns_us;
        t.tcp_us = conn->tcp_connect_us;
        t.tls_us = conn->tls_handshake_us;
        t.tls_net_wait_us = conn->hs_net_wait_us;
        t.tls_crypto_us = (conn->tls_handshake_us > conn->hs_net_wait_us)
            ? conn->tls_handshake_us - conn->hs_net_wait_us : 0;
    }
    return t;
}

tls_bandwidth_t tls_get_bandwidth(const tls_conn_t *conn) {
    tls_bandwidth_t b = { 0, 0, 0, 0, 0, 0 };
    if (conn) {
        b.handshake_rx_bytes = conn->tls_handshake_rx_bytes;
        b.handshake_tx_bytes = conn->tls_handshake_tx_bytes;
        b.total_rx_bytes = conn->tls_rx_bytes;
        b.total_tx_bytes = conn->tls_tx_bytes;
        b.handshake_tx_calls = conn->hs_tx_calls;
        b.handshake_rx_calls = conn->hs_rx_calls;
    }
    return b;
}

int tls_write(tls_conn_t *conn, const uint8_t *buf, size_t len) {
    return wolfSSL_write(conn->ssl, buf, (int)len);
}

int tls_read(tls_conn_t *conn, uint8_t *buf, size_t len) {
    conn->io_timed_out = false;
    return wolfSSL_read(conn->ssl, buf, (int)len);
}

bool tls_io_timed_out(const tls_conn_t *conn) {
    return conn && conn->io_timed_out;
}

void tls_close(tls_conn_t *conn) {
    if (!conn) return;
    runtime_memory_set_stage(RUNTIME_MEM_STAGE_CLOSE);
    if (conn->ssl) {
        wolfSSL_shutdown(conn->ssl);
        wolfSSL_free(conn->ssl);
    }
    if (conn->ssl_ctx) wolfSSL_CTX_free(conn->ssl_ctx);
    if (conn->pcb) {
        cyw43_arch_lwip_begin();
        tcp_arg(conn->pcb, NULL);
        tcp_recv(conn->pcb, NULL);
        tcp_err(conn->pcb, NULL);
        err_t e = tcp_close(conn->pcb);
        if (e != ERR_OK) tcp_abort(conn->pcb);
        cyw43_arch_lwip_end();
    }
    free(conn);
}
