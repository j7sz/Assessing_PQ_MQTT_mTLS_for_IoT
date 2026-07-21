#include "tls_transport.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

/* Fallback for newlib packagings that mis-guard the 64-bit PRI* macros. */
#ifndef PRIu64
#define PRIu64 "llu"
#endif
#include <sys/time.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "lwip/dns.h"
#include "lwip/err.h"
#include "runtime_memory.h"

/* ---- RX ring buffer ------------------------------------------------ */

#define RX_BUF_CAP 16384u

typedef struct {
    uint8_t  data[RX_BUF_CAP];
    uint16_t head;
    uint16_t tail;
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
    uint64_t        dns_us;
    uint64_t        tcp_connect_us;
    uint64_t        total_rx_bytes;
    uint64_t        total_tx_bytes;
};

/* ---- DNS helper ---------------------------------------------------- */

static volatile bool dns_done;
static volatile bool dns_err;
static ip_addr_t     dns_result;

static void dns_cb(const char *name, const ip_addr_t *addr, void *arg) {
    (void)name;
    (void)arg;
    if (addr) {
        dns_result = *addr;
        dns_done = true;
    } else {
        dns_err = true;
        dns_done = true;
    }
}

static bool resolve_host(const char *host, ip_addr_t *out, int *error_code,
                         bool *timed_out) {
    dns_done = false;
    dns_err = false;
    cyw43_arch_lwip_begin();
    err_t e = dns_gethostbyname(host, out, dns_cb, NULL);
    cyw43_arch_lwip_end();
    if (e == ERR_OK) return true;
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
    c->total_rx_bytes += p->tot_len;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void on_err(void *arg, err_t err) {
    tls_conn_t *c = (tls_conn_t *)arg;
    c->tcp_error_code = err;
    c->tcp_error = true;
    c->pcb = NULL;
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

tls_conn_t *tls_connect_plain_attempt(
    const char *host, uint16_t port, tls_attempt_result_t *result) {
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

    ip_addr_t server_ip;
    uint64_t t0 = time_us_64();
    int dns_error = ERR_OK;
    bool dns_timeout = false;
    if (!resolve_host(host, &server_ip, &dns_error, &dns_timeout)) {
        c->dns_us = time_us_64() - t0;
        printf("[plain] DNS resolution failed for %s\n", host);
        if (result) {
            result->timings = tls_get_timings(c);
            result->failure_stage = TLS_FAILURE_DNS;
            result->error_code = dns_error;
            result->timed_out = dns_timeout;
        }
        tls_close(c);
        return NULL;
    }
    c->dns_us = time_us_64() - t0;
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[plain] Resolved %s -> %s (%" PRIu64 " us)\n",
           host, ip4addr_ntoa(ip_2_ip4(&server_ip)), c->dns_us);
#endif

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
        if (result) {
            result->failure_stage = TLS_FAILURE_TCP;
            result->error_code = ERR_MEM;
        }
        tls_close(c);
        return NULL;
    }
    tcp_arg(c->pcb, c);
    tcp_recv(c->pcb, on_recv);
    tcp_err(c->pcb, on_err);
    err_t e = tcp_connect(c->pcb, &server_ip, port, on_connected);
    cyw43_arch_lwip_end();
    if (e != ERR_OK) {
        if (result) {
            result->failure_stage = TLS_FAILURE_TCP;
            result->error_code = e;
        }
        tls_close(c);
        return NULL;
    }

    uint32_t deadline = to_ms_since_boot(get_absolute_time()) + 10000;
    while (!c->tcp_connected && !c->tcp_error) {
        if (to_ms_since_boot(get_absolute_time()) > deadline) {
            printf("[plain] TCP connect timeout\n");
            c->tcp_connect_us = time_us_64() - t0;
            if (result) {
                result->timings = tls_get_timings(c);
                result->failure_stage = TLS_FAILURE_TCP;
                result->error_code = TLS_ATTEMPT_ERR_TIMEOUT;
                result->timed_out = true;
            }
            tls_close(c);
            return NULL;
        }
        sleep_ms(1);
    }
    if (c->tcp_error) {
        c->tcp_connect_us = time_us_64() - t0;
        printf("[plain] TCP connect error\n");
        if (result) {
            result->timings = tls_get_timings(c);
            result->failure_stage = TLS_FAILURE_TCP;
            result->error_code = c->tcp_error_code;
        }
        tls_close(c);
        return NULL;
    }

    c->tcp_connect_us = time_us_64() - t0;
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[plain] TCP connected to %s:%u (%" PRIu64 " us)\n",
           host, port, c->tcp_connect_us);
#endif
    if (result) result->timings = tls_get_timings(c);
    return c;
}

tls_conn_t *tls_connect_plain(const char *host, uint16_t port) {
    return tls_connect_plain_attempt(host, port, NULL);
}

tls_timings_t tls_get_timings(const tls_conn_t *conn) {
    tls_timings_t t = { 0, 0, 0, 0, 0 };
    if (conn) {
        t.dns_us = conn->dns_us;
        t.tcp_us = conn->tcp_connect_us;
    }
    return t;
}

tls_bandwidth_t tls_get_bandwidth(const tls_conn_t *conn) {
    tls_bandwidth_t b = { 0, 0, 0, 0, 0, 0 };
    if (conn) {
        b.total_rx_bytes = conn->total_rx_bytes;
        b.total_tx_bytes = conn->total_tx_bytes;
    }
    return b;
}

int tls_write(tls_conn_t *conn, const uint8_t *buf, size_t len) {
    if (!conn || !conn->pcb || conn->tcp_error) return -1;
    if (len > UINT16_MAX) return -1;

    cyw43_arch_lwip_begin();
    err_t e = tcp_write(conn->pcb, buf, (u16_t)len, TCP_WRITE_FLAG_COPY);
    if (e == ERR_OK) tcp_output(conn->pcb);
    cyw43_arch_lwip_end();
    if (e != ERR_OK) return -1;

    conn->total_tx_bytes += (uint64_t)len;
    return (int)len;
}

int tls_read(tls_conn_t *conn, uint8_t *buf, size_t len) {
    if (!conn || len > UINT16_MAX) return -1;

    conn->io_timed_out = false;
    size_t total = 0;
    uint32_t deadline = to_ms_since_boot(get_absolute_time()) + 15000;
    while (total < len) {
        cyw43_arch_lwip_begin();
        uint16_t got = rx_pop(&conn->rx, buf + total, (uint16_t)(len - total));
        bool closed = conn->tcp_error || conn->remote_closed;
        cyw43_arch_lwip_end();

        total += got;
        if (total == len) return (int)total;
        if (closed) return total > 0 ? (int)total : -1;
        if (to_ms_since_boot(get_absolute_time()) > deadline) {
            conn->io_timed_out = true;
            return total > 0 ? (int)total : -1;
        }
        sleep_ms(1);
    }
    return (int)total;
}

bool tls_io_timed_out(const tls_conn_t *conn) {
    return conn && conn->io_timed_out;
}

void tls_close(tls_conn_t *conn) {
    if (!conn) return;
    runtime_memory_set_stage(RUNTIME_MEM_STAGE_CLOSE);
    if (conn->pcb) {
        cyw43_arch_lwip_begin();
        tcp_arg(conn->pcb, NULL);
        tcp_recv(conn->pcb, NULL);
        tcp_err(conn->pcb, NULL);
        err_t e = tcp_close(conn->pcb);
        if (e != ERR_OK) {
            tcp_abort(conn->pcb);
        }
        cyw43_arch_lwip_end();
    }
    free(conn);
}
