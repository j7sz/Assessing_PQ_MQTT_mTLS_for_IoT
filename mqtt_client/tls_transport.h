#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* TLS benchmark builds suppress successful per-phase traces by default so
 * serial captures retain their lifecycle messages and machine-readable rows.
 * Failure diagnostics remain enabled. Set the CMake option
 * MQTT_TLS_BENCH_COMPACT_OUTPUT=OFF when interactive transport debugging is
 * needed. */
#ifndef TLS_BENCH_ITERS
#define TLS_BENCH_ITERS 0
#endif
#ifndef MQTT_TLS_BENCH_COMPACT_OUTPUT
#define MQTT_TLS_BENCH_COMPACT_OUTPUT 0
#endif
#if TLS_BENCH_ITERS > 0 && MQTT_TLS_BENCH_COMPACT_OUTPUT
#define MQTT_BENCH_COMPACT_OUTPUT 1
#else
#define MQTT_BENCH_COMPACT_OUTPUT 0
#endif

typedef struct tls_conn tls_conn_t;

typedef enum {
    TLS_FAILURE_NONE = 0,
    TLS_FAILURE_DNS,
    TLS_FAILURE_TCP,
    TLS_FAILURE_TLS_CONTEXT,
    TLS_FAILURE_CERTIFICATE,
    TLS_FAILURE_PRIVATE_KEY,
    TLS_FAILURE_KEY_SHARE,
    TLS_FAILURE_TLS_HANDSHAKE,
    TLS_FAILURE_MQTT
} tls_failure_stage_t;

enum {
    TLS_ATTEMPT_ERR_ALLOCATION = -1000,
    TLS_ATTEMPT_ERR_TIMEOUT = -1001,
    TLS_ATTEMPT_ERR_MQTT_SEND = -1101,
    TLS_ATTEMPT_ERR_MQTT_PACKET = -1102,
    TLS_ATTEMPT_ERR_MQTT_CONNACK = -1103
};

/* Per-phase latency breakdown captured during transport connect. */
typedef struct {
    uint64_t dns_us;          /* DNS resolution time   */
    uint64_t tcp_us;          /* TCP three-way handshake time */
    uint64_t tls_us;          /* wolfSSL_connect() total wall time, or 0 for plain MQTT */
    uint64_t tls_net_wait_us; /* time inside tls_us spent waiting for peer bytes */
    uint64_t tls_crypto_us;   /* tls_us - tls_net_wait_us: device-side work */
} tls_timings_t;

/* Client-observed transport payload bytes carried over TCP.
 * TLS targets count TLS record bytes; the plain target counts MQTT bytes.
 * These counters exclude TCP/IP/WiFi headers and link-layer retransmits. */
typedef struct {
    uint64_t handshake_rx_bytes;
    uint64_t handshake_tx_bytes;
    uint64_t total_rx_bytes;
    uint64_t total_tx_bytes;
    uint32_t handshake_tx_calls; /* send-callback invocations during handshake */
    uint32_t handshake_rx_calls; /* recv-callback returns with data during handshake */
} tls_bandwidth_t;

/* Populated even when connect returns NULL, so failed and timed-out attempts
 * retain their completed phase timings and machine-readable cause. */
typedef struct {
    tls_timings_t timings;
    tls_bandwidth_t bandwidth;
    uint64_t tcp_start_epoch_ms;
    tls_failure_stage_t failure_stage;
    int error_code;
    bool timed_out;
} tls_attempt_result_t;

const char *tls_failure_stage_name(tls_failure_stage_t stage);

/* Establishes TCP + TLS to host:port.
 * ca_der      : DER-encoded CA cert for server verification
 * client_cert : DER-encoded client cert (mTLS)
 * client_key  : DER-encoded private key (PKCS#8 DER)
 * Returns allocated tls_conn_t on success, NULL on failure.
 * Caller must free with tls_close(). */
tls_conn_t *tls_connect(
    const char     *host,
    uint16_t        port,
    const uint8_t  *ca_der,       size_t ca_der_len,
    const uint8_t  *client_cert,  size_t client_cert_len,
    const uint8_t  *client_key,   size_t client_key_len
);

tls_conn_t *tls_connect_attempt(
    const char     *host,
    uint16_t        port,
    const uint8_t  *ca_der,       size_t ca_der_len,
    const uint8_t  *client_cert,  size_t client_cert_len,
    const uint8_t  *client_key,   size_t client_key_len,
    tls_attempt_result_t *result
);

/* Establishes plain TCP to host:port, without TLS. */
tls_conn_t *tls_connect_plain(const char *host, uint16_t port);
tls_conn_t *tls_connect_plain_attempt(
    const char *host, uint16_t port, tls_attempt_result_t *result);

/* Returns per-phase timing recorded during the last transport connect. */
tls_timings_t tls_get_timings(const tls_conn_t *conn);

/* Returns TLS record byte counters captured by the transport. */
tls_bandwidth_t tls_get_bandwidth(const tls_conn_t *conn);

/* Write len bytes; returns bytes written or < 0 on error. */
int tls_write(tls_conn_t *conn, const uint8_t *buf, size_t len);

/* Read up to len bytes; returns bytes read or < 0 on error. */
int tls_read(tls_conn_t *conn, uint8_t *buf, size_t len);

/* True when the most recent transport read failed because its deadline expired. */
bool tls_io_timed_out(const tls_conn_t *conn);

void tls_close(tls_conn_t *conn);
