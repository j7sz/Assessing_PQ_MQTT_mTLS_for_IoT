#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

/* Some newlib packagings guard the 64-bit PRI* macros behind
 * __int64_t_defined while only defining ___int64_t_defined; provide a
 * portable fallback (newlib uint64_t is unsigned long long). */
#ifndef PRIu64
#define PRIu64 "llu"
#endif

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "hardware/adc.h"
#include "lwip/netif.h"
#include "lwip/apps/sntp.h"
#include "config.h"
#if defined(MQTT_TRANSPORT_PLAIN)
/* Plain MQTT mode uses only TCP and does not need certificate material. */
#elif defined(MQTT_SCHEME_FALCON512)
#  include "certs/certs_falcon512.h"
#elif defined(MQTT_SCHEME_MAYO1)
#  include "certs/certs_mayo1.h"
#elif defined(MQTT_SCHEME_SNOVA_24_5_16_4)
#  include "certs/certs_snova_24_5_16_4.h"
#elif defined(MQTT_SCHEME_HAWK512)
#  include "certs/certs_hawk512.h"
#elif defined(MQTT_SCHEME_ECDSA_P256)
#  include "certs/certs_ecdsa_p256.h"
#elif defined(MQTT_SCHEME_RSA2048)
#  include "certs/certs_rsa2048.h"
#else
#  include "certs/certs.h"          /* default: ML-DSA-44 */
#endif
#include "tls_transport.h"
#include "mqtt.h"
#include "runtime_memory.h"

#define NTP_SYNC_TIMEOUT_MS   60000u
#define MIN_VALID_UNIX_TIME   1735689600L  /* 2025-01-01T00:00:00Z */

static const char *const NTP_SERVER_NAMES[] = {
    "time.cloudflare.com",
    "time.google.com",
    "pool.ntp.org"
};

static volatile bool sntp_time_set;

void mqtt_sntp_set_system_time(unsigned long sec) {
    struct timeval tv = {
        .tv_sec = (time_t)sec,
        .tv_usec = 0
    };
    settimeofday(&tv, NULL);
    sntp_time_set = true;
}

/* ---- Internal temperature sensor (RP2040 and RP2350) --------------- */

static float read_temperature_c(void) {
    /* ADC channel 4 = internal temperature sensor */
    adc_select_input(4);
    uint16_t raw = adc_read();
    /* Pico RP2040/RP2350 datasheet (same constants on both chips):
     * T = 27 - (ADC_voltage - 0.706) / 0.001721 */
    float voltage = (float)raw * (3.3f / (1 << 12));
    return 27.0f - (voltage - 0.706f) / 0.001721f;
}

/* ---- Simulated humidity sensor ------------------------------------ */

static float read_humidity_percent(void) {
    /* Simulated humidity: oscillates between 45% and 75% based on time */
    time_t now;
    time(&now);

    /* Use time to create a realistic oscillation pattern */
    uint32_t cycle = (uint32_t)now % 3600;  /* 1-hour cycle */
    float phase = (float)cycle / 3600.0f * 6.28f;  /* Convert to radians */
    float humidity = 60.0f + 15.0f * sinf(phase);  /* Oscillates 45-75% */

    return humidity;
}

/* ---- JSON payload builder ----------------------------------------- */

static int build_payload(char *buf, size_t buf_len, float temp_c, float humidity_pct) {
#if defined(MQTT_BOARD_PICO2W)
    (void)temp_c;
    return snprintf(buf, buf_len,
        "{\"humidity_percent\":%.1f}",
        (double)humidity_pct);
#else
    (void)humidity_pct;
    return snprintf(buf, buf_len,
        "{\"temperature_c\":%.2f}",
        (double)temp_c);
#endif
}

/* ---- Home Assistant MQTT Discovery -------------------------------- */

static const char home_assistant_discovery_json[] =
    "{"
    "\"dev\":{"
        "\"ids\":\"" DEVICE_ID "\","
        "\"name\":\"" DEVICE_NAME "\","
        "\"mf\":\"Raspberry Pi\","
        "\"mdl\":\"" DEVICE_MODEL "\","
        "\"sw\":\"pq-mqtt-1.0\""
    "},"
    "\"o\":{"
        "\"name\":\"pico-pqc-mqtt\","
        "\"sw\":\"1.0\""
    "},"
    "\"state_topic\":\"" STATE_TOPIC "\","
    "\"availability_topic\":\"" STATUS_TOPIC "\","
    "\"payload_available\":\"online\","
    "\"payload_not_available\":\"offline\","
    "\"qos\":0,"
    "\"cmps\":{"
#if defined(MQTT_BOARD_PICO2W)
        "\"humidity\":{"
            "\"p\":\"sensor\","
            "\"unique_id\":\"" DEVICE_ID "_humidity\","
            "\"device_class\":\"humidity\","
            "\"state_class\":\"measurement\","
            "\"unit_of_measurement\":\"%\","
            "\"value_template\":\"{{ value_json.humidity_percent }}\""
        "}"
#else
        "\"temperature\":{"
            "\"p\":\"sensor\","
            "\"unique_id\":\"" DEVICE_ID "_temperature\","
            "\"device_class\":\"temperature\","
            "\"state_class\":\"measurement\","
            "\"unit_of_measurement\":\"\\u00b0C\","
            "\"value_template\":\"{{ value_json.temperature_c }}\""
        "}"
#endif
    "}"
    "}";

static bool publish_home_assistant_discovery(mqtt_client_t *mqtt) {
    bool ok = mqtt_publish_retained(
        mqtt, DISCOVERY_TOPIC,
        (const uint8_t *)home_assistant_discovery_json,
        strlen(home_assistant_discovery_json));
    printf("[mqtt] Home Assistant discovery %s -> %s\n",
           ok ? "OK" : "FAIL", DISCOVERY_TOPIC);
    return ok;
}

static bool publish_availability(mqtt_client_t *mqtt, const char *status) {
    bool ok = mqtt_publish_retained(
        mqtt, STATUS_TOPIC, (const uint8_t *)status, strlen(status));
    printf("[mqtt] availability %s -> %s\n",
           ok ? "OK" : "FAIL", status);
    return ok;
}

/* ---- WiFi connect -------------------------------------------------- */

static const char *wifi_status_name(int status) {
    switch (status) {
    case CYW43_LINK_DOWN:    return "link down";
    case CYW43_LINK_JOIN:    return "joining";
    case CYW43_LINK_NOIP:    return "joined, waiting for IP";
    case CYW43_LINK_UP:      return "connected with IP";
    case CYW43_LINK_FAIL:    return "connection failed";
    case CYW43_LINK_NONET:   return "network not found";
    case CYW43_LINK_BADAUTH: return "bad password/auth";
    default:                 return "unknown";
    }
}

static bool has_valid_ip(void) {
    return netif_default != NULL &&
           !ip4_addr_isany_val(*netif_ip4_addr(netif_default));
}

static bool wifi_connect(void) {
#if MQTT_BENCH_COMPACT_OUTPUT
    printf("[wifi] connecting\n");
#endif
    for (int attempt = 1; attempt <= 5; attempt++) {
#if !MQTT_BENCH_COMPACT_OUTPUT
        printf("[wifi] Attempt %d/5: connecting to \"%s\" using WPA2-AES...\n",
               attempt, WIFI_SSID);
#endif

        int err = cyw43_arch_wifi_connect_async(
            WIFI_SSID, WIFI_PASS, CYW43_AUTH_WPA2_AES_PSK);
        if (err) {
            printf("[wifi] connect attempt %d failed to start: %d\n", attempt, err);
            sleep_ms(3000);
            continue;
        }

        absolute_time_t deadline = make_timeout_time_ms(60000);
        int last_status = 999;
        while (!time_reached(deadline)) {
            int status =
                cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);

            if (status != last_status) {
#if !MQTT_BENCH_COMPACT_OUTPUT
                printf("[wifi] status: %s (%d), IP=%s\n",
                       wifi_status_name(status), status,
                       netif_default
                           ? ip4addr_ntoa(netif_ip4_addr(netif_default))
                           : "no-netif");
#endif
                last_status = status;
            }

            if (status == CYW43_LINK_UP && has_valid_ip()) {
                printf("[wifi] connected: %s\n",
                       ip4addr_ntoa(netif_ip4_addr(netif_default)));
                return true;
            }

            if (status == CYW43_LINK_BADAUTH ||
                status == CYW43_LINK_FAIL ||
                status == CYW43_LINK_NONET) {
                printf("[wifi] connect attempt %d failed: %s (%d)\n",
                       attempt, wifi_status_name(status), status);
                break;
            }

            sleep_ms(500);
        }

#if !MQTT_BENCH_COMPACT_OUTPUT
        printf("[wifi] waiting 3 s before retry...\n");
#endif
        sleep_ms(3000);
    }
    printf("[wifi] all attempts failed\n");
    return false;
}

/* ---- Network time -------------------------------------------------- */

static bool current_time_is_sane(time_t *now_out) {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) return false;
    if (now_out) *now_out = tv.tv_sec;
    return tv.tv_sec >= (time_t)MIN_VALID_UNIX_TIME;
}

static bool sync_time_with_sntp(void) {
    time_t now = 0;
    if (current_time_is_sane(&now)) {
#if MQTT_BENCH_COMPACT_OUTPUT
        printf("[time] synchronized clock available\n");
#else
        printf("[time] clock already set: %ld\n", (long)now);
#endif
        return true;
    }

    printf("[time] synchronizing UTC clock\n");
    cyw43_arch_lwip_begin();
    sntp_time_set = false;
    if (sntp_enabled()) {
        sntp_stop();
    }
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    for (size_t i = 0; i < sizeof(NTP_SERVER_NAMES) / sizeof(NTP_SERVER_NAMES[0]); i++) {
#if !MQTT_BENCH_COMPACT_OUTPUT
        printf("[time] SNTP server %u: %s\n", (unsigned)i, NTP_SERVER_NAMES[i]);
#endif
        sntp_setservername((u8_t)i, NTP_SERVER_NAMES[i]);
    }
    sntp_init();
    cyw43_arch_lwip_end();

    absolute_time_t deadline = make_timeout_time_ms(NTP_SYNC_TIMEOUT_MS);
    while (!time_reached(deadline)) {
        if (sntp_time_set && current_time_is_sane(&now)) {
#if MQTT_BENCH_COMPACT_OUTPUT
            printf("[time] synchronized\n");
#else
            printf("[time] SNTP synced, unix time: %ld\n", (long)now);
#endif
            return true;
        }
        sleep_ms(250);
    }

    printf("[time] SNTP sync timed out; refusing TLS cert validation without real time\n");
    return false;
}

/* ---- TLS handshake benchmark mode ----------------------------------
 * Built when TLS_BENCH_ITERS > 0 (cmake -DTLS_BENCH_ITERS=30). Instead of
 * the MQTT publish loop, the firmware repeats connect/close cycles and
 * reports latency (total, crypto, network-wait) and handshake traffic
 * statistics in the same style as the signature benchmarks. */

#ifndef TLS_BENCH_ITERS
#define TLS_BENCH_ITERS 0
#endif

#if TLS_BENCH_ITERS > 0
#include <stdlib.h>

#ifndef TLS_BENCH_WARMUP
#define TLS_BENCH_WARMUP 3
#endif
#ifndef TLS_BENCH_CAMPAIGN
#define TLS_BENCH_CAMPAIGN 1
#endif
#define TLS_BENCH_COOLDOWN_MS      750

#if defined(MQTT_TRANSPORT_PLAIN)
#  define TLS_BENCH_SCHEME "Plain-MQTT"
#elif defined(MQTT_SCHEME_FALCON512)
#  define TLS_BENCH_SCHEME "Falcon-512"
#elif defined(MQTT_SCHEME_MAYO1)
#  define TLS_BENCH_SCHEME "MAYO-1"
#elif defined(MQTT_SCHEME_SNOVA_24_5_16_4)
#  define TLS_BENCH_SCHEME "SNOVA-24-5-16-4"
#elif defined(MQTT_SCHEME_HAWK512)
#  define TLS_BENCH_SCHEME "HAWK-512"
#elif defined(MQTT_SCHEME_ECDSA_P256)
#  define TLS_BENCH_SCHEME "ECDSA-P256"
#elif defined(MQTT_SCHEME_RSA2048)
#  define TLS_BENCH_SCHEME "RSA-2048"
#else
#  define TLS_BENCH_SCHEME "ML-DSA-44"
#endif

static tls_conn_t *bench_connect(tls_attempt_result_t *result) {
#ifdef MQTT_TRANSPORT_PLAIN
    return tls_connect_plain_attempt(BROKER_HOST, BROKER_PORT, result);
#else
    return tls_connect_attempt(BROKER_HOST, BROKER_PORT,
                               MQTT_CA_CERT_DER,     MQTT_CA_CERT_DER_LEN,
                               MQTT_CLIENT_CERT_DER, MQTT_CLIENT_CERT_DER_LEN,
                               MQTT_CLIENT_KEY_DER,  MQTT_CLIENT_KEY_DER_LEN,
                               result);
#endif
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Linear quantile (Hyndman/Fan type 7), matching the host analyzer. */
static double quantile_sorted(const double *v, unsigned n, double p) {
    if (n == 1) return v[0];
    double pos = p * (double)(n - 1);
    unsigned lo = (unsigned)pos;
    unsigned hi = lo + 1 < n ? lo + 1 : lo;
    double frac = pos - (double)lo;
    return v[lo] + frac * (v[hi] - v[lo]);
}

/* Device-side summary for immediate collection checks. The host analyzer
 * remains authoritative because it combines independent campaigns and reports
 * confidence intervals, reliability, and memory observations. */
static void print_stat_row(const char *metric, double *v, unsigned n) {
    if (n == 0) {
        printf("    %-20s: no successful observations\n", metric);
        return;
    }

    double sum = 0.0, mn = v[0], mx = v[0];
    for (unsigned i = 0; i < n; ++i) {
        sum += v[i];
        if (v[i] < mn) mn = v[i];
        if (v[i] > mx) mx = v[i];
    }
    double mean = sum / (double)n;
    double variance = 0.0;
    for (unsigned i = 0; i < n; ++i) {
        double delta = v[i] - mean;
        variance += delta * delta;
    }
    double stddev = sqrt(variance / (n > 1 ? (double)(n - 1) : 1.0));

    qsort(v, n, sizeof(double), cmp_double);
#if !MQTT_BENCH_COMPACT_OUTPUT
    double q1 = quantile_sorted(v, n, 0.25);
    double median = quantile_sorted(v, n, 0.50);
    double q3 = quantile_sorted(v, n, 0.75);
    double p90 = quantile_sorted(v, n, 0.90);
    printf("    %-20s: median %.2f ms  IQR %.2f [%.2f, %.2f]  "
           "p90 %.2f  min %.2f  max %.2f\n",
           metric, median, q3 - q1, q1, q3, p90, v[0], v[n - 1]);
#endif
    printf("csv_hs_summary," TLS_BENCH_SCHEME "," SIGBENCH_BOARD_NAME
           ",%s,%u,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
           metric, n, mean, stddev, mn, mx, quantile_sorted(v, n, 0.50),
           quantile_sorted(v, n, 0.90),
           quantile_sorted(v, n, 0.99));
}

static bool run_benchmark_attempt(int run, bool warmup,
                                  tls_timings_t *timings_out,
                                  uint64_t *mqtt_us_out,
                                  tls_bandwidth_t *bandwidth_out) {
    tls_attempt_result_t attempt = {0};
    struct timeval attempt_start = {0};
    (void)gettimeofday(&attempt_start, NULL);
    uint64_t start_epoch_ms = (uint64_t)attempt_start.tv_sec * 1000u +
                              (uint64_t)attempt_start.tv_usec / 1000u;
    /* A start marker is retained only for measured attempts: the host
     * analyzer uses it to detect a reset or truncated serial capture. */
    if (!warmup) {
        printf("csv_hs_start," TLS_BENCH_SCHEME "," SIGBENCH_BOARD_NAME
               ",%d,%d,0,%" PRIu64 "\n",
               TLS_BENCH_CAMPAIGN, run, start_epoch_ms);
    }
    runtime_memory_begin();
    tls_conn_t *tls = bench_connect(&attempt);
    bool success = false;
    uint64_t mqtt_us = 0;

    if (tls) {
        attempt.timings = tls_get_timings(tls);
        runtime_memory_set_stage(RUNTIME_MEM_STAGE_MQTT);
        mqtt_client_t mqtt = { .conn = tls };
        int mqtt_error = 0;
        uint64_t mqtt_start = time_us_64();
        success = mqtt_connect_measured_attempt(
            &mqtt, CLIENT_ID, KEEPALIVE_SEC, &mqtt_us, &mqtt_error);
        if (!success && mqtt_us == 0) mqtt_us = time_us_64() - mqtt_start;
        attempt.bandwidth = tls_get_bandwidth(tls);
        if (success) {
            mqtt_disconnect(&mqtt);
        } else {
            attempt.failure_stage = TLS_FAILURE_MQTT;
            attempt.error_code = mqtt_error;
            attempt.timed_out = tls_io_timed_out(tls);
            if (attempt.timed_out) attempt.error_code = TLS_ATTEMPT_ERR_TIMEOUT;
            tls_close(tls);
        }
    }

    runtime_memory_result_t memory = runtime_memory_end();
    double total_ms = (double)(attempt.timings.tcp_us +
                               attempt.timings.tls_us + mqtt_us) / 1000.0;

    if (warmup) {
#if !MQTT_BENCH_COMPACT_OUTPUT
        printf("[bench] warmup %d/%d: %s, total %.2f ms, failure=%s error=%d\n",
               run + 1, TLS_BENCH_WARMUP, success ? "success" : "failure",
               total_ms, tls_failure_stage_name(attempt.failure_stage),
               attempt.error_code);
#endif
    } else {
        printf("csv_hs," TLS_BENCH_SCHEME "," SIGBENCH_BOARD_NAME
               ",%d,%d,%" PRIu64 ",%" PRIu64 ",%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%u,%s,%d,%u,"
               "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
               "%u,%u,%u,%u,%u,%s,%u,"
               "%u,%u,%u,%u,%u,%u\n",
               TLS_BENCH_CAMPAIGN, run,
               start_epoch_ms,
               attempt.tcp_start_epoch_ms,
               (double)attempt.timings.dns_us / 1000.0,
               (double)attempt.timings.tcp_us / 1000.0,
               (double)attempt.timings.tls_us / 1000.0,
               (double)mqtt_us / 1000.0,
               total_ms,
               (double)attempt.timings.tls_crypto_us / 1000.0,
               (double)attempt.timings.tls_net_wait_us / 1000.0,
               success ? 1u : 0u,
               tls_failure_stage_name(attempt.failure_stage),
               attempt.error_code,
               attempt.timed_out ? 1u : 0u,
               memory.heap_capacity_bytes,
               memory.heap_in_use_before_bytes,
               memory.heap_peak_in_use_bytes,
               memory.heap_peak_delta_bytes,
               memory.heap_in_use_after_bytes,
               memory.free_before_bytes,
               memory.free_before_tls_bytes,
               memory.min_free_bytes,
               memory.free_after_bytes,
               memory.maximum_allocation_request_bytes,
               memory.allocation_calls,
               memory.free_calls,
               memory.failed_allocations,
               memory.stack_capacity_bytes,
               memory.stack_high_water_bytes,
               memory.stack_unused_bytes,
               memory.stack_guard_corrupted ? 1u : 0u,
               memory.allocation_failed ? 1u : 0u,
               runtime_memory_stage_name(memory.allocation_failure_stage),
               memory.allocation_failure_bytes,
               (unsigned)attempt.bandwidth.handshake_tx_bytes,
               (unsigned)attempt.bandwidth.handshake_rx_bytes,
               (unsigned)attempt.bandwidth.handshake_tx_calls,
               (unsigned)attempt.bandwidth.handshake_rx_calls,
               (unsigned)attempt.bandwidth.total_tx_bytes,
               (unsigned)attempt.bandwidth.total_rx_bytes);
    }

    if (timings_out) *timings_out = attempt.timings;
    if (mqtt_us_out) *mqtt_us_out = mqtt_us;
    if (bandwidth_out) *bandwidth_out = attempt.bandwidth;
    return success;
}

static int run_handshake_benchmark(void) {
    static double tcp_ms[TLS_BENCH_ITERS];
    static double tls_ms[TLS_BENCH_ITERS];
    static double crypto_ms[TLS_BENCH_ITERS];
    static double net_ms[TLS_BENCH_ITERS];
    static double mqtt_ms[TLS_BENCH_ITERS];
    static double total_connect_ms[TLS_BENCH_ITERS];
    unsigned successes = 0;
    unsigned failures = 0;
    unsigned warmup_successes = 0;
    tls_bandwidth_t last_bandwidth = {0};

#if MQTT_BENCH_COMPACT_OUTPUT
    printf("[bench] ready: scheme=" TLS_BENCH_SCHEME " board=" SIGBENCH_BOARD_NAME
           " campaign=%d\n", TLS_BENCH_CAMPAIGN);
#else
#ifdef MQTT_TRANSPORT_PLAIN
    printf("\n=== Plain MQTT connection benchmark ===\n");
    printf("scheme=" TLS_BENCH_SCHEME "  board=" SIGBENCH_BOARD_NAME
           "  tls=none  broker=%s:%u\n", BROKER_HOST, BROKER_PORT);
#else
    printf("\n=== MQTT over TLS connection benchmark ===\n");
    printf("scheme=" TLS_BENCH_SCHEME "  board=" SIGBENCH_BOARD_NAME
           "  group=X25519MLKEM768  broker=%s:%u\n", BROKER_HOST, BROKER_PORT);
#endif
    printf("campaign=%d  warmup=%d  attempted=%d\n",
           TLS_BENCH_CAMPAIGN, TLS_BENCH_WARMUP, TLS_BENCH_ITERS);
#endif
    printf("csv_hs_header,scheme,board,campaign,run,start_epoch_ms,tcp_start_epoch_ms,dns_ms,tcp_ms,tls_ms,mqtt_ms,"
           "total_ms,crypto_ms,net_wait_ms,success,failure_stage,error_code,timeout,"
           "heap_capacity_bytes,heap_in_use_before_bytes,heap_peak_in_use_bytes,"
           "heap_peak_delta_bytes,heap_in_use_after_bytes,free_before_bytes,"
           "free_before_tls_bytes,min_free_bytes,free_after_bytes,"
           "maximum_allocation_request_bytes,allocation_calls,free_calls,failed_allocations,"
           "stack_capacity_bytes,stack_high_water_bytes,stack_unused_bytes,"
           "stack_guard_corrupted,alloc_failed,alloc_failure_stage,"
           "alloc_failure_bytes,hs_tx_bytes,hs_rx_bytes,hs_tx_writes,hs_rx_reads,"
           "total_tx_bytes,total_rx_bytes\n");
#if defined(MQTT_TRANSPORT_PLAIN) && !MQTT_BENCH_COMPACT_OUTPUT
    printf("[bench] plain mode: tls/crypto/net_wait columns remain 0; "
           "total_ms is tcp_ms + mqtt_ms\n");
#endif

    for (int i = 0; i < TLS_BENCH_WARMUP; ++i) {
        if (run_benchmark_attempt(i, true, NULL, NULL, NULL)) {
            warmup_successes++;
        }
        sleep_ms(TLS_BENCH_COOLDOWN_MS);
    }
    printf("[bench] warm-up complete: %u/%d successful\n",
           warmup_successes, TLS_BENCH_WARMUP);
    printf("[bench] benchmarking: %d attempted connections\n", TLS_BENCH_ITERS);

    for (int i = 0; i < TLS_BENCH_ITERS; ++i) {
        tls_timings_t ht = {0};
        uint64_t mqtt_us = 0;
        tls_bandwidth_t bandwidth = {0};
        bool ok = run_benchmark_attempt(i, false, &ht, &mqtt_us, &bandwidth);
        if (ok) {
            unsigned j = successes++;
            tcp_ms[j] = (double)ht.tcp_us / 1000.0;
            tls_ms[j] = (double)ht.tls_us / 1000.0;
            crypto_ms[j] = (double)ht.tls_crypto_us / 1000.0;
            net_ms[j] = (double)ht.tls_net_wait_us / 1000.0;
            mqtt_ms[j] = (double)mqtt_us / 1000.0;
            total_connect_ms[j] =
                (double)(ht.tcp_us + ht.tls_us + mqtt_us) / 1000.0;
            last_bandwidth = bandwidth;
        } else {
            failures++;
        }
        sleep_ms(TLS_BENCH_COOLDOWN_MS);
    }

    printf("\n--- summary over %u successful connections (%d attempted) ---\n",
           successes, TLS_BENCH_ITERS);
    printf("[bench] attempted=%d successful=%u failures=%u success_rate=%.1f%%\n",
           TLS_BENCH_ITERS, successes, failures,
           100.0 * (double)successes / (double)TLS_BENCH_ITERS);
    printf("csv_hs_summary_header,scheme,board,metric,n,mean_ms,std_ms,"
           "min_ms,max_ms,median_ms,p90_ms,p99_ms\n");
    print_stat_row("tcp", tcp_ms, successes);
    print_stat_row("tls", tls_ms, successes);
    print_stat_row("mqtt_connect", mqtt_ms, successes);
    print_stat_row("mqtts_total_connect", total_connect_ms, successes);
    print_stat_row("crypto", crypto_ms, successes);
    print_stat_row("net_wait", net_ms, successes);
    if (successes > 0) {
#if !MQTT_BENCH_COMPACT_OUTPUT
        printf("    handshake traffic: %u B up in %u writes, %u B down in %u reads, "
               "%u B total\n",
               (unsigned)last_bandwidth.handshake_tx_bytes,
               (unsigned)last_bandwidth.handshake_tx_calls,
               (unsigned)last_bandwidth.handshake_rx_bytes,
               (unsigned)last_bandwidth.handshake_rx_calls,
               (unsigned)(last_bandwidth.handshake_tx_bytes +
                          last_bandwidth.handshake_rx_bytes));
#endif
        printf("csv_hs_traffic," TLS_BENCH_SCHEME "," SIGBENCH_BOARD_NAME
               ",%u,%u,%u,%u,%u,%u,%u\n",
               (unsigned)last_bandwidth.handshake_tx_bytes,
               (unsigned)last_bandwidth.handshake_rx_bytes,
               (unsigned)(last_bandwidth.handshake_tx_bytes +
                          last_bandwidth.handshake_rx_bytes),
               (unsigned)last_bandwidth.handshake_tx_calls,
               (unsigned)last_bandwidth.handshake_rx_calls,
               (unsigned)last_bandwidth.total_tx_bytes,
               (unsigned)last_bandwidth.total_rx_bytes);
    }
    printf("[bench] done\n");
    return 0;
}
#endif /* TLS_BENCH_ITERS > 0 */

/* ---- Main ---------------------------------------------------------- */

int main(void) {
    stdio_init_all();
    sleep_ms(2000);   /* wait for USB CDC to enumerate */
#if !MQTT_BENCH_COMPACT_OUTPUT
#ifdef MQTT_TRANSPORT_PLAIN
    printf("\n=== " SIGBENCH_BOARD_NAME " MQTT client (plain TCP, no TLS) ===\n");
#elif defined(MQTT_SCHEME_FALCON512)
    printf("\n=== " SIGBENCH_BOARD_NAME " PQ-MQTT client (Falcon-512 mTLS) ===\n");
#elif defined(MQTT_SCHEME_MAYO1)
    printf("\n=== " SIGBENCH_BOARD_NAME " PQ-MQTT client (MAYO-1 mTLS) ===\n");
#elif defined(MQTT_SCHEME_SNOVA_24_5_16_4)
    printf("\n=== " SIGBENCH_BOARD_NAME " PQ-MQTT client (SNOVA-24-5-16-4 mTLS) ===\n");
#elif defined(MQTT_SCHEME_HAWK512)
    printf("\n=== " SIGBENCH_BOARD_NAME " PQ-MQTT client (HAWK-512 mTLS) ===\n");
#elif defined(MQTT_SCHEME_ECDSA_P256)
    printf("\n=== " SIGBENCH_BOARD_NAME " PQ-MQTT client (ECDSA P-256 mTLS) ===\n");
#elif defined(MQTT_SCHEME_RSA2048)
    printf("\n=== " SIGBENCH_BOARD_NAME " PQ-MQTT client (RSA-2048 mTLS) ===\n");
#else
    printf("\n=== " SIGBENCH_BOARD_NAME " PQ-MQTT client (ML-DSA-44 mTLS) ===\n");
#endif
#endif

    /* Temperature sensor */
    adc_init();
    adc_set_temp_sensor_enabled(true);

    /* WiFi + lwIP run continuously in the background. */
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[wifi] regulatory country: Singapore (SG)\n");
#endif
    if (cyw43_arch_init_with_country(CYW43_COUNTRY_SINGAPORE)) {
        printf("[wifi] cyw43 init failed\n");
        return 1;
    }
    cyw43_arch_enable_sta_mode();
#if !MQTT_BENCH_COMPACT_OUTPUT
    cyw43_state.trace_flags |= CYW43_TRACE_ASYNC_EV;
    printf("[wifi] background CYW43/lwIP worker enabled\n");
#endif

    if (!wifi_connect()) {
        cyw43_arch_deinit();
        return 1;
    }

#if TLS_BENCH_ITERS > 0
    if (!sync_time_with_sntp()) {
        cyw43_arch_deinit();
        return 1;
    }
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[time] synchronized clock retained for serial/pcap attempt matching\n");
#endif
#elif defined(MQTT_TRANSPORT_PLAIN)
    printf("[time] skipping SNTP sync; plain MQTT has no certificate validation\n");
#else
    if (!sync_time_with_sntp()) {
        cyw43_arch_deinit();
        return 1;
    }
#endif

    /* Verify certificates were populated */
#ifdef MQTT_TRANSPORT_PLAIN
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[plain] TLS certificates are not used\n");
#endif
#else
    if (MQTT_CA_CERT_DER_LEN <= 1 ||
        MQTT_CLIENT_CERT_DER_LEN <= 1 ||
        MQTT_CLIENT_KEY_DER_LEN  <= 1) {
        printf("[main] ERROR: placeholder certificates in mqtt_client/certs\n"
               "       Import a lab certificate with tools/import_client_cert.sh.\n");
        cyw43_arch_deinit();
        return 1;
    }
#if !MQTT_BENCH_COMPACT_OUTPUT
    printf("[cert] CA=%u bytes, client cert=%u bytes, client key=%u bytes\n",
           (unsigned)MQTT_CA_CERT_DER_LEN,
           (unsigned)MQTT_CLIENT_CERT_DER_LEN,
           (unsigned)MQTT_CLIENT_KEY_DER_LEN);
#ifdef MQTT_SCHEME_HAWK512
    printf("[cert] HAWK OID DER: 06 0a 2b 06 01 04 01 86 8d 1f 01 01\n");
    printf("[cert] CA DER prefix: %02x %02x %02x %02x %02x %02x %02x %02x\n",
           MQTT_CA_CERT_DER[0], MQTT_CA_CERT_DER[1],
           MQTT_CA_CERT_DER[2], MQTT_CA_CERT_DER[3],
           MQTT_CA_CERT_DER[4], MQTT_CA_CERT_DER[5],
           MQTT_CA_CERT_DER[6], MQTT_CA_CERT_DER[7]);
#elif defined(MQTT_SCHEME_FALCON512)
    printf("[cert] Falcon-512 OID DER: 06 05 2b ce 0f 03 0b\n");
    printf("[cert] Falcon-512 TLS SignatureScheme: 0xfed7\n");
#elif defined(MQTT_SCHEME_MAYO1)
    printf("[cert] MAYO-1 OID DER: 06 06 2b ce 0f 08 01 03\n");
    printf("[cert] MAYO-1 TLS SignatureScheme: 0xff32\n");
#elif defined(MQTT_SCHEME_SNOVA_24_5_16_4)
    printf("[cert] SNOVA-24-5-16-4 OID DER: 06 06 2b ce 0f 0a 01 01\n");
    printf("[cert] SNOVA-24-5-16-4 TLS SignatureScheme: 0xff3a\n");
#endif
#endif
#endif

#if TLS_BENCH_ITERS > 0
    /* Benchmark mode replaces the MQTT session entirely. */
    int bench_ret = run_handshake_benchmark();
    cyw43_arch_deinit();
    return bench_ret;
#endif

    /* Establish transport connection */
    printf("[main] Connecting to broker %s:%u\n", BROKER_HOST, BROKER_PORT);
#ifdef MQTT_TRANSPORT_PLAIN
    tls_conn_t *tls = tls_connect_plain(BROKER_HOST, BROKER_PORT);
#else
    tls_conn_t *tls = tls_connect(
        BROKER_HOST, BROKER_PORT,
        MQTT_CA_CERT_DER,      MQTT_CA_CERT_DER_LEN,
        MQTT_CLIENT_CERT_DER,  MQTT_CLIENT_CERT_DER_LEN,
        MQTT_CLIENT_KEY_DER,   MQTT_CLIENT_KEY_DER_LEN
    );
#endif
    if (!tls) {
        printf("[main] transport connection failed\n");
        cyw43_arch_deinit();
        return 1;
    }
    tls_timings_t timings = tls_get_timings(tls);
#ifdef MQTT_TRANSPORT_PLAIN
    printf("[plain] DNS: %" PRIu64 " ms  TCP: %" PRIu64
           " ms  TLS handshake: 0 ms\n",
           timings.dns_us / 1000, timings.tcp_us / 1000);
    printf("[plain] TLS disabled; MQTT CONNECT/CONNACK carries the application latency\n");
#else
    printf("[tls] DNS: %" PRIu64 " ms  TCP: %" PRIu64 " ms  TLS handshake: %" PRIu64 " ms\n",
           timings.dns_us / 1000, timings.tcp_us / 1000, timings.tls_us / 1000);
    printf("[tls] Handshake split: crypto %" PRIu64 " ms + net wait %" PRIu64 " ms\n",
           timings.tls_crypto_us / 1000, timings.tls_net_wait_us / 1000);
    tls_bandwidth_t bw = tls_get_bandwidth(tls);
    uint64_t tls_handshake_bytes =
        bw.handshake_rx_bytes + bw.handshake_tx_bytes;
    uint64_t tls_handshake_kbit_s =
        (timings.tls_us > 0)
            ? (tls_handshake_bytes * 8u * 1000000u) / timings.tls_us / 1000u
            : 0;
    printf("[tls] Handshake traffic: rx=%" PRIu64 " B  tx=%" PRIu64
           " B  total=%" PRIu64 " B  effective=%" PRIu64 " kbit/s\n",
           bw.handshake_rx_bytes, bw.handshake_tx_bytes,
           tls_handshake_bytes, tls_handshake_kbit_s);
    printf("[tls] Traffic note: TLS record bytes only; excludes TCP/IP/WiFi headers and retransmits\n");
#endif

    /* MQTT handshake */
    mqtt_client_t mqtt = { .conn = tls };
    static const char offline_status[] = "offline";
    if (!mqtt_connect_with_will(&mqtt, CLIENT_ID, KEEPALIVE_SEC,
                                STATUS_TOPIC,
                                (const uint8_t *)offline_status,
                                strlen(offline_status), true)) {
        printf("[main] MQTT CONNECT failed\n");
        mqtt_disconnect(&mqtt);
        cyw43_arch_deinit();
        return 1;
    }
    if (!publish_home_assistant_discovery(&mqtt) ||
        !publish_availability(&mqtt, "online")) {
        mqtt_disconnect(&mqtt);
        cyw43_arch_deinit();
        return 1;
    }

    printf("[main] Publishing sensor state to \"%s\" every %u ms\n",
           STATE_TOPIC, PUB_INTERVAL_MS);

    /* Publish loop */
    char    payload[128];
    uint32_t last_pub = 0;
    while (true) {
        uint32_t now = to_ms_since_boot(get_absolute_time());
        if (now - last_pub >= PUB_INTERVAL_MS) {
            last_pub = now;
            float temp = read_temperature_c();
            float humidity = read_humidity_percent();
            int   plen = build_payload(payload, sizeof(payload), temp, humidity);
            if (plen > 0) {
                bool ok = mqtt_publish(&mqtt, STATE_TOPIC,
                                       (uint8_t *)payload, (size_t)plen);
                printf("[mqtt] publish %s -> %s\n",
                       ok ? "OK" : "FAIL", payload);
                if (!ok) break;
            }
        }
        sleep_ms(10);
    }

    printf("[main] Disconnecting\n");
    publish_availability(&mqtt, "offline");
    mqtt_disconnect(&mqtt);
    cyw43_arch_deinit();
    return 0;
}
