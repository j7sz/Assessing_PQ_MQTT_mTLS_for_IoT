/* snova_verify_main.c - verify-only SNOVA KAT benchmark for memory-limited boards.
 *
 * SNOVA signing expands too much state for RP2040/Pico W. This driver uses a
 * static known-answer signed message and benchmarks verification only.
 */
#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"

#include "api.h"
#include "bench.h"
#include "primitive_memory_report.h"
#include "symmetric.h"
#include STATIC_VERIFY_HEADER
#ifdef STATIC_EXPANDED_PK_HEADER
#include STATIC_EXPANDED_PK_HEADER
#define SNOVA_VERIFY_IMPLEMENTATION "SNOVA 2.3 core verify, host-expanded public key"
#else
#define SNOVA_VERIFY_IMPLEMENTATION "SNOVA 2.3 optimized portable C (SHAKE)"
#endif

static uint8_t g_sm[sizeof(STATIC_SIG) + sizeof(STATIC_MSG)];
static uint8_t g_recovered[sizeof(STATIC_MSG)];

static int verify_once(const uint8_t *signed_message) {
#ifdef STATIC_EXPANDED_PK_HEADER
    uint8_t digest[BYTES_DIGEST];
    shake256(digest, sizeof(digest), signed_message + CRYPTO_BYTES,
             sizeof(g_sm) - CRYPTO_BYTES);
    int rc = SNOVA_NAMESPACE(verify)(STATIC_EXPANDED_PK, signed_message,
                                     digest, sizeof(digest));
    if (rc != 0) return rc;
    memcpy(g_recovered, signed_message + CRYPTO_BYTES, sizeof(STATIC_MSG));
    return memcmp(g_recovered, STATIC_MSG, sizeof(STATIC_MSG)) == 0 ? 0 : -1;
#else
    unsigned long long recovered_len = 0;
    int rc = crypto_sign_open(g_recovered, &recovered_len, signed_message,
                              sizeof(g_sm), STATIC_PK);
    if (rc != 0 || recovered_len != sizeof(STATIC_MSG)) {
        return rc ? rc : -1;
    }
    return memcmp(g_recovered, STATIC_MSG, sizeof(STATIC_MSG)) == 0 ? 0 : -1;
#endif
}

static int verify_iter(void *ctx) {
    (void)ctx;
    return verify_once(g_sm);
}

int main(void) {
    stdio_init_all();

    for (int i = 0; i < 30 && !stdio_usb_connected(); i++)
        sleep_ms(100);
    sleep_ms(500);

    bench_init();

    memcpy(g_sm, STATIC_SIG, sizeof(STATIC_SIG));
    memcpy(g_sm + sizeof(STATIC_SIG), STATIC_MSG, sizeof(STATIC_MSG));

    printf("\n==================================================\n");
    printf(" PQC signature benchmark : %s verify-only\n", SNOVA_DISPLAY_NAME);
    printf("--------------------------------------------------\n");
    printf(" clk_sys    : %.2f MHz\n", bench_clk_hz() / 1e6);
    printf(" board      : %s\n", SIGBENCH_BOARD_NAME);
#ifdef STATIC_EXPANDED_PK_HEADER
    printf(" impl       : " SNOVA_VERIFY_IMPLEMENTATION "\n");
#else
    printf(" impl       : " SNOVA_VERIFY_IMPLEMENTATION "\n");
#endif
    printf(" params     : %s\n", CRYPTO_ALGNAME);
    printf(" pk bytes   : %u\n", (unsigned)CRYPTO_PUBLICKEYBYTES);
    printf(" sig bytes  : %u\n", (unsigned)CRYPTO_BYTES);
    printf(" msg bytes  : %u\n", (unsigned)sizeof(STATIC_MSG));
    printf(" iters      : %d (warmup %d)\n", BENCH_ITERS, BENCH_WARMUP);
    printf("==================================================\n");
    printf("PHASE,kat_verify,start\n");
    stdio_flush();

    int rc = verify_once(g_sm);
    if (rc != 0) {
        printf("ERROR: official KAT verification failed, rc=%d\n", rc);
        stdio_flush();
        while (1) tight_loop_contents();
    }
    printf("PHASE,kat_verify,success\n");
    stdio_flush();

    bench_stats_t s;
    primitive_memory_start(SNOVA_DISPLAY_NAME, "verify");
    rc = bench_run(verify_iter, NULL, BENCH_ITERS, BENCH_WARMUP, &s);
    primitive_memory_finish(SNOVA_DISPLAY_NAME, "verify");
    if (rc != 0) {
        printf("ERROR: verification benchmark failed, rc=%d\n", rc);
        while (1) tight_loop_contents();
    }
    bench_print("verify", &s);
    printf("RESULT,%s,%s,%s,%s,%s,%u,%u,%u,%u,%u,verify,%u,"
           "%.4f,%.4f,%.4f,%.4f,%.4f,%.0f,%.0f,%.2f\n",
           SNOVA_DISPLAY_NAME, CRYPTO_ALGNAME, SNOVA_VERIFY_IMPLEMENTATION,
           "verify-only on Pico W", SIGBENCH_BOARD_NAME, bench_clk_hz(),
           (unsigned)sizeof(STATIC_MSG), (unsigned)CRYPTO_PUBLICKEYBYTES,
           (unsigned)CRYPTO_SECRETKEYBYTES, (unsigned)CRYPTO_BYTES, s.n,
           s.mean_ms, s.std_ms, s.min_ms, s.max_ms, s.median_ms,
           s.mean_cyc, s.median_cyc, s.ops_per_s);

    g_sm[0] ^= 0x01;
    rc = verify_once(g_sm);
    g_sm[0] ^= 0x01;
    if (rc == 0) {
        printf("ERROR: tampered KAT signature accepted\n");
        while (1) tight_loop_contents();
    }
    printf(" sanity: tampered=%d (expect nonzero) -> PASS\n", rc);
    printf("=== DONE: %s verify-only ===\n", SNOVA_DISPLAY_NAME);
    while (1) tight_loop_contents();
}
