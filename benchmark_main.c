/* benchmark_main.c - scheme-agnostic driver.
 *
 * Flow:
 *   1. bring up USB serial + cycle counter
 *   2. print scheme info (name, key/sig sizes, clock)
 *   3. benchmark SIGNING   over the static SK            (excludes keygen)
 *   4. produce one valid signature (unmeasured)
 *   5. benchmark VERIFYING that signature against static PK
 *   6. correctness sanity check (valid sig passes, tampered sig fails)
 *
 * Build one binary per scheme; each links exactly one adapter + that scheme's
 * PQClean sources + its embedded static keypair.
 */
#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "hardware/clocks.h"

#include "bench.h"
#include "runtime_memory.h"
#include "scheme.h"

#ifndef MSG_LEN
#define MSG_LEN 32          /* fixed test message length (bytes) */
#endif

#ifndef SIG_BUF
#define SIG_BUF 65536       /* override per target to save RAM */
#endif

static uint8_t g_msg[MSG_LEN];
static uint8_t g_sig[SIG_BUF];
static size_t  g_siglen;

static int sign_iter(void *ctx) {
    (void)ctx;
    return scheme_do_sign(g_sig, &g_siglen, g_msg, MSG_LEN);
}

static int verify_iter(void *ctx) {
    (void)ctx;
    /* verify the SAME fixed signature each time; must not modify g_sig */
    return scheme_do_verify(g_sig, g_siglen, g_msg, MSG_LEN);
}

static void print_memory_result(const char *operation,
                                const runtime_memory_result_t *m) {
    printf("MEMORY,%s,%s,%s,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
           "%u,%u,%u,%u,%u,%s,%u\n",
           scheme_name(), SIGBENCH_BOARD_NAME, operation,
           m->heap_capacity_bytes, m->heap_in_use_before_bytes,
           m->heap_peak_in_use_bytes, m->heap_peak_delta_bytes,
           m->heap_in_use_after_bytes, m->free_before_bytes,
           m->min_free_bytes, m->free_after_bytes,
           m->maximum_allocation_request_bytes, m->allocation_calls,
           m->free_calls, m->failed_allocations, m->stack_capacity_bytes,
           m->stack_high_water_bytes, m->stack_unused_bytes,
           m->stack_guard_corrupted ? 1u : 0u,
           m->allocation_failed ? 1u : 0u,
           runtime_memory_stage_name(m->allocation_failure_stage),
           m->allocation_failure_bytes);
}

int main(void) {
    stdio_init_all();

    /* Give the host USB stack a moment; proceed even if nobody is listening. */
    for (int i = 0; i < 30 && !stdio_usb_connected(); i++)
        sleep_ms(100);
    sleep_ms(500);

    bench_init();

    if (scheme_init() != 0) {
        printf("FATAL: scheme initialization failed for %s\n", scheme_name());
        while (1) tight_loop_contents();
    }

    if (scheme_sig_max_bytes() > SIG_BUF) {
        printf("FATAL: SIG_BUF too small for %s (need %u)\n",
               scheme_name(), (unsigned)scheme_sig_max_bytes());
        while (1) tight_loop_contents();
    }

    for (size_t i = 0; i < MSG_LEN; i++) g_msg[i] = (uint8_t)i;

    printf("\n==================================================\n");
    printf(" PQC signature benchmark : %s\n", scheme_name());
    printf("--------------------------------------------------\n");
    printf(" clk_sys    : %.2f MHz\n", bench_clk_hz() / 1e6);
    printf(" board      : %s\n", SIGBENCH_BOARD_NAME);
    printf(" impl       : %s\n", scheme_implementation());
    printf(" params     : %s\n", scheme_parameter_set());
    printf(" status     : %s\n", scheme_status());
    printf(" NIST level : %u\n", scheme_nist_level());
    printf(" pk bytes   : %u\n", (unsigned)scheme_pk_bytes());
    printf(" sk bytes   : %u\n", (unsigned)scheme_sk_bytes());
    printf(" sig max B  : %u\n", (unsigned)scheme_sig_max_bytes());
    printf(" msg bytes  : %u\n", (unsigned)MSG_LEN);
    printf(" iters      : %d (warmup %d)\n", BENCH_ITERS, BENCH_WARMUP);
    printf("==================================================\n");
    printf("CSV_HEADER,scheme,params,impl,status,board,clock_hz,msg_bytes,"
           "pk_bytes,sk_bytes,sig_bytes,operation,n,mean_ms,std_ms,min_ms,"
           "max_ms,median_ms,mean_cycles,median_cycles,ops_per_s\n");
    printf("MEMORY_HEADER,scheme,board,operation,heap_capacity_bytes,"
           "heap_in_use_before_bytes,heap_peak_in_use_bytes,heap_peak_delta_bytes,"
           "heap_in_use_after_bytes,free_before_bytes,min_free_bytes,free_after_bytes,"
           "maximum_allocation_request_bytes,allocation_calls,free_calls,failed_allocations,"
           "stack_capacity_bytes,stack_high_water_bytes,stack_unused_bytes,"
           "stack_guard_corrupted,alloc_failed,alloc_failure_stage,alloc_failure_bytes\n");

    bench_stats_t s;

    /* --- SIGN ------------------------------------------------------------- */
    printf("MEMORY_START,%s,%s,sign\n", scheme_name(), SIGBENCH_BOARD_NAME);
    runtime_memory_begin();
    runtime_memory_set_stage(RUNTIME_MEM_STAGE_PRIMITIVE_SIGN);
    int rc = bench_run(sign_iter, NULL, BENCH_ITERS, BENCH_WARMUP, &s);
    runtime_memory_result_t sign_memory = runtime_memory_end();
    print_memory_result("sign", &sign_memory);
    if (rc != 0) {
        printf("ERROR: signing failed, implementation return code=%d\n", rc);
        while (1) tight_loop_contents();
    }
    printf(" actual sig len: %u bytes\n", (unsigned)g_siglen);
    bench_print("sign", &s);
    printf("RESULT,%s,%s,%s,%s,%s,%u,%u,%u,%u,%u,sign,%u,"
           "%.4f,%.4f,%.4f,%.4f,%.4f,%.0f,%.0f,%.2f\n",
           scheme_name(), scheme_parameter_set(), scheme_implementation(),
           scheme_status(), SIGBENCH_BOARD_NAME, bench_clk_hz(), (unsigned)MSG_LEN,
           (unsigned)scheme_pk_bytes(), (unsigned)scheme_sk_bytes(),
           (unsigned)g_siglen, s.n, s.mean_ms, s.std_ms, s.min_ms, s.max_ms,
           s.median_ms, s.mean_cyc, s.median_cyc, s.ops_per_s);

    /* --- prepare one fixed, valid signature for the verify benchmark ------ */
    if (scheme_do_sign(g_sig, &g_siglen, g_msg, MSG_LEN) != 0) {
        printf("ERROR: could not produce reference signature\n");
        while (1) tight_loop_contents();
    }

    /* --- VERIFY ----------------------------------------------------------- */
    printf("MEMORY_START,%s,%s,verify\n", scheme_name(), SIGBENCH_BOARD_NAME);
    runtime_memory_begin();
    runtime_memory_set_stage(RUNTIME_MEM_STAGE_PRIMITIVE_VERIFY);
    rc = bench_run(verify_iter, NULL, BENCH_ITERS, BENCH_WARMUP, &s);
    runtime_memory_result_t verify_memory = runtime_memory_end();
    print_memory_result("verify", &verify_memory);
    if (rc != 0) {
        printf("ERROR: verification failed, implementation return code=%d\n", rc);
        while (1) tight_loop_contents();
    }
    bench_print("verify", &s);
    printf("RESULT,%s,%s,%s,%s,%s,%u,%u,%u,%u,%u,verify,%u,"
           "%.4f,%.4f,%.4f,%.4f,%.4f,%.0f,%.0f,%.2f\n",
           scheme_name(), scheme_parameter_set(), scheme_implementation(),
           scheme_status(), SIGBENCH_BOARD_NAME, bench_clk_hz(), (unsigned)MSG_LEN,
           (unsigned)scheme_pk_bytes(), (unsigned)scheme_sk_bytes(),
           (unsigned)g_siglen, s.n, s.mean_ms, s.std_ms, s.min_ms, s.max_ms,
           s.median_ms, s.mean_cyc, s.median_cyc, s.ops_per_s);

    /* --- correctness sanity check ---------------------------------------- */
    int ok  = scheme_do_verify(g_sig, g_siglen, g_msg, MSG_LEN);   /* expect 0 */
    g_sig[0] ^= 0x01;
    int bad = scheme_do_verify(g_sig, g_siglen, g_msg, MSG_LEN);   /* expect != 0 */
    g_sig[0] ^= 0x01;
    printf(" sanity: valid=%d (expect 0), tampered=%d (expect nonzero) -> %s\n",
           ok, bad, (ok == 0 && bad != 0) ? "PASS" : "FAIL");

    printf("=== DONE: %s ===\n", scheme_name());
    while (1) tight_loop_contents();
}
