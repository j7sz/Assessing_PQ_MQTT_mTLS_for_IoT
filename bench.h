/* bench.h - minimal, pqm4-style timing + statistics harness for the Pico SDK.
 *
 * Authoritative timing source is the RP2040/RP2350 64-bit hardware timer
 * (time_us_64), which is rock-solid on both boards. Cycle counts are derived
 * from a free-running SysTick counter (present on both Cortex-M0+ and M33),
 * matching how pqm4 measures on STM32. Results are reported as mean / stddev /
 * min / max over N iterations, plus ops/s, mirroring the paper's reporting.
 */
#ifndef BENCH_H
#define BENCH_H

#include <stdint.h>
#include <stddef.h>

#ifndef BENCH_ITERS
#define BENCH_ITERS 100      /* measured iterations (paper uses 30; pqm4 more) */
#endif
#ifndef BENCH_WARMUP
#define BENCH_WARMUP 8       /* discarded warm-up iterations */
#endif
#ifndef BENCH_MAX_ITERS
#define BENCH_MAX_ITERS 256  /* static buffer cap */
#endif

typedef struct {
    unsigned n;
    double mean_ms, std_ms, min_ms, max_ms, median_ms;
    double mean_cyc, std_cyc, min_cyc, max_cyc, median_cyc;
    double ops_per_s;
} bench_stats_t;

/* Configure the cycle counter. Call once at startup. */
void     bench_init(void);

/* Monotonic counters. */
uint64_t bench_cycles(void);
uint64_t bench_us(void);
uint32_t bench_clk_hz(void);

/* The operation to benchmark. Return 0 on success, nonzero to flag an error
 * (an error aborts the run). ctx is opaque user data. */
typedef int (*bench_fn_t)(void *ctx);

/* Run fn(ctx) `warmup` times (discarded) then `iters` times (measured).
 * Fills *out. Returns 0 on success, -1 if any iteration reported an error. */
int  bench_run(bench_fn_t fn, void *ctx,
               unsigned iters, unsigned warmup, bench_stats_t *out);

/* Pretty-print one stats block over stdio. */
void bench_print(const char *label, const bench_stats_t *s);

#endif /* BENCH_H */
