/* bench.c - implementation of the timing + statistics harness. */
#include "bench.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "pico/stdlib.h"
#include "pico/time.h"
#include "hardware/clocks.h"
#include "hardware/structs/systick.h"

/* ---- Free-running cycle counter via SysTick -------------------------------
 * SysTick is a 24-bit down-counter present on both Cortex-M0+ (RP2040) and
 * Cortex-M33 (RP2350). We run it free-running from the processor clock and
 * count wraps in the SysTick exception handler, giving a 56-bit cycle count.
 *
 * NOTE: this claims SysTick for the whole program. If you later add an RTOS
 * (e.g. FreeRTOS) that uses SysTick for its tick, disable this counter (build
 * with -DBENCH_NO_SYSTICK) and rely on the microsecond timer only.
 */
#define SYSTICK_RELOAD 0x00FFFFFFu

static volatile uint32_t g_wraps;

#ifndef BENCH_NO_SYSTICK
/* Pico SDK weakly defines isr_systick; defining it here overrides it. */
void isr_systick(void) { g_wraps++; }
#endif

void bench_init(void) {
    g_wraps = 0;
#ifndef BENCH_NO_SYSTICK
    systick_hw->csr = 0;                 /* disable while configuring        */
    systick_hw->rvr = SYSTICK_RELOAD;    /* reload value (full 24-bit range) */
    systick_hw->cvr = 0;                 /* clear current value + COUNTFLAG  */
    /* bit0 ENABLE, bit1 TICKINT (exception on wrap), bit2 CLKSOURCE=proc clk */
    systick_hw->csr = (1u << 2) | (1u << 1) | (1u << 0);
#endif
}

uint64_t bench_cycles(void) {
#ifndef BENCH_NO_SYSTICK
    uint32_t w1, w2, v;
    do {                                  /* re-read to avoid wrap race       */
        w1 = g_wraps;
        v  = systick_hw->cvr & SYSTICK_RELOAD;
        w2 = g_wraps;
    } while (w1 != w2);
    /* SysTick counts DOWN; elapsed within a period = RELOAD - v, and one full
     * period is (RELOAD + 1) ticks. */
    return ((uint64_t)w1 * (SYSTICK_RELOAD + 1ull)) + (SYSTICK_RELOAD - v);
#else
    /* Derive an approximate cycle count from the microsecond timer. */
    return (bench_us() * (uint64_t)bench_clk_hz()) / 1000000ull;
#endif
}

uint64_t bench_us(void)     { return time_us_64(); }
uint32_t bench_clk_hz(void) { return clock_get_hz(clk_sys); }

/* ---- statistics ----------------------------------------------------------- */
static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

int bench_run(bench_fn_t fn, void *ctx,
              unsigned iters, unsigned warmup, bench_stats_t *out) {
    static double ms[BENCH_MAX_ITERS];
    static double cyc[BENCH_MAX_ITERS];
    if (!fn || !out || iters == 0) return -1;
    if (iters > BENCH_MAX_ITERS) iters = BENCH_MAX_ITERS;

    for (unsigned i = 0; i < warmup; i++)
        {
            int rc = fn(ctx);
            if (rc) return rc;
        }

    for (unsigned i = 0; i < iters; i++) {
        uint64_t c0 = bench_cycles();
        uint64_t u0 = bench_us();
        int rc = fn(ctx);
        uint64_t u1 = bench_us();
        uint64_t c1 = bench_cycles();
        if (rc) return rc;
        ms[i]  = (double)(u1 - u0) / 1000.0;
        cyc[i] = (double)(c1 - c0);
    }

    double sm = 0, sc = 0;
    double mnm = ms[0], mxm = ms[0], mnc = cyc[0], mxc = cyc[0];
    for (unsigned i = 0; i < iters; i++) {
        sm += ms[i]; sc += cyc[i];
        if (ms[i]  < mnm) mnm = ms[i];   if (ms[i]  > mxm) mxm = ms[i];
        if (cyc[i] < mnc) mnc = cyc[i];  if (cyc[i] > mxc) mxc = cyc[i];
    }
    double mean_ms = sm / iters, mean_cyc = sc / iters;

    double vm = 0, vc = 0;
    for (unsigned i = 0; i < iters; i++) {
        double dm = ms[i] - mean_ms, dc = cyc[i] - mean_cyc;
        vm += dm * dm; vc += dc * dc;
    }
    /* sample standard deviation (n-1) */
    double denom = (iters > 1) ? (double)(iters - 1) : 1.0;

    qsort(ms, iters, sizeof(double), cmp_double);
    qsort(cyc, iters, sizeof(double), cmp_double);
    double median = (iters & 1) ? ms[iters / 2]
                                : 0.5 * (ms[iters / 2 - 1] + ms[iters / 2]);
    double median_cyc = (iters & 1) ? cyc[iters / 2]
                                    : 0.5 * (cyc[iters / 2 - 1] + cyc[iters / 2]);

    out->n         = iters;
    out->mean_ms   = mean_ms;
    out->std_ms    = sqrt(vm / denom);
    out->min_ms    = mnm;
    out->max_ms    = mxm;
    out->median_ms = median;
    out->mean_cyc  = mean_cyc;
    out->std_cyc   = sqrt(vc / denom);
    out->min_cyc   = mnc;
    out->max_cyc   = mxc;
    out->median_cyc = median_cyc;
    out->ops_per_s = (mean_ms > 0.0) ? 1000.0 / mean_ms : 0.0;
    return 0;
}

void bench_print(const char *label, const bench_stats_t *s) {
    printf("  %-7s n=%u\n", label, s->n);
    printf("    time  : mean %.4f ms  std %.4f  min %.4f  max %.4f  median %.4f\n",
           s->mean_ms, s->std_ms, s->min_ms, s->max_ms, s->median_ms);
    printf("    cycles: mean %.0f     std %.0f      min %.0f      max %.0f      median %.0f\n",
           s->mean_cyc, s->std_cyc, s->min_cyc, s->max_cyc, s->median_cyc);
    printf("    throughput: %.2f ops/s\n", s->ops_per_s);
    /* CSV line for easy log scraping: label,n,mean_ms,std_ms,min_ms,max_ms,mean_cyc,ops_s */
    printf("    CSV,%s,%u,%.4f,%.4f,%.4f,%.4f,%.4f,%.0f,%.0f,%.2f\n",
           label, s->n, s->mean_ms, s->std_ms, s->min_ms, s->max_ms,
           s->median_ms, s->mean_cyc, s->median_cyc, s->ops_per_s);
}
