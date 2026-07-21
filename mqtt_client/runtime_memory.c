#include "runtime_memory.h"

#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Symbols exported by the Pico SDK linker scripts. */
extern uint8_t __heap_start;
extern uint8_t __heap_end;
extern uint8_t __StackBottom;
extern uint8_t __StackTop;

#define STACK_PAINT_WORD 0xA55A3CC3u
#define STACK_GUARD_WORD 0xD15EA5EDu
#define STACK_PAINT_GUARD_BYTES 128u
#define STACK_LIMIT_GUARD_BYTES 64u

static volatile bool monitoring;
static volatile runtime_mem_stage_t current_stage;
static volatile size_t heap_before;
static volatile size_t heap_peak;
static volatile size_t free_before_tls;
static volatile size_t maximum_allocation_request;
static volatile uint32_t allocation_calls;
static volatile uint32_t free_calls;
static volatile uint32_t failed_allocations;
static volatile bool allocation_failed;
static volatile size_t allocation_failure_bytes;
static volatile runtime_mem_stage_t allocation_failure_stage;
static uint32_t *paint_begin;
static uint32_t *paint_end;
static uint32_t *stack_guard_end;

/* Pico SDK already wraps malloc/calloc/realloc/free to provide its mutex and
 * allocation checks. Wrapping those names again causes duplicate symbols, so
 * observe the underlying reentrant newlib entry points instead. */
struct _reent;
void *__real__malloc_r(struct _reent *reent, size_t size);
void *__real__realloc_r(struct _reent *reent, void *ptr, size_t size);
void __real__free_r(struct _reent *reent, void *ptr);

static size_t heap_capacity(void) {
    uintptr_t start = (uintptr_t)&__heap_start;
    uintptr_t end = (uintptr_t)&__heap_end;
    uintptr_t stack_bottom = (uintptr_t)&__StackBottom;
    if (stack_bottom < end) end = stack_bottom;
    return end > start ? (size_t)(end - start) : 0;
}

static size_t heap_in_use(void) {
    return mallinfo().uordblks;
}

static void observe_heap(void) {
    if (!monitoring) return;
    size_t used = heap_in_use();
    if (used > heap_peak) heap_peak = used;
}

void runtime_memory_note_allocation_failure(size_t requested) {
    if (!monitoring || requested == 0 || allocation_failed) return;
    allocation_failed = true;
    allocation_failure_bytes = requested;
    allocation_failure_stage = current_stage;
}

const char *runtime_memory_stage_name(runtime_mem_stage_t stage) {
    switch (stage) {
    case RUNTIME_MEM_STAGE_DNS:           return "dns";
    case RUNTIME_MEM_STAGE_TCP:           return "tcp";
    case RUNTIME_MEM_STAGE_TLS_CONTEXT:   return "tls_context";
    case RUNTIME_MEM_STAGE_CERTIFICATE:   return "certificate";
    case RUNTIME_MEM_STAGE_PRIVATE_KEY:   return "private_key";
    case RUNTIME_MEM_STAGE_KEY_SHARE:     return "key_share";
    case RUNTIME_MEM_STAGE_TLS_HANDSHAKE: return "tls_handshake";
    case RUNTIME_MEM_STAGE_SERVER_CERT_VERIFY: return "server_certificate_verify";
    case RUNTIME_MEM_STAGE_CLIENT_CERT_VERIFY: return "client_certificate_verify";
    case RUNTIME_MEM_STAGE_PRIMITIVE_SIGN: return "primitive_sign";
    case RUNTIME_MEM_STAGE_PRIMITIVE_VERIFY: return "primitive_verify";
    case RUNTIME_MEM_STAGE_MQTT:          return "mqtt";
    case RUNTIME_MEM_STAGE_CLOSE:         return "close";
    case RUNTIME_MEM_STAGE_IDLE:
    default:                              return "none";
    }
}

void runtime_memory_observe(void) {
    observe_heap();
}

void runtime_memory_set_stage(runtime_mem_stage_t stage) {
    current_stage = stage;
    observe_heap();
}

void runtime_memory_mark_tls_start(void) {
    observe_heap();
    size_t capacity = heap_capacity();
    size_t used = heap_in_use();
    free_before_tls = capacity > used ? capacity - used : 0;
}

void runtime_memory_begin(void) {
    uint32_t stack_marker;
    uintptr_t bottom = (uintptr_t)&__StackBottom;
    uintptr_t top = (uintptr_t)&__StackTop;
    uintptr_t current = (uintptr_t)&stack_marker;
    uintptr_t safe_end = current > STACK_PAINT_GUARD_BYTES
        ? current - STACK_PAINT_GUARD_BYTES : current;

    paint_begin = (uint32_t *)((bottom + 3u) & ~(uintptr_t)3u);
    paint_end = (uint32_t *)(safe_end & ~(uintptr_t)3u);
    stack_guard_end = (uint32_t *)((bottom + STACK_LIMIT_GUARD_BYTES + 3u) &
                                  ~(uintptr_t)3u);
    if (current < bottom || current > top || paint_end < paint_begin) {
        paint_begin = NULL;
        paint_end = NULL;
        stack_guard_end = NULL;
    } else {
        if (stack_guard_end > paint_end) stack_guard_end = paint_end;
        for (uint32_t *p = paint_begin; p < stack_guard_end; ++p) {
            *p = STACK_GUARD_WORD;
        }
        for (uint32_t *p = stack_guard_end; p < paint_end; ++p) {
            *p = STACK_PAINT_WORD;
        }
    }

    current_stage = RUNTIME_MEM_STAGE_IDLE;
    allocation_failed = false;
    allocation_failure_bytes = 0;
    allocation_failure_stage = RUNTIME_MEM_STAGE_IDLE;
    heap_before = heap_in_use();
    heap_peak = heap_before;
    free_before_tls = 0;
    maximum_allocation_request = 0;
    allocation_calls = 0;
    free_calls = 0;
    failed_allocations = 0;
    monitoring = true;
}

runtime_memory_result_t runtime_memory_end(void) {
    observe_heap();
    monitoring = false;

    size_t capacity = heap_capacity();
    size_t before = heap_before;
    size_t peak = heap_peak;
    uint32_t stack_high_water = 0;
    bool stack_guard_corrupted = false;
    if (paint_begin && paint_end) {
        for (uint32_t *g = paint_begin; g < stack_guard_end; ++g) {
            if (*g != STACK_GUARD_WORD) stack_guard_corrupted = true;
        }
        uint32_t *p = stack_guard_end;
        while (p < paint_end && *p == STACK_PAINT_WORD) ++p;
        stack_high_water = (uint32_t)((uintptr_t)&__StackTop - (uintptr_t)p);
        if (stack_guard_corrupted) stack_high_water = (uint32_t)(
            (uintptr_t)&__StackTop - (uintptr_t)&__StackBottom);
    }

    size_t after = heap_in_use();
    size_t stack_capacity = (size_t)(&__StackTop - &__StackBottom);

    runtime_memory_result_t result = {
        .heap_capacity_bytes = (uint32_t)capacity,
        .heap_in_use_before_bytes = (uint32_t)before,
        .heap_peak_in_use_bytes = (uint32_t)peak,
        .heap_peak_delta_bytes = (uint32_t)(peak > before ? peak - before : 0),
        .heap_in_use_after_bytes = (uint32_t)after,
        .free_before_bytes = (uint32_t)(capacity > before ? capacity - before : 0),
        .free_before_tls_bytes = (uint32_t)free_before_tls,
        .min_free_bytes = (uint32_t)(capacity > peak ? capacity - peak : 0),
        .free_after_bytes = (uint32_t)(capacity > after ? capacity - after : 0),
        .maximum_allocation_request_bytes = (uint32_t)maximum_allocation_request,
        .allocation_calls = allocation_calls,
        .free_calls = free_calls,
        .failed_allocations = failed_allocations,
        .stack_capacity_bytes = (uint32_t)stack_capacity,
        .stack_high_water_bytes = stack_high_water,
        .stack_unused_bytes = (uint32_t)(stack_capacity > stack_high_water
            ? stack_capacity - stack_high_water : 0),
        .stack_guard_corrupted = stack_guard_corrupted,
        .allocation_failed = allocation_failed,
        .allocation_failure_bytes = (uint32_t)allocation_failure_bytes,
        .allocation_failure_stage = allocation_failure_stage
};
    return result;
}

/* mallinfo() reports allocator bookkeeping rather than requested sizes, so
 * the peak includes allocator overhead and fragmentation—the quantity that
 * matters for SRAM feasibility. */
static void allocation_observed(size_t requested, void *ptr) {
    if (!monitoring) return;
    allocation_calls++;
    if (requested > maximum_allocation_request) {
        maximum_allocation_request = requested;
    }
    if (!ptr && requested != 0) {
        failed_allocations++;
        runtime_memory_note_allocation_failure(requested);
    }
    observe_heap();
}

void *__wrap__malloc_r(struct _reent *reent, size_t size) {
    void *ptr = __real__malloc_r(reent, size);
    allocation_observed(size, ptr);
    return ptr;
}

void *__wrap__realloc_r(struct _reent *reent, void *old_ptr, size_t size) {
    void *ptr = __real__realloc_r(reent, old_ptr, size);
    allocation_observed(size, ptr);
    return ptr;
}

void __wrap__free_r(struct _reent *reent, void *ptr) {
    __real__free_r(reent, ptr);
    if (monitoring && ptr) free_calls++;
    observe_heap();
}

void *runtime_memory_wolfssl_malloc(size_t size) {
    return malloc(size);
}

void *runtime_memory_wolfssl_realloc(void *old_ptr, size_t size) {
    return realloc(old_ptr, size);
}

void runtime_memory_wolfssl_free(void *ptr) {
    free(ptr);
}
