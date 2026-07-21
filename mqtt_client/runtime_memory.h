#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Runtime phases are deliberately stable strings because they are emitted in
 * the attempt CSV and used to locate allocation failures. */
typedef enum {
    RUNTIME_MEM_STAGE_IDLE = 0,
    RUNTIME_MEM_STAGE_DNS,
    RUNTIME_MEM_STAGE_TCP,
    RUNTIME_MEM_STAGE_TLS_CONTEXT,
    RUNTIME_MEM_STAGE_CERTIFICATE,
    RUNTIME_MEM_STAGE_PRIVATE_KEY,
    RUNTIME_MEM_STAGE_KEY_SHARE,
    RUNTIME_MEM_STAGE_TLS_HANDSHAKE,
    RUNTIME_MEM_STAGE_SERVER_CERT_VERIFY,
    RUNTIME_MEM_STAGE_CLIENT_CERT_VERIFY,
    RUNTIME_MEM_STAGE_PRIMITIVE_SIGN,
    RUNTIME_MEM_STAGE_PRIMITIVE_VERIFY,
    RUNTIME_MEM_STAGE_MQTT,
    RUNTIME_MEM_STAGE_CLOSE
} runtime_mem_stage_t;

typedef struct {
    uint32_t heap_capacity_bytes;
    uint32_t heap_in_use_before_bytes;
    uint32_t heap_peak_in_use_bytes;
    uint32_t heap_peak_delta_bytes;
    uint32_t heap_in_use_after_bytes;
    uint32_t free_before_bytes;
    uint32_t free_before_tls_bytes;
    uint32_t min_free_bytes;
    uint32_t free_after_bytes;
    uint32_t maximum_allocation_request_bytes;
    uint32_t allocation_calls;
    uint32_t free_calls;
    uint32_t failed_allocations;
    uint32_t stack_capacity_bytes;
    uint32_t stack_high_water_bytes;
    uint32_t stack_unused_bytes;
    bool stack_guard_corrupted;
    bool allocation_failed;
    uint32_t allocation_failure_bytes;
    runtime_mem_stage_t allocation_failure_stage;
} runtime_memory_result_t;

void runtime_memory_begin(void);
void runtime_memory_set_stage(runtime_mem_stage_t stage);
void runtime_memory_mark_tls_start(void);
void runtime_memory_observe(void);
void runtime_memory_note_allocation_failure(size_t requested);
runtime_memory_result_t runtime_memory_end(void);
const char *runtime_memory_stage_name(runtime_mem_stage_t stage);

/* wolfSSL allocator callbacks. These retain Pico SDK's allocator and mutex;
 * the reentrant newlib wrappers below observe the resulting operations. */
void *runtime_memory_wolfssl_malloc(size_t size);
void runtime_memory_wolfssl_free(void *ptr);
void *runtime_memory_wolfssl_realloc(void *ptr, size_t size);
