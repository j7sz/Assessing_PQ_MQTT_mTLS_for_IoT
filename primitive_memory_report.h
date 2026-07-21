#pragma once

#include <stdio.h>

#include "runtime_memory.h"

static inline void primitive_memory_start(const char *scheme,
                                          const char *operation) {
    printf("MEMORY_HEADER,scheme,board,operation,heap_capacity_bytes,"
           "heap_in_use_before_bytes,heap_peak_in_use_bytes,heap_peak_delta_bytes,"
           "heap_in_use_after_bytes,free_before_bytes,min_free_bytes,free_after_bytes,"
           "maximum_allocation_request_bytes,allocation_calls,free_calls,failed_allocations,"
           "stack_capacity_bytes,stack_high_water_bytes,stack_unused_bytes,"
           "stack_guard_corrupted,alloc_failed,alloc_failure_stage,alloc_failure_bytes\n");
    printf("MEMORY_START,%s,%s,%s\n", scheme, SIGBENCH_BOARD_NAME, operation);
    runtime_memory_begin();
    runtime_memory_set_stage(
        operation[0] == 's' ? RUNTIME_MEM_STAGE_PRIMITIVE_SIGN
                            : RUNTIME_MEM_STAGE_PRIMITIVE_VERIFY);
}

static inline void primitive_memory_finish(const char *scheme,
                                           const char *operation) {
    runtime_memory_result_t m = runtime_memory_end();
    printf("MEMORY,%s,%s,%s,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
           "%u,%u,%u,%u,%u,%s,%u\n",
           scheme, SIGBENCH_BOARD_NAME, operation,
           m.heap_capacity_bytes, m.heap_in_use_before_bytes,
           m.heap_peak_in_use_bytes, m.heap_peak_delta_bytes,
           m.heap_in_use_after_bytes, m.free_before_bytes,
           m.min_free_bytes, m.free_after_bytes,
           m.maximum_allocation_request_bytes, m.allocation_calls,
           m.free_calls, m.failed_allocations, m.stack_capacity_bytes,
           m.stack_high_water_bytes, m.stack_unused_bytes,
           m.stack_guard_corrupted ? 1u : 0u,
           m.allocation_failed ? 1u : 0u,
           runtime_memory_stage_name(m.allocation_failure_stage),
           m.allocation_failure_bytes);
}
