set(SIGBENCH_SNOVA_PROJECT_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")

function(sigbench_add_snova target root key_header)
    set(options)
    set(oneValueArgs V O Q L R SIG_BYTES DISPLAY_NAME MAIN_DRIVER MSG_LEN_OVERRIDE)
    cmake_parse_arguments(SB "${options}" "${oneValueArgs}" "" ${ARGN})
    foreach(required V O Q L R SIG_BYTES DISPLAY_NAME)
        if(NOT SB_${required})
            message(FATAL_ERROR "sigbench_add_snova: missing ${required}")
        endif()
    endforeach()
    if(SB_MAIN_DRIVER)
        set(_main_src "${SB_MAIN_DRIVER}")
    else()
        set(_main_src "${SIGBENCH_SNOVA_PROJECT_ROOT}/benchmark_main.c")
    endif()
    if(SB_MSG_LEN_OVERRIDE)
        set(_snova_msg_len "${SB_MSG_LEN_OVERRIDE}")
    else()
        set(_snova_msg_len "${SIGBENCH_MSG_LEN}")
    endif()
    if(NOT PICO_PLATFORM STREQUAL "rp2350-arm-s")
        message(STATUS
            "Skipping ${target}: SNOVA reference signing needs more than "
            "RP2040's total SRAM after expanded-key and nested workspace")
        return()
    endif()
    if(NOT EXISTS "${root}/src/api.h" OR NOT EXISTS "${key_header}")
        message(STATUS "Skipping ${target}: SNOVA source or static key missing")
        return()
    endif()
    get_filename_component(key_dir "${key_header}" DIRECTORY)
    get_filename_component(key_file "${key_header}" NAME)

    add_executable(${target}
        "${_main_src}"
        "${SIGBENCH_SNOVA_PROJECT_ROOT}/bench.c"
        "${SIGBENCH_SNOVA_PROJECT_ROOT}/adapters/adapter_snova.c"
        "${SIGBENCH_SNOVA_PROJECT_ROOT}/adapters/snova_randombytes.c"
        "${root}/src/sign.c"
        "${root}/src/snova_ref.c"
        "${root}/src/symmetric_ref.c"
    )
    target_include_directories(${target} PRIVATE
        "${SIGBENCH_SNOVA_PROJECT_ROOT}" "${root}/src" "${key_dir}"
    )
    target_compile_definitions(${target} PRIVATE
        SNOVA_v=${SB_V} SNOVA_o=${SB_O} SNOVA_q=${SB_Q}
        SNOVA_l=${SB_L} SNOVA_r=${SB_R}
        BENCH_ITERS=${SIGBENCH_ITERS} BENCH_WARMUP=${SIGBENCH_WARMUP}
        MSG_LEN=${_snova_msg_len} SIG_BUF=${SB_SIG_BYTES}
        PICO_STACK_SIZE=430080
        "SNOVA_DISPLAY_NAME=\"${SB_DISPLAY_NAME}\""
        "STATIC_KEYS_HEADER=\"${key_file}\""
        "SIGBENCH_BOARD_NAME=\"${PICO_BOARD}\""
    )
    set(default_linker
        "${PICO_SDK_PATH}/src/rp2_common/pico_crt0/rp2350/memmap_default.ld")
    file(READ "${default_linker}" linker_text)
    string(REPLACE "} > SCRATCH_Y\n\n    .flash_end" "} > RAM\n\n    .flash_end"
        linker_text "${linker_text}")
    string(REPLACE
        "__StackTop = ORIGIN(SCRATCH_Y) + LENGTH(SCRATCH_Y);"
        "__StackTop = ORIGIN(RAM) + LENGTH(RAM);"
        linker_text "${linker_text}")
    string(REPLACE
        "__HeapLimit = ORIGIN(RAM) + LENGTH(RAM);"
        "__HeapLimit = ORIGIN(RAM) + LENGTH(RAM) - 430080;"
        linker_text "${linker_text}")
    string(REPLACE
        "__StackLimit = ORIGIN(RAM) + LENGTH(RAM);"
        "__StackLimit = ORIGIN(RAM) + LENGTH(RAM) - 430080;"
        linker_text "${linker_text}")
    set(linker "${CMAKE_CURRENT_BINARY_DIR}/${target}_memmap.ld")
    file(WRITE "${linker}" "${linker_text}")
    pico_set_linker_script(${target} "${linker}")

    target_link_libraries(${target} pico_stdlib pico_rand hardware_clocks)
    pico_enable_stdio_usb(${target} 1)
    pico_enable_stdio_uart(${target} 0)
    pico_add_extra_outputs(${target})
endfunction()

function(sigbench_add_snova_opt target root key_header)
    set(options)
    set(oneValueArgs V O Q L R SIG_BYTES DISPLAY_NAME STACK_SIZE MAIN_DRIVER MSG_LEN_OVERRIDE)
    cmake_parse_arguments(SB "${options}" "${oneValueArgs}" "" ${ARGN})
    foreach(required V O Q L R SIG_BYTES DISPLAY_NAME)
        if(NOT SB_${required})
            message(FATAL_ERROR "sigbench_add_snova_opt: missing ${required}")
        endif()
    endforeach()
    if(SB_MAIN_DRIVER)
        set(_main_src "${SB_MAIN_DRIVER}")
    else()
        set(_main_src "${SIGBENCH_SNOVA_PROJECT_ROOT}/benchmark_main.c")
    endif()
    if(SB_MSG_LEN_OVERRIDE)
        set(_snova_msg_len "${SB_MSG_LEN_OVERRIDE}")
    else()
        set(_snova_msg_len "${SIGBENCH_MSG_LEN}")
    endif()
    if(SB_STACK_SIZE)
        set(_snova_stack_size "${SB_STACK_SIZE}")
    else()
        set(_snova_stack_size 237568)
    endif()
    if(NOT EXISTS "${root}/src/api.h" OR NOT EXISTS "${key_header}")
        message(STATUS "Skipping ${target}: SNOVA source or static key missing")
        return()
    endif()
    get_filename_component(key_dir "${key_header}" DIRECTORY)
    get_filename_component(key_file "${key_header}" NAME)

    add_executable(${target}
        "${_main_src}"
        "${SIGBENCH_SNOVA_PROJECT_ROOT}/bench.c"
        "${SIGBENCH_SNOVA_PROJECT_ROOT}/adapters/adapter_snova.c"
        "${SIGBENCH_SNOVA_PROJECT_ROOT}/adapters/snova_randombytes.c"
        "${root}/src/sign.c"
        "${root}/src/snova_opt.c"
        "${root}/src/symmetric.c"
    )
    target_include_directories(${target} PRIVATE
        "${SIGBENCH_SNOVA_PROJECT_ROOT}" "${root}/src" "${key_dir}"
    )
    target_compile_definitions(${target} PRIVATE
        SNOVA_v=${SB_V} SNOVA_o=${SB_O} SNOVA_q=${SB_Q}
        SNOVA_l=${SB_L} SNOVA_r=${SB_R}
        BENCH_ITERS=${SIGBENCH_ITERS} BENCH_WARMUP=${SIGBENCH_WARMUP}
        MSG_LEN=${_snova_msg_len} SIG_BUF=${SB_SIG_BYTES}
        PICO_STACK_SIZE=${_snova_stack_size}
        "SNOVA_IMPL_NAME=\"SNOVA 2.3 optimized portable C (SHAKE)\""
        "SNOVA_DISPLAY_NAME=\"${SB_DISPLAY_NAME}\""
        "STATIC_KEYS_HEADER=\"${key_file}\""
        "SIGBENCH_BOARD_NAME=\"${PICO_BOARD}\""
    )

    if(PICO_PLATFORM STREQUAL "rp2040")
        set(default_linker
            "${PICO_SDK_PATH}/src/rp2_common/pico_crt0/rp2040/memmap_default.ld")
    elseif(PICO_PLATFORM STREQUAL "rp2350-arm-s")
        set(default_linker
            "${PICO_SDK_PATH}/src/rp2_common/pico_crt0/rp2350/memmap_default.ld")
    else()
        message(FATAL_ERROR "SNOVA optimized linker unsupported on ${PICO_PLATFORM}")
    endif()
    file(READ "${default_linker}" linker_text)
    string(REPLACE "} > SCRATCH_Y\n\n    .flash_end" "} > RAM\n\n    .flash_end"
        linker_text "${linker_text}")
    string(REPLACE
        "__StackTop = ORIGIN(SCRATCH_Y) + LENGTH(SCRATCH_Y);"
        "__StackTop = ORIGIN(RAM) + LENGTH(RAM);"
        linker_text "${linker_text}")
    string(REPLACE
        "__HeapLimit = ORIGIN(RAM) + LENGTH(RAM);"
        "__HeapLimit = ORIGIN(RAM) + LENGTH(RAM) - ${_snova_stack_size};"
        linker_text "${linker_text}")
    string(REPLACE
        "__StackLimit = ORIGIN(RAM) + LENGTH(RAM);"
        "__StackLimit = ORIGIN(RAM) + LENGTH(RAM) - ${_snova_stack_size};"
        linker_text "${linker_text}")
    set(linker "${CMAKE_CURRENT_BINARY_DIR}/${target}_memmap.ld")
    file(WRITE "${linker}" "${linker_text}")
    pico_set_linker_script(${target} "${linker}")

    target_link_libraries(${target} pico_stdlib pico_rand hardware_clocks)
    pico_enable_stdio_usb(${target} 1)
    pico_enable_stdio_uart(${target} 0)
    pico_add_extra_outputs(${target})
endfunction()

function(sigbench_add_snova_verify_only target root verify_header)
    set(options)
    set(oneValueArgs V O Q L R SIG_BYTES DISPLAY_NAME STACK_SIZE
        EXPANDED_PK_HEADER MAIN_DRIVER)
    cmake_parse_arguments(SB "${options}" "${oneValueArgs}" "" ${ARGN})
    foreach(required V O Q L R SIG_BYTES DISPLAY_NAME)
        if(NOT SB_${required})
            message(FATAL_ERROR "sigbench_add_snova_verify_only: missing ${required}")
        endif()
    endforeach()
    if(SB_STACK_SIZE)
        set(_snova_stack_size "${SB_STACK_SIZE}")
    else()
        set(_snova_stack_size 237568)
    endif()
    set(_snova_bench_iters "${SIGBENCH_ITERS}")
    set(_snova_bench_warmup "${SIGBENCH_WARMUP}")
    if(NOT EXISTS "${root}/src/api.h" OR NOT EXISTS "${verify_header}")
        message(STATUS "Skipping ${target}: SNOVA source or static verify KAT missing")
        return()
    endif()
    if(SB_EXPANDED_PK_HEADER AND NOT EXISTS "${SB_EXPANDED_PK_HEADER}")
        message(STATUS
            "Skipping ${target}: host-expanded public-key header missing "
            "(run tools/generate_snova_expanded_pk.py)")
        return()
    endif()
    get_filename_component(key_dir "${verify_header}" DIRECTORY)
    get_filename_component(key_file "${verify_header}" NAME)
    if(SB_MAIN_DRIVER)
        set(_main_src "${SB_MAIN_DRIVER}")
    else()
        set(_main_src "${SIGBENCH_SNOVA_PROJECT_ROOT}/snova_verify_main.c")
    endif()

    add_executable(${target}
        "${_main_src}"
        "${SIGBENCH_SNOVA_PROJECT_ROOT}/bench.c"
        "${root}/src/sign.c"
        "${root}/src/snova_opt.c"
        "${root}/src/symmetric.c"
    )
    target_include_directories(${target} PRIVATE
        "${SIGBENCH_SNOVA_PROJECT_ROOT}" "${root}/src" "${key_dir}"
    )
    target_compile_definitions(${target} PRIVATE
        SNOVA_v=${SB_V} SNOVA_o=${SB_O} SNOVA_q=${SB_Q}
        SNOVA_l=${SB_L} SNOVA_r=${SB_R}
        BENCH_ITERS=${_snova_bench_iters} BENCH_WARMUP=${_snova_bench_warmup}
        MSG_LEN=33 SIG_BUF=${SB_SIG_BYTES}
        PICO_STACK_SIZE=${_snova_stack_size}
        "SNOVA_DISPLAY_NAME=\"${SB_DISPLAY_NAME}\""
        "STATIC_VERIFY_HEADER=\"${key_file}\""
        "SIGBENCH_BOARD_NAME=\"${PICO_BOARD}\""
    )
    if(SB_EXPANDED_PK_HEADER)
        get_filename_component(expanded_pk_dir "${SB_EXPANDED_PK_HEADER}" DIRECTORY)
        get_filename_component(expanded_pk_file "${SB_EXPANDED_PK_HEADER}" NAME)
        target_include_directories(${target} PRIVATE "${expanded_pk_dir}")
        target_compile_definitions(${target} PRIVATE
            "STATIC_EXPANDED_PK_HEADER=\"${expanded_pk_file}\"")
    endif()
    # Preserve compiler stack-usage reports for validating the configured
    # verify-only stack against nested crypto_sign_open -> verify frames.
    target_compile_options(${target} PRIVATE -fstack-usage)

    if(PICO_PLATFORM STREQUAL "rp2040")
        set(default_linker
            "${PICO_SDK_PATH}/src/rp2_common/pico_crt0/rp2040/memmap_default.ld")
    elseif(PICO_PLATFORM STREQUAL "rp2350-arm-s")
        set(default_linker
            "${PICO_SDK_PATH}/src/rp2_common/pico_crt0/rp2350/memmap_default.ld")
    else()
        message(FATAL_ERROR "SNOVA verify-only linker unsupported on ${PICO_PLATFORM}")
    endif()
    file(READ "${default_linker}" linker_text)
    string(REPLACE "} > SCRATCH_Y\n\n    .flash_end" "} > RAM\n\n    .flash_end"
        linker_text "${linker_text}")
    string(REPLACE
        "__StackTop = ORIGIN(SCRATCH_Y) + LENGTH(SCRATCH_Y);"
        "__StackTop = ORIGIN(RAM) + LENGTH(RAM);"
        linker_text "${linker_text}")
    string(REPLACE
        "__HeapLimit = ORIGIN(RAM) + LENGTH(RAM);"
        "__HeapLimit = ORIGIN(RAM) + LENGTH(RAM) - ${_snova_stack_size};"
        linker_text "${linker_text}")
    string(REPLACE
        "__StackLimit = ORIGIN(RAM) + LENGTH(RAM);"
        "__StackLimit = ORIGIN(RAM) + LENGTH(RAM) - ${_snova_stack_size};"
        linker_text "${linker_text}")
    set(linker "${CMAKE_CURRENT_BINARY_DIR}/${target}_memmap.ld")
    file(WRITE "${linker}" "${linker_text}")
    pico_set_linker_script(${target} "${linker}")

    target_link_libraries(${target} pico_stdlib hardware_clocks)
    pico_enable_stdio_usb(${target} 1)
    pico_enable_stdio_uart(${target} 0)
    pico_add_extra_outputs(${target})
endfunction()
