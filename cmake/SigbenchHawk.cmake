include(CMakeParseArguments)
set(SIGBENCH_HAWK_PROJECT_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")

function(sigbench_add_hawk)
    set(oneValueArgs TARGET ROOT KEY_HEADER LOGN DISPLAY_NAME NIST_LEVEL SIG_BUFFER
        MAIN_DRIVER MSG_LEN_OVERRIDE)
    cmake_parse_arguments(SB "" "${oneValueArgs}" "" ${ARGN})
    if(NOT EXISTS "${SB_ROOT}/src/hawk.h" OR NOT EXISTS "${SB_KEY_HEADER}")
        message(STATUS "Skipping ${SB_TARGET}: HAWK source or static key missing")
        return()
    endif()

    set(hawk_sources
        hawk_kgen.c hawk_sign.c hawk_vrfy.c ng_fxp.c ng_hawk.c ng_mp31.c
        ng_ntru.c ng_poly.c ng_zint31.c sha3.c
    )
    list(TRANSFORM hawk_sources PREPEND "${SB_ROOT}/src/")
    get_filename_component(key_dir "${SB_KEY_HEADER}" DIRECTORY)

    if(SB_MAIN_DRIVER)
        set(_main_src "${SB_MAIN_DRIVER}")
    else()
        set(_main_src "${SIGBENCH_HAWK_PROJECT_ROOT}/benchmark_main.c")
    endif()
    if(SB_MSG_LEN_OVERRIDE)
        set(_hawk_msg_len "${SB_MSG_LEN_OVERRIDE}")
    else()
        set(_hawk_msg_len "${SIGBENCH_MSG_LEN}")
    endif()

    get_filename_component(key_file "${SB_KEY_HEADER}" NAME)
    add_executable(${SB_TARGET}
        "${_main_src}"
        "${SIGBENCH_HAWK_PROJECT_ROOT}/bench.c"
        "${SIGBENCH_HAWK_PROJECT_ROOT}/adapters/adapter_hawk512.c"
        ${hawk_sources}
    )
    target_include_directories(${SB_TARGET} PRIVATE
        "${SIGBENCH_HAWK_PROJECT_ROOT}" "${SB_ROOT}/src" "${key_dir}"
    )
    target_compile_definitions(${SB_TARGET} PRIVATE
        HAWK_AVX2=0 BENCH_ITERS=${SIGBENCH_ITERS}
        BENCH_WARMUP=${SIGBENCH_WARMUP} MSG_LEN=${_hawk_msg_len}
        SIG_BUF=${SB_SIG_BUFFER} HAWK_LOGN=${SB_LOGN}
        HAWK_NIST_LEVEL=${SB_NIST_LEVEL}
        "HAWK_DISPLAY_NAME=\"${SB_DISPLAY_NAME}\""
        "HAWK_KEYS_HEADER=\"${key_file}\""
        "SIGBENCH_BOARD_NAME=\"${PICO_BOARD}\""
    )
    target_link_libraries(${SB_TARGET}
        pico_stdlib pico_rand hardware_clocks
    )
    pico_enable_stdio_usb(${SB_TARGET} 1)
    pico_enable_stdio_uart(${SB_TARGET} 0)
    pico_add_extra_outputs(${SB_TARGET})
endfunction()
