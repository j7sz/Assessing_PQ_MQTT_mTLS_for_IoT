include(CMakeParseArguments)
set(SIGBENCH_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")

function(sigbench_add_pqclean)
    set(options CONTEXT_API)
    set(oneValueArgs TARGET DISPLAY_NAME PARAMETER_SET STATUS NIST_LEVEL
        IMPL_DIR PREFIX KEY_HEADER SIG_BUFFER MAIN_DRIVER MSG_LEN_OVERRIDE)
    set(multiValueArgs COMMON_SOURCES INCLUDE_DIRS)
    cmake_parse_arguments(SB "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    foreach(required TARGET DISPLAY_NAME PARAMETER_SET STATUS NIST_LEVEL
                     IMPL_DIR PREFIX KEY_HEADER SIG_BUFFER)
        if(NOT SB_${required})
            message(FATAL_ERROR "sigbench_add_pqclean: missing ${required}")
        endif()
    endforeach()

    if(NOT EXISTS "${SB_IMPL_DIR}/api.h" OR NOT EXISTS "${SB_KEY_HEADER}")
        message(STATUS
            "Skipping ${SB_TARGET}: provide ${SB_IMPL_DIR}/api.h and ${SB_KEY_HEADER}")
        return()
    endif()

    if(SB_MAIN_DRIVER)
        set(_main_src "${SB_MAIN_DRIVER}")
    else()
        set(_main_src "${SIGBENCH_ROOT}/benchmark_main.c")
    endif()
    if(SB_MSG_LEN_OVERRIDE)
        set(_msg_len "${SB_MSG_LEN_OVERRIDE}")
    else()
        set(_msg_len "${SIGBENCH_MSG_LEN}")
    endif()

    file(GLOB scheme_sources CONFIGURE_DEPENDS "${SB_IMPL_DIR}/*.c")
    add_executable(${SB_TARGET}
        "${_main_src}"
        ${SIGBENCH_ROOT}/bench.c
        ${SIGBENCH_ROOT}/randombytes.c
        ${SIGBENCH_ROOT}/adapters/adapter_pqclean.c
        ${scheme_sources}
        ${SB_COMMON_SOURCES}
    )

    get_filename_component(key_dir "${SB_KEY_HEADER}" DIRECTORY)
    get_filename_component(key_file "${SB_KEY_HEADER}" NAME)
    target_include_directories(${SB_TARGET} PRIVATE
        ${SIGBENCH_ROOT}
        "${SB_IMPL_DIR}"
        "${key_dir}"
        ${SB_INCLUDE_DIRS}
    )
    target_compile_definitions(${SB_TARGET} PRIVATE
        BENCH_ITERS=${SIGBENCH_ITERS}
        BENCH_WARMUP=${SIGBENCH_WARMUP}
        MSG_LEN=${_msg_len}
        SIG_BUF=${SB_SIG_BUFFER}
        "SIGBENCH_BOARD_NAME=\"${PICO_BOARD}\""
        "SCHEME_DISPLAY_NAME=\"${SB_DISPLAY_NAME}\""
        "SCHEME_PARAMETER_SET=\"${SB_PARAMETER_SET}\""
        "SCHEME_STATUS=\"${SB_STATUS}\""
        "SCHEME_NIST_LEVEL=${SB_NIST_LEVEL}"
        "SCHEME_PREFIX=${SB_PREFIX}"
        "STATIC_KEYS_HEADER=\"${key_file}\""
    )
    if(SB_CONTEXT_API)
        target_compile_definitions(${SB_TARGET} PRIVATE SCHEME_CONTEXT_API=1)
    endif()

    target_link_libraries(${SB_TARGET} pico_stdlib pico_rand hardware_clocks)
    pico_enable_stdio_usb(${SB_TARGET} 1)
    pico_enable_stdio_uart(${SB_TARGET} 0)
    pico_add_extra_outputs(${SB_TARGET})
endfunction()
