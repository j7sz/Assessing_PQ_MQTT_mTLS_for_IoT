include(CMakeParseArguments)
set(SIGBENCH_WOLFSSL_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")

function(sigbench_add_wolfssl_library root)
    if(TARGET wolfssl)
        return()
    endif()
    if(NOT EXISTS "${root}/wolfssl/wolfcrypt/settings.h")
        message(STATUS "wolfSSL not found at ${root}; classical targets skipped")
        return()
    endif()

    file(GLOB wolfcrypt_sources CONFIGURE_DEPENDS
        "${root}/wolfcrypt/src/*.c"
        "${root}/wolfcrypt/src/port/rpi_pico/*.c"
    )
    list(REMOVE_ITEM wolfcrypt_sources
        "${root}/wolfcrypt/src/asn_orig.c"
        "${root}/wolfcrypt/src/evp.c"
        "${root}/wolfcrypt/src/evp_pk.c"
        "${root}/wolfcrypt/src/misc.c"
    )

    add_library(wolfssl STATIC ${wolfcrypt_sources})
    target_include_directories(wolfssl PUBLIC
        "${root}"
        "${SIGBENCH_WOLFSSL_ROOT}/config/wolfssl"
    )
    target_compile_definitions(wolfssl PUBLIC WOLFSSL_USER_SETTINGS)
    # wolfSSL 5.9.1's Pico RNG port uses BAD_FUNC_ARG without directly
    # including error-crypt.h. Force the public error definitions consistently.
    set_source_files_properties(
        "${root}/wolfcrypt/src/port/rpi_pico/pico.c"
        PROPERTIES COMPILE_OPTIONS
        "-include;wolfssl/wolfcrypt/error-crypt.h"
    )

    if(PICO_PLATFORM STREQUAL "rp2350-arm-s")
        target_compile_definitions(wolfssl PUBLIC WOLFSSL_SP_ARM_CORTEX_M_ASM)
    elseif(PICO_PLATFORM STREQUAL "rp2350-riscv")
        message(WARNING "wolfSSL's Pico port has not tested RP2350 RISC-V")
    else()
        target_compile_definitions(wolfssl PUBLIC WOLFSSL_SP_ARM_THUMB_ASM)
    endif()

    target_link_libraries(wolfssl PUBLIC pico_stdlib pico_rand)
endfunction()

function(sigbench_add_wolfssl_scheme)
    set(oneValueArgs TARGET ADAPTER SIG_BUFFER MAIN_DRIVER MSG_LEN_OVERRIDE)
    set(multiValueArgs DEFINITIONS INCLUDE_DIRS)
    cmake_parse_arguments(SB "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    if(NOT TARGET wolfssl)
        return()
    endif()
    foreach(required TARGET ADAPTER SIG_BUFFER)
        if(NOT SB_${required})
            message(FATAL_ERROR "sigbench_add_wolfssl_scheme: missing ${required}")
        endif()
    endforeach()

    if(SB_MAIN_DRIVER)
        set(_main_src "${SB_MAIN_DRIVER}")
    else()
        set(_main_src "${SIGBENCH_WOLFSSL_ROOT}/benchmark_main.c")
    endif()
    if(SB_MSG_LEN_OVERRIDE)
        set(_msg_len "${SB_MSG_LEN_OVERRIDE}")
    else()
        set(_msg_len "${SIGBENCH_MSG_LEN}")
    endif()

    add_executable(${SB_TARGET}
        "${_main_src}"
        "${SIGBENCH_WOLFSSL_ROOT}/bench.c"
        "${SB_ADAPTER}"
    )
    target_include_directories(${SB_TARGET} PRIVATE
        "${SIGBENCH_WOLFSSL_ROOT}"
        ${SB_INCLUDE_DIRS}
    )
    target_compile_definitions(${SB_TARGET} PRIVATE
        BENCH_ITERS=${SIGBENCH_ITERS}
        BENCH_WARMUP=${SIGBENCH_WARMUP}
        MSG_LEN=${_msg_len}
        SIG_BUF=${SB_SIG_BUFFER}
        PICO_STACK_SIZE=4096
        "SIGBENCH_BOARD_NAME=\"${PICO_BOARD}\""
        ${SB_DEFINITIONS}
    )
    target_link_libraries(${SB_TARGET}
        wolfssl pico_stdlib pico_rand hardware_clocks
    )
    pico_enable_stdio_usb(${SB_TARGET} 1)
    pico_enable_stdio_uart(${SB_TARGET} 0)
    pico_add_extra_outputs(${SB_TARGET})
endfunction()
