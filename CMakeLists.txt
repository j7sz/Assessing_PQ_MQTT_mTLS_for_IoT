cmake_minimum_required(VERSION 3.13)

if(NOT DEFINED ENV{PICO_SDK_PATH} OR
   NOT EXISTS "$ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake")
    message(FATAL_ERROR
        "Set PICO_SDK_PATH to a Raspberry Pi Pico SDK 2.2.0 checkout")
endif()

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(pico_pqc_sigbench C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
pico_sdk_init()

set(PQCLEAN_ROOT "${CMAKE_CURRENT_LIST_DIR}/third_party/PQClean" CACHE PATH
    "Pinned PQClean checkout containing crypto_sign/")
set(WOLFSSL_ROOT "${CMAKE_CURRENT_LIST_DIR}/third_party/wolfssl" CACHE PATH
    "Pinned and patched wolfSSL checkout")
set(SIGBENCH_KEY_DIR "${CMAKE_CURRENT_LIST_DIR}/keys" CACHE PATH
    "Generated test-key headers")
set(SIGBENCH_ITERS 30 CACHE STRING "Measured signing/verifying operations")
set(SIGBENCH_WARMUP 3 CACHE STRING "Discarded warm-up operations")
set(SIGBENCH_MSG_LEN 32 CACHE STRING "Message size in bytes")

include(cmake/SigbenchScheme.cmake)
include(cmake/SigbenchWolfSSL.cmake)
include(cmake/SigbenchHawk.cmake)
include(cmake/SigbenchMayo.cmake)
include(cmake/SigbenchSnova.cmake)

# Classical baselines.
sigbench_add_wolfssl_library("${WOLFSSL_ROOT}")
sigbench_add_wolfssl_scheme(
    TARGET sigbench_rsa2048
    ADAPTER "${CMAKE_CURRENT_LIST_DIR}/adapters/adapter_wolfssl_rsa2048.c"
    SIG_BUFFER 256)
sigbench_add_wolfssl_scheme(
    TARGET sigbench_ecdsa_p256
    ADAPTER "${CMAKE_CURRENT_LIST_DIR}/adapters/adapter_wolfssl_ecdsa_p256.c"
    SIG_BUFFER 80)

# Standardized/selected post-quantum baselines.
sigbench_add_pqclean(
    TARGET sigbench_mldsa44
    DISPLAY_NAME "ML-DSA-44"
    PARAMETER_SET "ML-DSA-44"
    STATUS "FIPS 204"
    NIST_LEVEL 2
    IMPL_DIR "${PQCLEAN_ROOT}/crypto_sign/ml-dsa-44/clean"
    PREFIX "PQCLEAN_MLDSA44_CLEAN_"
    KEY_HEADER "${SIGBENCH_KEY_DIR}/keys_mldsa44.h"
    SIG_BUFFER 2420
    COMMON_SOURCES "${PQCLEAN_ROOT}/common/fips202.c"
    INCLUDE_DIRS "${PQCLEAN_ROOT}/common")

sigbench_add_pqclean(
    TARGET sigbench_falcon512
    DISPLAY_NAME "Falcon-512"
    PARAMETER_SET "Falcon-512"
    STATUS "Selected for FN-DSA / FIPS 206 in development"
    NIST_LEVEL 1
    IMPL_DIR "${PQCLEAN_ROOT}/crypto_sign/falcon-512/clean"
    PREFIX "PQCLEAN_FALCON512_CLEAN_"
    KEY_HEADER "${SIGBENCH_KEY_DIR}/keys_falcon512.h"
    SIG_BUFFER 752
    COMMON_SOURCES "${PQCLEAN_ROOT}/common/fips202.c"
    INCLUDE_DIRS "${PQCLEAN_ROOT}/common")

sigbench_add_hawk(
    TARGET sigbench_hawk512
    ROOT "${CMAKE_CURRENT_LIST_DIR}/third_party/hawk"
    KEY_HEADER "${SIGBENCH_KEY_DIR}/keys_hawk512.h"
    LOGN 9 DISPLAY_NAME "HAWK-512" NIST_LEVEL 1 SIG_BUFFER 555)

sigbench_add_mayo(
    TARGET sigbench_mayo1
    ROOT "${CMAKE_CURRENT_LIST_DIR}/third_party/mayo-m4"
    PARAM mayo1 DISPLAY_NAME "MAYO-1" NIST_LEVEL 1
    KEY_HEADER "${SIGBENCH_KEY_DIR}/keys_mayo1.h"
    SIG_BUFFER 454 STACK_SIZE 225280)

# SNOVA signing needs RP2350 SRAM. Pico W retains an optimized target plus a
# verify-only target so its resource-limit outcome can be recorded honestly.
sigbench_add_snova(
    sigbench_snova_24_5_16_4
    "${CMAKE_CURRENT_LIST_DIR}/third_party/snova"
    "${SIGBENCH_KEY_DIR}/keys_snova_24_5_16_4.h"
    V 24 O 5 Q 16 L 4 R 4 SIG_BYTES 248
    DISPLAY_NAME "SNOVA-24-5-16-4")
sigbench_add_snova_opt(
    sigbench_snova_24_5_16_4_opt
    "${CMAKE_CURRENT_LIST_DIR}/third_party/snova"
    "${SIGBENCH_KEY_DIR}/keys_snova_24_5_16_4.h"
    V 24 O 5 Q 16 L 4 R 4 SIG_BYTES 248
    DISPLAY_NAME "SNOVA-24-5-16-4" STACK_SIZE 237568)
sigbench_add_snova_verify_only(
    sigbench_snova_24_5_16_4_verify
    "${CMAKE_CURRENT_LIST_DIR}/third_party/snova"
    "${SIGBENCH_KEY_DIR}/keys_snova_24_5_16_4_verify.h"
    V 24 O 5 Q 16 L 4 R 4 SIG_BYTES 248
    DISPLAY_NAME "SNOVA-24-5-16-4" STACK_SIZE 196608)

# Add observed heap/stack instrumentation to every selected primitive image.
get_property(_sigbench_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
foreach(_target IN LISTS _sigbench_targets)
    if(_target MATCHES "^sigbench_" AND TARGET "${_target}")
        get_target_property(_target_type "${_target}" TYPE)
        if(_target_type STREQUAL "EXECUTABLE")
            target_sources("${_target}" PRIVATE
                "${CMAKE_CURRENT_LIST_DIR}/mqtt_client/runtime_memory.c")
            target_include_directories("${_target}" PRIVATE
                "${CMAKE_CURRENT_LIST_DIR}/mqtt_client")
            target_compile_definitions("${_target}" PRIVATE PICO_MALLOC_PANIC=0)
            target_link_options("${_target}" PRIVATE
                "-Wl,--wrap=_malloc_r" "-Wl,--wrap=_realloc_r"
                "-Wl,--wrap=_free_r")
        endif()
    endif()
endforeach()

add_subdirectory(mqtt_client)
