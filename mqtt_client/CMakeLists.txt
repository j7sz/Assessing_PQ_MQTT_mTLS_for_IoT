cmake_minimum_required(VERSION 3.13)

# Connection benchmark mode: when TLS_BENCH_ITERS > 0 every mqtt_client
# firmware performs repeated TCP + TLS + MQTT CONNECT/CONNACK cycles and
# reports latency + traffic statistics instead of entering the publish loop.
set(TLS_BENCH_ITERS 0 CACHE STRING
    "Measured MQTT-over-TLS connection iterations (0 = normal MQTT client mode)")
set(TLS_BENCH_WARMUP 3 CACHE STRING
    "Discarded warm-up connection attempts in TLS benchmark mode")
set(TLS_BENCH_CAMPAIGN 1 CACHE STRING
    "Campaign identifier embedded in every TLS benchmark attempt row")
option(MQTT_TLS_BENCH_COMPACT_OUTPUT
    "Keep TLS benchmark serial output to lifecycle, CSV results, and failures" ON)
set(MQTT_WIFI_SSID "" CACHE STRING
    "Wi-Fi SSID compiled into mqtt_client targets (empty = config.h default)")
set(MQTT_WIFI_PASS "" CACHE STRING
    "Wi-Fi password compiled into mqtt_client targets (empty = config.h default)")
set(MQTT_BROKER_HOST "" CACHE STRING
    "Mosquitto IP address or hostname (empty = config.h default)")
set(MQTT_PLAIN_HEAP_SIZE 131072 CACHE STRING
    "Plain MQTT heap reservation in bytes")
set(MQTT_ECDSA_P256_STACK_SIZE "" CACHE STRING
    "ECDSA P-256 stack size in bytes (empty = board default)")
set(MQTT_FALCON512_STACK_SIZE "" CACHE STRING
    "Falcon-512 stack size in bytes (empty = board default)")
set(MQTT_MAYO1_STACK_SIZE 16384 CACHE STRING
    "MAYO-1 stack size in bytes")
set(MQTT_SNOVA2454_STACK_SIZE 262144 CACHE STRING
    "SNOVA-24-5-16-4 stack size in bytes")

function(add_mqtt_wolfssl_tls target sp_int_bits)
    # SCHEME selects which PQ signature algorithm's sources/macros get
    # compiled into THIS library variant. Only one of these may be set (or
    # none, for classical targets that need no PQ signature code
    # at all). This is what makes each mqtt_client_* firmware isolated
    # instead of sharing one library containing every algorithm.
    #   Valid values: MLDSA44 FALCON512 HAWK512 MAYO1 (SNOVA2454 via flag below)
    # NEEDS_RSA: only the RSA-2048 library variant should set this. Every
    # other scheme (ECDSA and every PQ scheme) has no use for RSA
    # X.509 parsing/signing and previously carried it anyway because NO_RSA
    # was never defined for any target.
    cmake_parse_arguments(MQTT_TLS "CLASSICAL_SP_OPT;SNOVA2454;NEEDS_RSA" "SCHEME" "" ${ARGN})
    if(NOT EXISTS "${WOLFSSL_ROOT}/wolfssl/wolfcrypt/settings.h")
        message(FATAL_ERROR
            "wolfSSL not found at ${WOLFSSL_ROOT}. "
            "Set WOLFSSL_ROOT to a wolfSSL v5.9.1 checkout.")
    endif()

    # wolfCrypt primitives
    file(GLOB wolfcrypt_src CONFIGURE_DEPENDS
        "${WOLFSSL_ROOT}/wolfcrypt/src/*.c"
        "${WOLFSSL_ROOT}/wolfcrypt/src/port/rpi_pico/*.c"
    )
    list(REMOVE_ITEM wolfcrypt_src
        "${WOLFSSL_ROOT}/wolfcrypt/src/asn_orig.c"
        "${WOLFSSL_ROOT}/wolfcrypt/src/evp.c"
        "${WOLFSSL_ROOT}/wolfcrypt/src/evp_pk.c"
        "${WOLFSSL_ROOT}/wolfcrypt/src/misc.c"
    )

    # TLS protocol layer (ssl.c, tls.c, tls13.c, internal.c, keys.c, …)
    # pk.c is #include'd by ssl.c and must not be compiled as a standalone TU
    file(GLOB wolfssl_tls_src CONFIGURE_DEPENDS
        "${WOLFSSL_ROOT}/src/*.c"
    )
    # Exclude files that wolfSSL #include's directly from ssl.c
    list(REMOVE_ITEM wolfssl_tls_src
        "${WOLFSSL_ROOT}/src/pk.c"
        "${WOLFSSL_ROOT}/src/pk_ec.c"
    )

    # Third-party PQ signature sources: only compiled in for the ONE scheme
    # that requested them, instead of unconditionally for every target.
    set(_mqtt_pq_sig_src)
    set(_mqtt_pq_sig_inc)
    if(MQTT_TLS_SCHEME STREQUAL "FALCON512")
        list(APPEND _mqtt_pq_sig_src
            "${CMAKE_CURRENT_LIST_DIR}/../randombytes.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/common/fips202.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/crypto_sign/falcon-512/clean/codec.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/crypto_sign/falcon-512/clean/common.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/crypto_sign/falcon-512/clean/fft.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/crypto_sign/falcon-512/clean/fpr.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/crypto_sign/falcon-512/clean/keygen.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/crypto_sign/falcon-512/clean/pqclean.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/crypto_sign/falcon-512/clean/rng.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/crypto_sign/falcon-512/clean/sign.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/crypto_sign/falcon-512/clean/vrfy.c"
        )
        list(APPEND _mqtt_pq_sig_inc
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/common"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/crypto_sign/falcon-512/clean"
        )
    elseif(MQTT_TLS_SCHEME STREQUAL "HAWK512")
        list(APPEND _mqtt_pq_sig_src
            "${CMAKE_CURRENT_LIST_DIR}/hawk512_tls.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src/hawk_kgen.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src/hawk_sign.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src/hawk_vrfy.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src/ng_fxp.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src/ng_hawk.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src/ng_mp31.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src/ng_ntru.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src/ng_poly.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src/ng_zint31.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src/sha3.c"
        )
        list(APPEND _mqtt_pq_sig_inc
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src"
        )
    elseif(MQTT_TLS_SCHEME STREQUAL "MAYO1")
        list(APPEND _mqtt_pq_sig_src
            "${CMAKE_CURRENT_LIST_DIR}/../randombytes.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/common/fips202.c"
            "${CMAKE_CURRENT_LIST_DIR}/mayo1_tls.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/mayo-m4/crypto_sign/mayo1/ref/api.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/mayo-m4/crypto_sign/mayo1/ref/mayo.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/mayo-m4/crypto_sign/mayo1/ref/arithmetic.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/mayo-m4/crypto_sign/mayo1/ref/params.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/mayo-m4/crypto_sign/mayo1/ref/mem.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/mayo-m4/crypto_sign/mayo1/ref/aes_ctr.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/mayo-m4/submodules/pqm4/mupq/pqclean/common/aes.c"
        )
        list(APPEND _mqtt_pq_sig_inc
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/PQClean/common"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/mayo-m4/crypto_sign/mayo1/ref"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/mayo-m4/submodules/pqm4/mupq/pqclean/common"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/mayo-m4/submodules/pqm4/mupq/common"
        )
    endif()
    if(MQTT_TLS_SCHEME)
        list(APPEND _mqtt_pq_sig_inc "${CMAKE_CURRENT_LIST_DIR}")
    endif()

    set(_mqtt_tls_extra_src)
    set(_mqtt_tls_extra_inc)
    set(_mqtt_tls_extra_defs)
    if(MQTT_TLS_SCHEME)
        list(APPEND _mqtt_tls_extra_defs "MQTT_LIB_SCHEME_${MQTT_TLS_SCHEME}")
    endif()
    if(MQTT_TLS_NEEDS_RSA)
        list(APPEND _mqtt_tls_extra_defs MQTT_LIB_NEEDS_RSA)
    endif()
    if(MQTT_TLS_SNOVA2454)
        list(APPEND _mqtt_tls_extra_src
            "${CMAKE_CURRENT_LIST_DIR}/snova2454_tls.c"
            "${CMAKE_CURRENT_LIST_DIR}/../adapters/snova_randombytes.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/snova/src/sign.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/snova/src/snova_opt.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/snova/src/symmetric.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/snova/src/aes.c"
        )
        list(APPEND _mqtt_tls_extra_inc
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/snova/src"
        )
        list(APPEND _mqtt_tls_extra_defs
            WOLFSSL_SNOVA2454
            SNOVA_v=24
            SNOVA_o=5
            SNOVA_q=16
            SNOVA_l=4
            AESCTR
        )
        set_source_files_properties(
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/snova/src/sign.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/snova/src/snova_opt.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/snova/src/symmetric.c"
            "${CMAKE_CURRENT_LIST_DIR}/../third_party/snova/src/aes.c"
            PROPERTIES COMPILE_DEFINITIONS
                "SNOVA_OPT=opt;AESCTR;shake256=snova2454_shake256;shake128_init=snova2454_shake128_init;shake256_init=snova2454_shake256_init;shake_absorb=snova2454_shake_absorb;shake_finalize=snova2454_shake_finalize;shake_squeeze=snova2454_shake_squeeze;shake_squeeze_keep=snova2454_shake_squeeze_keep;shake_release=snova2454_shake_release"
        )
    endif()

    add_library(${target} STATIC
        ${wolfcrypt_src}
        ${wolfssl_tls_src}
        ${_mqtt_pq_sig_src}
        ${_mqtt_tls_extra_src}
    )
    target_include_directories(${target} PUBLIC
        "${WOLFSSL_ROOT}"
        "${CMAKE_CURRENT_LIST_DIR}/../config/wolfssl/tls"   # → user_settings.h
        "${CMAKE_CURRENT_LIST_DIR}"
        "${CMAKE_CURRENT_LIST_DIR}/.."
        ${_mqtt_pq_sig_inc}
        ${_mqtt_tls_extra_inc}
    )
    target_compile_definitions(${target} PUBLIC
        WOLFSSL_USER_SETTINGS
        RUNTIME_MEMORY_TLS_PHASES
        "MQTT_TLS_SP_INT_BITS=${sp_int_bits}"
        # HAVE_ECC is also set in user_settings.h but is declared here via
        # -D so that it is always defined at compile time, independent of
        # header include order or make dependency-tracking gaps.
        HAVE_ECC
        HAVE_STACKEFFICIENT
        ${_mqtt_tls_extra_defs}
    )
    if(MQTT_TLS_CLASSICAL_SP_OPT)
        target_compile_definitions(${target} PUBLIC MQTT_TLS_CLASSICAL_SP_OPT)
    endif()

    # Force-include error-crypt.h for the Pico RNG port (same fix as benchmark)
    set_source_files_properties(
        "${WOLFSSL_ROOT}/wolfcrypt/src/port/rpi_pico/pico.c"
        PROPERTIES COMPILE_OPTIONS
            "-include;wolfssl/wolfcrypt/error-crypt.h"
    )

    if(PICO_PLATFORM STREQUAL "rp2350-arm-s")
        target_compile_definitions(${target} PUBLIC WOLFSSL_SP_ARM_CORTEX_M_ASM)
    elseif(PICO_PLATFORM STREQUAL "rp2350-riscv")
        message(WARNING "wolfSSL Pico port not tested on RP2350 RISC-V")
    else()
        target_compile_definitions(${target} PUBLIC WOLFSSL_SP_ARM_THUMB_ASM)
    endif()

    target_link_libraries(${target} PUBLIC pico_stdlib pico_rand)
endfunction()

# -----------------------------------------------------------------------
# Classical RSA/ECDSA targets use wolfSSL's SP RSA/ECC fast paths. Keep these
# separate so PQ MQTT targets retain the smaller baseline TLS library.
if(NOT TARGET wolfssl_tls_classical)
    add_mqtt_wolfssl_tls(wolfssl_tls_classical 256 CLASSICAL_SP_OPT)
endif()

# RSA-2048 also needs wider SP integers for certificate parsing/signing.
if(NOT TARGET wolfssl_tls_rsa2048)
    add_mqtt_wolfssl_tls(wolfssl_tls_rsa2048 2048 CLASSICAL_SP_OPT NEEDS_RSA)
endif()

if(NOT TARGET wolfssl_tls_snova2454)
    add_mqtt_wolfssl_tls(wolfssl_tls_snova2454 256 SNOVA2454)
endif()

# -----------------------------------------------------------------------
# One isolated library PER PQ signature scheme — this is the actual fix for
# the "every mqtt_client_* firmware is the same size" problem: previously
# ML-DSA-44, Falcon-512, HAWK-512 and MAYO-1 all shared the single
# "wolfssl_tls" library above, which pulled in every algorithm's sources
# and feature macros regardless of which one the target used. Each of
# these now only compiles/enables its own scheme (see SCHEME arg wired
# through add_mqtt_wolfssl_tls() -> MQTT_LIB_SCHEME_* -> user_settings.h).
# -----------------------------------------------------------------------
if(NOT TARGET wolfssl_tls_mldsa44)
    add_mqtt_wolfssl_tls(wolfssl_tls_mldsa44 256 SCHEME MLDSA44)
endif()
if(NOT TARGET wolfssl_tls_falcon512)
    add_mqtt_wolfssl_tls(wolfssl_tls_falcon512 256 SCHEME FALCON512)
endif()
if(NOT TARGET wolfssl_tls_hawk512)
    add_mqtt_wolfssl_tls(wolfssl_tls_hawk512 256 SCHEME HAWK512)
endif()
if(NOT TARGET wolfssl_tls_mayo1)
    add_mqtt_wolfssl_tls(wolfssl_tls_mayo1 256 SCHEME MAYO1)
endif()

function(mqtt_use_ram_stack target stack_size)
    if(PICO_PLATFORM STREQUAL "rp2040")
        set(default_linker
            "${PICO_SDK_PATH}/src/rp2_common/pico_crt0/rp2040/memmap_default.ld")
    elseif(PICO_PLATFORM STREQUAL "rp2350-arm-s")
        set(default_linker
            "${PICO_SDK_PATH}/src/rp2_common/pico_crt0/rp2350/memmap_default.ld")
    else()
        message(FATAL_ERROR "MQTT RAM-stack linker unsupported on ${PICO_PLATFORM}")
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
        "__HeapLimit = ORIGIN(RAM) + LENGTH(RAM) - ${stack_size};"
        linker_text "${linker_text}")
    string(REPLACE
        "__StackLimit = ORIGIN(RAM) + LENGTH(RAM);"
        "__StackLimit = ORIGIN(RAM) + LENGTH(RAM) - ${stack_size};"
        linker_text "${linker_text}")
    set(linker "${CMAKE_CURRENT_BINARY_DIR}/${target}_memmap.ld")
    file(WRITE "${linker}" "${linker_text}")
    pico_set_linker_script(${target} "${linker}")
endfunction()

function(add_pq_mqtt_client target)
    cmake_parse_arguments(MQTT "STACK_IN_RAM;PLAIN_TRANSPORT" "TLS_LIB;STACK_SIZE;HEAP_SIZE" "" ${ARGN})
    if(MQTT_PLAIN_TRANSPORT)
        set(_mqtt_tls_lib)
        set(_mqtt_transport_src "${CMAKE_CURRENT_LIST_DIR}/plain_transport.c")
        set(_mqtt_transport_defs MQTT_TRANSPORT_PLAIN)
    elseif(MQTT_TLS_LIB)
        set(_mqtt_tls_lib "${MQTT_TLS_LIB}")
        set(_mqtt_transport_src "${CMAKE_CURRENT_LIST_DIR}/tls_transport.c")
        set(_mqtt_transport_defs)
    else()
        set(_mqtt_tls_lib wolfssl_tls)
        set(_mqtt_transport_src "${CMAKE_CURRENT_LIST_DIR}/tls_transport.c")
        set(_mqtt_transport_defs)
    endif()
    if(MQTT_STACK_SIZE)
        set(_mqtt_stack_size "${MQTT_STACK_SIZE}")
    else()
        set(_mqtt_stack_size 4096)
    endif()
    if(MQTT_HEAP_SIZE)
        set(_mqtt_heap_size "${MQTT_HEAP_SIZE}")
    else()
        set(_mqtt_heap_size 131072)
    endif()

    set(_mqtt_board_defs)
    if(PICO_BOARD STREQUAL "pico2_w")
        list(APPEND _mqtt_board_defs MQTT_BOARD_PICO2W)
    else()
        list(APPEND _mqtt_board_defs MQTT_BOARD_PICOW)
    endif()

    set(_mqtt_wifi_defs)
    if(NOT MQTT_WIFI_SSID STREQUAL "")
        list(APPEND _mqtt_wifi_defs "WIFI_SSID=\"${MQTT_WIFI_SSID}\"")
    endif()
    if(NOT MQTT_WIFI_PASS STREQUAL "")
        list(APPEND _mqtt_wifi_defs "WIFI_PASS=\"${MQTT_WIFI_PASS}\"")
    endif()
    if(NOT MQTT_BROKER_HOST STREQUAL "")
        list(APPEND _mqtt_wifi_defs "BROKER_HOST=\"${MQTT_BROKER_HOST}\"")
    endif()

    add_executable(${target}
        "${CMAKE_CURRENT_LIST_DIR}/main.c"
        "${_mqtt_transport_src}"
        "${CMAKE_CURRENT_LIST_DIR}/mqtt.c"
        "${CMAKE_CURRENT_LIST_DIR}/runtime_memory.c"
    )
    target_include_directories(${target} PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}"
        "${CMAKE_CURRENT_LIST_DIR}/certs"
    )
    target_compile_definitions(${target} PRIVATE
        PICO_STACK_SIZE=${_mqtt_stack_size}
        PICO_HEAP_SIZE=${_mqtt_heap_size}
        "SIGBENCH_BOARD_NAME=\"${PICO_BOARD}\""
        TLS_BENCH_ITERS=${TLS_BENCH_ITERS}
        TLS_BENCH_WARMUP=${TLS_BENCH_WARMUP}
        TLS_BENCH_CAMPAIGN=${TLS_BENCH_CAMPAIGN}
        ${_mqtt_board_defs}
        ${_mqtt_wifi_defs}
        ${_mqtt_transport_defs}
        ${MQTT_UNPARSED_ARGUMENTS}
    )
    if(MQTT_STACK_IN_RAM)
        mqtt_use_ram_stack(${target} "${_mqtt_stack_size}")
    endif()
    target_link_libraries(${target}
        ${_mqtt_tls_lib}
        pico_cyw43_arch_lwip_threadsafe_background
        pico_lwip_sntp
        hardware_adc
        pico_stdlib
    )
    target_link_options(${target} PRIVATE
        "-Wl,--wrap=_malloc_r"
        "-Wl,--wrap=_realloc_r"
        "-Wl,--wrap=_free_r"
    )
    if(TLS_BENCH_ITERS GREATER 0)
        # Allocation failures must return to the benchmark so the attempt row
        # can record their stage; Pico SDK's default is to panic immediately.
        target_compile_definitions(${target} PRIVATE PICO_MALLOC_PANIC=0)
        if(MQTT_TLS_BENCH_COMPACT_OUTPUT)
            target_compile_definitions(${target} PRIVATE MQTT_TLS_BENCH_COMPACT_OUTPUT=1)
        endif()
        if(_mqtt_tls_lib AND TARGET ${_mqtt_tls_lib})
            target_compile_definitions(${_mqtt_tls_lib} PUBLIC PICO_MALLOC_PANIC=0)
        endif()
    endif()
    pico_enable_stdio_usb(${target} 1)
    pico_enable_stdio_uart(${target} 0)
    pico_add_extra_outputs(${target})
endfunction()

# -----------------------------------------------------------------------
# mqtt_client_mldsa44  —  default ML-DSA-44 MQTT-over-mTLS application
# -----------------------------------------------------------------------
add_pq_mqtt_client(mqtt_client_mldsa44
    TLS_LIB wolfssl_tls_mldsa44
    STACK_SIZE 8192
    STACK_IN_RAM)

# -----------------------------------------------------------------------
# mqtt_client_hawk512  —  HAWK-512 mTLS target shell
# -----------------------------------------------------------------------
add_pq_mqtt_client(mqtt_client_hawk512
    TLS_LIB wolfssl_tls_hawk512
    STACK_SIZE 8192
    STACK_IN_RAM
    MQTT_SCHEME_HAWK512
    HAWK_AVX2=0)
target_include_directories(mqtt_client_hawk512 PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../third_party/hawk/src"
)

# -----------------------------------------------------------------------
# mqtt_client_falcon512  —  Falcon-512 mTLS target
# Falcon exhausts the Pico SDK's default 4 KiB SCRATCH_Y stack during TLS.
# Reserve a 64 KiB stack on Pico 2 W. Pico W cannot fit this alongside the
# 128 KiB TLS heap reservation, so it retains the 8 KiB diagnostic stack.
# -----------------------------------------------------------------------
set(_mqtt_falcon512_default_stack_size 65536)
if(PICO_BOARD STREQUAL "pico_w")
    set(_mqtt_falcon512_default_stack_size 8192)
endif()
if(MQTT_FALCON512_STACK_SIZE STREQUAL "")
    set(_mqtt_falcon512_stack_size ${_mqtt_falcon512_default_stack_size})
else()
    set(_mqtt_falcon512_stack_size ${MQTT_FALCON512_STACK_SIZE})
endif()
add_pq_mqtt_client(mqtt_client_falcon512
    TLS_LIB wolfssl_tls_falcon512
    STACK_SIZE ${_mqtt_falcon512_stack_size}
    STACK_IN_RAM
    MQTT_SCHEME_FALCON512)

# -----------------------------------------------------------------------
# mqtt_client_mayo1  —  MAYO-1 mTLS target shell
# MAYO also requires a stack larger than the default 4 KiB scratch region.
# -----------------------------------------------------------------------
add_pq_mqtt_client(mqtt_client_mayo1
    TLS_LIB wolfssl_tls_mayo1
    STACK_SIZE ${MQTT_MAYO1_STACK_SIZE}
    STACK_IN_RAM
    MQTT_SCHEME_MAYO1)

# -----------------------------------------------------------------------
# mqtt_client_snova_24_5_16_4  —  SNOVA-24-5-16-4 / oqs-provider snova2454
# -----------------------------------------------------------------------
add_pq_mqtt_client(mqtt_client_snova_24_5_16_4
    TLS_LIB wolfssl_tls_snova2454
    # 237,568 B was below the measured compressed-key verification demand.
    # 256 KiB is feasible on Pico 2 W while retaining heap headroom for TLS.
    STACK_SIZE ${MQTT_SNOVA2454_STACK_SIZE}
    HEAP_SIZE 131072
    STACK_IN_RAM
    MQTT_SCHEME_SNOVA_24_5_16_4)

# -----------------------------------------------------------------------
# mqtt_client_ecdsa_p256  —  ECDSA P-256 mTLS target
# -----------------------------------------------------------------------
set(_mqtt_ecdsa_p256_default_stack_size 4096)
set(_mqtt_ecdsa_p256_stack_location)
if(PICO_BOARD STREQUAL "pico2_w")
    set(_mqtt_ecdsa_p256_default_stack_size 8192)
    set(_mqtt_ecdsa_p256_stack_location STACK_IN_RAM)
endif()
if(MQTT_ECDSA_P256_STACK_SIZE STREQUAL "")
    set(_mqtt_ecdsa_p256_stack_size ${_mqtt_ecdsa_p256_default_stack_size})
else()
    set(_mqtt_ecdsa_p256_stack_size ${MQTT_ECDSA_P256_STACK_SIZE})
endif()
add_pq_mqtt_client(mqtt_client_ecdsa_p256
    TLS_LIB wolfssl_tls_classical
    STACK_SIZE ${_mqtt_ecdsa_p256_stack_size}
    ${_mqtt_ecdsa_p256_stack_location}
    MQTT_SCHEME_ECDSA_P256)

# -----------------------------------------------------------------------
# mqtt_client_rsa2048  —  RSA-2048 mTLS target
# -----------------------------------------------------------------------
add_pq_mqtt_client(mqtt_client_rsa2048
    TLS_LIB wolfssl_tls_rsa2048
    STACK_SIZE 8192
    STACK_IN_RAM
    MQTT_SCHEME_RSA2048)

# -----------------------------------------------------------------------
# mqtt_client_plain  —  plain MQTT over TCP, no TLS
# -----------------------------------------------------------------------
add_pq_mqtt_client(mqtt_client_plain
    PLAIN_TRANSPORT
    HEAP_SIZE ${MQTT_PLAIN_HEAP_SIZE})
