include(CMakeParseArguments)
set(SIGBENCH_MAYO_PROJECT_ROOT "${CMAKE_CURRENT_LIST_DIR}/..")

function(sigbench_add_mayo)
    set(oneValueArgs TARGET ROOT PARAM DISPLAY_NAME NIST_LEVEL KEY_HEADER
        SIG_BUFFER STACK_SIZE MAIN_DRIVER MSG_LEN_OVERRIDE)
    cmake_parse_arguments(SB "" "${oneValueArgs}" "" ${ARGN})
    foreach(required TARGET ROOT PARAM DISPLAY_NAME NIST_LEVEL KEY_HEADER
                     SIG_BUFFER STACK_SIZE)
        if(NOT SB_${required})
            message(FATAL_ERROR "sigbench_add_mayo: missing ${required}")
        endif()
    endforeach()

    set(impl "${SB_ROOT}/crypto_sign/${SB_PARAM}/ref")
    set(common "${PQCLEAN_ROOT}/common")
    set(mupq_common "${SB_ROOT}/submodules/pqm4/mupq/common")
    if(NOT PQCLEAN_ROOT OR NOT EXISTS "${impl}/api.h" OR NOT EXISTS "${SB_KEY_HEADER}")
        message(STATUS "Skipping ${SB_TARGET}: MAYO source, static key, or PQCLEAN_ROOT missing")
        return()
    endif()

    if(SB_MAIN_DRIVER)
        set(_main_src "${SB_MAIN_DRIVER}")
    else()
        set(_main_src "${SIGBENCH_MAYO_PROJECT_ROOT}/benchmark_main.c")
    endif()
    if(SB_MSG_LEN_OVERRIDE)
        set(_mayo_msg_len "${SB_MSG_LEN_OVERRIDE}")
    else()
        set(_mayo_msg_len "${SIGBENCH_MSG_LEN}")
    endif()

    get_filename_component(key_dir "${SB_KEY_HEADER}" DIRECTORY)
    get_filename_component(key_file "${SB_KEY_HEADER}" NAME)
    add_executable(${SB_TARGET}
        "${_main_src}"
        "${SIGBENCH_MAYO_PROJECT_ROOT}/bench.c"
        "${SIGBENCH_MAYO_PROJECT_ROOT}/randombytes.c"
        "${SIGBENCH_MAYO_PROJECT_ROOT}/adapters/adapter_mayo.c"
        "${impl}/api.c"
        "${impl}/mayo.c"
        "${impl}/arithmetic.c"
        "${impl}/params.c"
        "${impl}/mem.c"
        "${impl}/aes_ctr.c"
        "${common}/aes.c"
        "${common}/fips202.c"
    )
    target_include_directories(${SB_TARGET} PRIVATE
        "${SIGBENCH_MAYO_PROJECT_ROOT}" "${impl}" "${mupq_common}"
        "${common}" "${key_dir}"
    )
    target_compile_definitions(${SB_TARGET} PRIVATE
        # Select MAYO's low-stack public-map evaluator. Without this, MAYO-1
        # verification creates a roughly 740 KiB frame, while signing needs
        # only about 193 KiB and can misleadingly appear to work on-device.
        HAVE_STACKEFFICIENT
        BENCH_ITERS=${SIGBENCH_ITERS}
        BENCH_WARMUP=${SIGBENCH_WARMUP}
        MSG_LEN=${_mayo_msg_len}
        SIG_BUF=${SB_SIG_BUFFER}
        PICO_STACK_SIZE=${SB_STACK_SIZE}
        MAYO_NIST_LEVEL=${SB_NIST_LEVEL}
        "MAYO_DISPLAY_NAME=\"${SB_DISPLAY_NAME}\""
        "MAYO_API_HEADER=\"api.h\""
        "STATIC_KEYS_HEADER=\"${key_file}\""
        "SIGBENCH_BOARD_NAME=\"${PICO_BOARD}\""
    )

    # The Pico SDK normally places the main stack in the dedicated 4 KiB
    # SCRATCH_Y bank. MAYO's memory-reduced C implementation still needs a
    # much larger contiguous call frame, so reserve that stack from normal
    # SRAM and let the linker prove that stack + data fit without overlap.
    if(PICO_PLATFORM STREQUAL "rp2040")
        set(default_linker
            "${PICO_SDK_PATH}/src/rp2_common/pico_crt0/rp2040/memmap_default.ld")
    elseif(PICO_PLATFORM STREQUAL "rp2350-arm-s")
        set(default_linker
            "${PICO_SDK_PATH}/src/rp2_common/pico_crt0/rp2350/memmap_default.ld")
    else()
        message(FATAL_ERROR "MAYO large-stack linker unsupported on ${PICO_PLATFORM}")
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
        "__HeapLimit = ORIGIN(RAM) + LENGTH(RAM) - ${SB_STACK_SIZE};"
        linker_text "${linker_text}")
    string(REPLACE
        "__StackLimit = ORIGIN(RAM) + LENGTH(RAM);"
        "__StackLimit = ORIGIN(RAM) + LENGTH(RAM) - ${SB_STACK_SIZE};"
        linker_text "${linker_text}")
    set(mayo_linker "${CMAKE_CURRENT_BINARY_DIR}/${SB_TARGET}_memmap.ld")
    file(WRITE "${mayo_linker}" "${linker_text}")
    pico_set_linker_script(${SB_TARGET} "${mayo_linker}")

    target_link_libraries(${SB_TARGET} pico_stdlib pico_rand hardware_clocks)
    pico_enable_stdio_usb(${SB_TARGET} 1)
    pico_enable_stdio_uart(${SB_TARGET} 0)
    pico_add_extra_outputs(${SB_TARGET})
endfunction()
