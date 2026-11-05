cmake_minimum_required(VERSION 3.20)
project(oot_pc_port VERSION 0.1.0 LANGUAGES C)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "The host scaffold requires 64-bit Windows.")
endif()

add_executable(oot-pc-port src/main.c src/host_win32.c)
target_compile_features(oot-pc-port PRIVATE c_std_17)
target_compile_definitions(oot-pc-port PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
if(MSVC)
    target_compile_options(oot-pc-port PRIVATE /W4)
else()
    target_compile_options(oot-pc-port PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_test(NAME host_self_test COMMAND oot-pc-port --self-test)

set(OOT_ZBIC_SOURCE "" CACHE PATH "Pinned external ZBIC dependency checkout")
if(OOT_ZBIC_SOURCE)
    find_package(Git REQUIRED)
    execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${OOT_ZBIC_SOURCE}" rev-parse HEAD
        RESULT_VARIABLE ZBIC_GIT_RESULT OUTPUT_VARIABLE ZBIC_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT ZBIC_GIT_RESULT EQUAL 0 OR NOT ZBIC_REVISION STREQUAL "491bb11b008cf57019a08fcd57beee5d3d24904d")
        message(FATAL_ERROR "ZBIC dependency revision mismatch. Run tools/build_zbic.py --fetch --fetch-only.")
    endif()
    execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${OOT_ZBIC_SOURCE}" status --porcelain --untracked-files=no
        RESULT_VARIABLE ZBIC_STATUS_RESULT OUTPUT_VARIABLE ZBIC_DIRTY)
    if(NOT ZBIC_STATUS_RESULT EQUAL 0 OR ZBIC_DIRTY)
        message(FATAL_ERROR "ZBIC dependency has modified tracked files.")
    endif()
    set(ZBIC_LIB "${OOT_ZBIC_SOURCE}/lib")
    add_executable(oot-zbic-decode tools/zbic_decode.c
        "${ZBIC_LIB}/common/debug.c" "${ZBIC_LIB}/common/entropy_common.c"
        "${ZBIC_LIB}/common/error_private.c" "${ZBIC_LIB}/common/fse_decompress.c"
        "${ZBIC_LIB}/common/xxhash.c" "${ZBIC_LIB}/common/zstd_common.c"
        "${ZBIC_LIB}/decompress/huf_decompress.c" "${ZBIC_LIB}/decompress/zstd_ddict.c"
        "${ZBIC_LIB}/decompress/zstd_decompress.c" "${ZBIC_LIB}/decompress/zstd_decompress_block.c")
    target_compile_features(oot-zbic-decode PRIVATE c_std_11)
    target_compile_definitions(oot-zbic-decode PRIVATE ZSTD_ZBIC_SUPPORT=1 ZSTD_LEGACY_SUPPORT=0 ZSTD_DISABLE_ASM=1)
    target_include_directories(oot-zbic-decode PRIVATE "${ZBIC_LIB}" "${ZBIC_LIB}/common")
    set_target_properties(oot-zbic-decode PROPERTIES OUTPUT_NAME zbic-decode
        RUNTIME_OUTPUT_DIRECTORY "$<1:${CMAKE_BINARY_DIR}/tools>")
    configure_file("${OOT_ZBIC_SOURCE}/LICENSE" "${CMAKE_BINARY_DIR}/tools/zbic-LICENSE.txt" COPYONLY)
endif()

find_package(Python3 3.10 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
    add_test(NAME input_inspection_tests
        COMMAND "${Python3_EXECUTABLE}" -B -m unittest discover -s "${CMAKE_CURRENT_SOURCE_DIR}/tests" -v)
    if(TARGET oot-zbic-decode)
        set_tests_properties(input_inspection_tests PROPERTIES
            ENVIRONMENT "OOT_ZBIC_DECODER=$<TARGET_FILE:oot-zbic-decode>")
    endif()
endif()
