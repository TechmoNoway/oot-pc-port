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

find_package(Python3 3.10 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
    add_test(NAME input_inspection_tests
        COMMAND "${Python3_EXECUTABLE}" -B -m unittest discover -s "${CMAKE_CURRENT_SOURCE_DIR}/tests" -v)
endif()
