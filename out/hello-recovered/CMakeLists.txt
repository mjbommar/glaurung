cmake_minimum_required(VERSION 3.13)
project(hello LANGUAGES C CXX)

# The binary's import list shows C++ symbols (libstdc++, __cxa_*, __gxx_personality_v0,
# std::ostream, std::string, etc.) even though the recovered source files have a .c
# extension. We therefore compile them as C++ and link the C++ runtime.

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
 endif()

# Stack protector was observed via __stack_chk_fail.
add_compile_options(-Wall -Wextra -fstack-protector-strong)

set(HELLO_SOURCES
    src/main.c
    src/vector_string.c
    src/iostream_support.c
)

# crtstuff.c is normally provided by the toolchain (libgcc). Only build the recovered
# copy if it is actually present on disk and the user explicitly opts in, because
# linking it alongside the real crtstuff will duplicate _ITM_* / __cxa_finalize stubs.
option(HELLO_BUILD_CRTSTUFF "Also compile the recovered crt/crtstuff.c (advanced)" OFF)
if(HELLO_BUILD_CRTSTUFF AND EXISTS "${CMAKE_SOURCE_DIR}/crt/crtstuff.c")
    list(APPEND HELLO_SOURCES crt/crtstuff.c)
endif()

# Force the recovered *.c files to be treated as C++ so the std:: / __cxa_* / new /
# delete symbols resolve correctly.
set_source_files_properties(${HELLO_SOURCES} PROPERTIES LANGUAGE CXX)

add_executable(hello ${HELLO_SOURCES})

target_include_directories(hello PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    target_link_libraries(hello PRIVATE Threads::Threads)
    # libstdc++ and libgcc_s are pulled in automatically by the CXX linker driver.
    target_link_libraries(hello PRIVATE ${CMAKE_DL_LIBS})
endif()

if(WIN32)
    # Not a primary target, but keep a stub branch so the file is portable.
    target_compile_definitions(hello PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

install(TARGETS hello RUNTIME DESTINATION bin)
