cmake_minimum_required(VERSION 3.10)
project(hello CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(hello
    src/main.cpp
    src/print_message.cpp
)

target_include_directories(hello PRIVATE src)

# Stack protector seen in binary imports (__stack_chk_fail)
if(NOT WIN32)
    target_compile_options(hello PRIVATE -fstack-protector-strong)
endif()

# pthread / dl typical on linux; not strictly required by import list but harmless
if(UNIX AND NOT APPLE)
    find_package(Threads)
    if(Threads_FOUND)
        target_link_libraries(hello PRIVATE Threads::Threads)
    endif()
endif()

install(TARGETS hello RUNTIME DESTINATION bin)
