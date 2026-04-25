cmake_minimum_required(VERSION 3.10)
project(hello CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Recommended hardening / warning flags on Linux
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -fstack-protector-strong)
endif()

add_executable(hello
    src/hello.cpp
)

# Binary imports indicate the C++ standard library and pthread are required.
# libstdc++ is linked automatically by the C++ driver; pthread is linked
# explicitly for portability with std::thread / atexit handlers.
if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    target_link_libraries(hello PRIVATE Threads::Threads)
endif()

install(TARGETS hello RUNTIME DESTINATION bin)
