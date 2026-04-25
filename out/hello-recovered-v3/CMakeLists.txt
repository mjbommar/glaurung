cmake_minimum_required(VERSION 3.10)
project(hello CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Stack protector flag observed in binary (__stack_chk_fail)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fstack-protector-strong -Wall)
endif()

add_executable(hello src/hello.cpp)

if(UNIX AND NOT APPLE)
    target_link_libraries(hello PRIVATE pthread)
endif()

install(TARGETS hello RUNTIME DESTINATION bin)
