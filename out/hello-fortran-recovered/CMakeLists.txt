cmake_minimum_required(VERSION 3.12)
project(hello_fortran C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# The original binary links against libgfortran (Fortran runtime symbols
# such as _gfortran_st_write, _gfortran_set_args, etc. appear in the
# import list).  Locate libgfortran on the host system.
if(UNIX AND NOT APPLE)
    find_library(GFORTRAN_LIBRARY
        NAMES gfortran
        PATHS
            /usr/lib
            /usr/lib64
            /usr/lib/x86_64-linux-gnu
            /usr/lib/gcc/x86_64-linux-gnu/13
            /usr/lib/gcc/x86_64-linux-gnu/12
            /usr/lib/gcc/x86_64-linux-gnu/11
            /usr/lib/gcc/x86_64-linux-gnu/10
        )
    if(NOT GFORTRAN_LIBRARY)
        message(FATAL_ERROR "libgfortran not found. Install gfortran (e.g. 'sudo apt install gfortran').")
    endif()
else()
    find_library(GFORTRAN_LIBRARY NAMES gfortran)
endif()

add_executable(hello_fortran
    src/hello.c
    src/main.c
)

target_include_directories(hello_fortran PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(hello_fortran PRIVATE
    ${GFORTRAN_LIBRARY}
)

if(UNIX)
    target_link_libraries(hello_fortran PRIVATE m)
endif()
