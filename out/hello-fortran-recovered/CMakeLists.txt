cmake_minimum_required(VERSION 3.10)
project(hello_fortran C Fortran)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# The binary imports many _gfortran_* symbols, indicating linkage against
# the GNU Fortran runtime. Locate libgfortran so it can be linked in.
find_library(GFORTRAN_LIBRARY
    NAMES gfortran
    PATHS
        /usr/lib
        /usr/lib/x86_64-linux-gnu
        /usr/lib64
        /usr/local/lib
)

if(NOT GFORTRAN_LIBRARY)
    message(WARNING "libgfortran not found via find_library; falling back to -lgfortran")
    set(GFORTRAN_LIBRARY gfortran)
endif()

set(HELLO_FORTRAN_SOURCES
    main.c
    hello.c
)

add_executable(hello_fortran ${HELLO_FORTRAN_SOURCES})

target_link_libraries(hello_fortran PRIVATE ${GFORTRAN_LIBRARY})

if(UNIX AND NOT APPLE)
    # Standard Linux runtime helpers seen in the import list
    # (__libc_start_main, __cxa_finalize, _ITM_*) come from libc/libgcc and
    # are linked automatically by the C driver.
    target_link_libraries(hello_fortran PRIVATE m)
endif()

install(TARGETS hello_fortran RUNTIME DESTINATION bin)
