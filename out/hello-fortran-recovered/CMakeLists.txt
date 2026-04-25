cmake_minimum_required(VERSION 3.10)
project(hello_gfortran_O2 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Optimization level matches the original binary (-O2)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_RELEASE "-O2")

add_executable(hello_gfortran_O2
    main.c
)

# The binary imports a number of libgfortran runtime symbols
# (_gfortran_set_args, _gfortran_st_write, _gfortran_iargc, ...)
# so we must link against gfortran's runtime library.
if(UNIX AND NOT APPLE)
    # Try to locate libgfortran via the gfortran compiler driver
    find_program(GFORTRAN_EXECUTABLE NAMES gfortran)
    if(GFORTRAN_EXECUTABLE)
        execute_process(
            COMMAND ${GFORTRAN_EXECUTABLE} -print-file-name=libgfortran.so
            OUTPUT_VARIABLE LIBGFORTRAN_PATH
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    endif()

    if(LIBGFORTRAN_PATH AND EXISTS "${LIBGFORTRAN_PATH}")
        target_link_libraries(hello_gfortran_O2 PRIVATE ${LIBGFORTRAN_PATH})
    else()
        # Fall back to plain -lgfortran; the linker will search default paths.
        target_link_libraries(hello_gfortran_O2 PRIVATE gfortran)
    endif()

    # libgfortran typically pulls in libquadmath and libm.
    target_link_libraries(hello_gfortran_O2 PRIVATE m)
else()
    target_link_libraries(hello_gfortran_O2 PRIVATE gfortran m)
endif()
