cmake_minimum_required(VERSION 3.13)
project(hello_gfortran_O2 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Optimization level matching original binary (-O2)
set(CMAKE_C_FLAGS_RELEASE "-O2")

# Source files (already exist in source tree)
set(SOURCES
    main.c
    src/core.c
)

add_executable(hello_gfortran_O2 ${SOURCES})

target_include_directories(hello_gfortran_O2 PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

# The binary imports gfortran runtime symbols (_gfortran_*).
# Link against libgfortran (provided by the system gfortran installation).
if(UNIX AND NOT APPLE)
    # Try to locate libgfortran via the gfortran compiler driver.
    find_program(GFORTRAN_EXECUTABLE NAMES gfortran)
    if(GFORTRAN_EXECUTABLE)
        execute_process(
            COMMAND ${GFORTRAN_EXECUTABLE} -print-file-name=libgfortran.so
            OUTPUT_VARIABLE LIBGFORTRAN_PATH
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        get_filename_component(LIBGFORTRAN_DIR "${LIBGFORTRAN_PATH}" DIRECTORY)
        if(LIBGFORTRAN_DIR)
            target_link_directories(hello_gfortran_O2 PRIVATE ${LIBGFORTRAN_DIR})
        endif()
    endif()
    target_link_libraries(hello_gfortran_O2 PRIVATE gfortran m)
else()
    target_link_libraries(hello_gfortran_O2 PRIVATE gfortran m)
endif()
