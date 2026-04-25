// main.c
// Recovered from hello-gfortran-O2 by glaurung source-recovery

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/**
 * @brief Program entry point for a GNU Fortran-compiled executable.
 *
 * Performs the standard libgfortran startup sequence required before
 * Fortran code may execute: it forwards the process command-line to the
 * runtime via _gfortran_set_args(), installs the compiler-generated
 * runtime options table (options_6_2, of length 7) via
 * _gfortran_set_options(), and then transfers control to the Fortran
 * PROGRAM unit through MAIN__(). On return from the Fortran program,
 * main() returns 0 to the operating system.
 *
 * @param argc Number of command-line arguments, passed unchanged to
 *             _gfortran_set_args().
 * @param argv Vector of command-line argument strings, passed unchanged
 *             to _gfortran_set_args() so they are visible to Fortran
 *             intrinsics such as GET_COMMAND_ARGUMENT.
 *
 * @return Always 0; any abnormal termination is handled inside the
 *         libgfortran runtime (e.g. via STOP/ERROR STOP) and does not
 *         return through this function.
 * @retval 0 The Fortran program completed and returned normally.
 *
 * @note This function is the C shim emitted by gfortran; the user's
 *       Fortran PROGRAM is invoked as MAIN__(). The binary therefore
 *       has a runtime dependency on libgfortran.so.5.
 */
int main(int argc, char **argv)
{
    _gfortran_set_args(argc, argv);
    _gfortran_set_options(7, options_6_2);
    MAIN__();
    return 0;
}

