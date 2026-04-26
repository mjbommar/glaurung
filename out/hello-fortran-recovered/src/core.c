// src/core.c
// Recovered from hello-gfortran-O2 by glaurung source-recovery

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "gfortran_runtime.h"

/**
 * @brief Fortran program entry point (gfortran `MAIN__`) for `hello.f90`.
 *
 * This is the lowered body of the Fortran `program hello` unit. When invoked
 * by the libgfortran startup shim it performs the following sequence of
 * list-directed `print *` statements and runtime calls:
 *
 *   1. Prints the banner `"Hello, World from Fortran!"` (source line 12).
 *   2. Queries the process command-line argument count via
 *      `_gfortran_iargc()`.
 *   3. Iterates `i = 1 .. nargs`, fetching each argument into a 100-byte
 *      buffer with `_gfortran_get_command_argument_i4` and accumulating the
 *      trimmed length returned by `_gfortran_string_len_trim` into
 *      `total_len`.
 *   4. Prints `"Number of arguments:"` followed by `nargs` (line 25).
 *   5. Prints `"Total argument length:"` followed by `total_len` (line 26).
 *   6. Prints `"Global counter:"` followed by the value of the module-level
 *      integer `global_counter` (line 27, originally at address 0x20c0 /
 *      offset 8384 in the binary).
 *   7. Inlines a call to `my_subroutine()`, which increments the file-scope
 *      counter `subroutine_invocations`, prints
 *      `"Fortran subroutine called"` (line 40), then prints
 *      `"Subroutine called"`, the static `call_count.1`, and `"times"`
 *      (line 41).
 *
 * All I/O goes through a stack-allocated `st_parameter_dt` descriptor whose
 * `common_flags` is set to `0x600000080` and whose `filename` points at the
 * embedded source path `"/workspace/source/fortran/hello.f90"`.
 *
 * @return None. The function takes no parameters and returns no value; it is
 *         invoked once by the gfortran-generated `main()` wrapper.
 *
 * @note This symbol is the conventional gfortran entry name for a Fortran
 *       `program` unit and is not intended to be called directly from C.
 *       Calling it requires that libgfortran has already been initialized
 *       (normally done by the `main()` produced by gfortran which calls
 *       `_gfortran_set_args` / `_gfortran_set_options` before `MAIN__`).
 *
 * @note The argument buffer is fixed at 100 characters; arguments longer
 *       than that are truncated by `_gfortran_get_command_argument_i4`,
 *       which still has its trimmed length measured over the 100-byte
 *       buffer.
 *
 * @code
 *     // Typical invocation (from the gfortran-generated main):
 *     _gfortran_set_args(argc, argv);
 *     _gfortran_set_options(...);
 *     MAIN__();
 * @endcode
 */
/*
 * Fortran MAIN program (compiled by gfortran).
 *
 * Equivalent Fortran source:
 *
 *     program hello
 *         integer :: i, nargs, total_len
 *         character(len=100) :: arg
 *         print *, "Hello, World from Fortran!"
 *         nargs = command_argument_count()
 *         total_len = 0
 *         do i = 1, nargs
 *             call get_command_argument(i, arg)
 *             total_len = total_len + len_trim(arg)
 *         end do
 *         print *, "Number of arguments:", nargs
 *         print *, "Total argument length:", total_len
 *         print *, "Global counter:", global_counter
 *         call my_subroutine()
 *     end program
 *
 * The decompiled body is the C-level lowering produced by gfortran's
 * runtime calling convention (libgfortran).  We reproduce it here as
 * plain C so the libgfortran call sequence stays faithful to the binary.
 */

extern void _gfortran_st_write(void *dt);
extern void _gfortran_transfer_character_write(void *dt, const char *s, int len);
extern void _gfortran_transfer_integer_write(void *dt, const void *p, int kind);
extern void _gfortran_st_write_done(void *dt);
extern int  _gfortran_iargc(void);
extern void _gfortran_get_command_argument_i4(int *idx, char *buf,
                                              int a, int b, int buflen);
extern int  _gfortran_string_len_trim(int buflen, const char *buf);

/* st_parameter_dt is now defined canonically in gfortran_runtime.h
 * (Task P) — single source of truth across every recovered module. */

static const char source_path[] = "/workspace/source/fortran/hello.f90";

/* File-scope globals referenced by the binary. */
/* Bug W: these were originally declared `extern` by the rewriter, but
 * the symbol table shows they are LOCAL statics in the binary
 * (`call_count.1` at 0x4014, the my_subroutine SAVE'd counter), not
 * external imports. Promote to file-scope statics with zero-init —
 * matches the binary's .bss layout and lets the recovered tree link. */
extern int global_counter;       /* address 0x20c0 in the original */
static int call_count_1;         /* call_count.1 – static in subroutine */
static int subroutine_invocations;  /* &[var7+0x4014] – bumped before call (Bug W) */

void MAIN__(void)
{
    /* Bug X: zero-initialise the descriptor so libgfortran's
     * private state starts with sane defaults. The original
     * gfortran-emitted code keeps a stack-resident descriptor
     * across all I/O calls in the routine, but reusing one
     * uninitialised in C tickles libgfortran's "is this a fresh
     * stream?" check and crashes. {0} keeps the recovered tree
     * runnable until the rewriter learns the full descriptor
     * init sequence. */
    st_parameter_dt dt = {0};
    char  arg_buf[100];
    int   arg_index;
    int   nargs;
    int   total_len;
    int   i;

    /* print *, "Hello, World from Fortran!" */
    dt.common_flags = 0x600000080L;
    dt.filename     = source_path;
    dt.line         = 12;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Hello, World from Fortran!", 26);
    _gfortran_st_write_done(&dt);

    /* nargs = command_argument_count() */
    nargs = _gfortran_iargc();

    total_len = 0;
    /* do i = 1, nargs ; total_len = total_len + len_trim(arg_i) ; end do */
    for (i = 1; i <= nargs; ++i) {
        arg_index = i;
        _gfortran_get_command_argument_i4(&arg_index, arg_buf, 0, 0, 100);
        total_len += _gfortran_string_len_trim(100, arg_buf);
    }

    /* print *, "Number of arguments:", nargs */
    dt.common_flags = 0x600000080L;
    dt.filename     = source_path;
    dt.line         = 25;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Number of arguments:", 20);
    _gfortran_transfer_integer_write(&dt, &nargs, 4);
    _gfortran_st_write_done(&dt);

    /* print *, "Total argument length:", total_len */
    dt.filename = source_path;
    dt.common_flags = 0x600000080L;
    dt.line         = 26;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Total argument length:", 22);
    _gfortran_transfer_integer_write(&dt, &total_len, 4);
    _gfortran_st_write_done(&dt);

    /* print *, "Global counter:", global_counter */
    dt.filename = source_path;
    dt.common_flags = 0x600000080L;
    dt.line         = 27;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Global counter:", 15);
    _gfortran_transfer_integer_write(&dt, (void *)8384, 4);
    _gfortran_st_write_done(&dt);

    /* Inlined call to my_subroutine(): */
    subroutine_invocations += 1;

    dt.filename = source_path;
    dt.common_flags = 0x600000080L;
    dt.line         = 40;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Fortran subroutine called", 25);
    _gfortran_st_write_done(&dt);

    dt.filename = source_path;
    dt.common_flags = 0x600000080L;
    dt.line         = 41;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Subroutine called", 17);
    _gfortran_transfer_integer_write(&dt, &call_count_1, 4);
    _gfortran_transfer_character_write(&dt, "times", 5);
    _gfortran_st_write_done(&dt);
}

