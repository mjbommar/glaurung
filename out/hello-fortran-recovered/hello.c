// hello.c
// Recovered from hello-gfortran-O2 by glaurung source-recovery

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/**
 * @brief Fortran program entry point (`MAIN__`) emitted by gfortran for hello.f90.
 *
 * Reconstructed body of the Fortran `program hello`. Performs the following
 * sequence of list-directed writes to unit 6 via the libgfortran runtime,
 * interleaved with a scan of the command-line arguments:
 *
 *  1. Prints the greeting `"Hello, World from Fortran!"`.
 *  2. Queries the argument count via `_gfortran_iargc()` and, for each
 *     argument index `1..nargs`, fetches the argument into a 100-byte
 *     buffer with `_gfortran_get_command_argument_i4` and accumulates
 *     `_gfortran_string_len_trim(100, arg_buf)` into `total_len`.
 *  3. Prints `"Number of arguments:"` followed by `nargs`.
 *  4. Prints `"Total argument length:"` followed by `total_len`.
 *  5. Prints `"Global counter:"` followed by the value of the COMMON-block
 *     variable `global_counter` (extern, located at 0x20c0 in the binary).
 *  6. Inlines a call to `my_sub`: increments the SAVE'd static counter
 *     `call_count_1`, prints `"Fortran subroutine called"`, then prints
 *     `"Subroutine called" <call_count_1> "times"`.
 *
 * Each WRITE statement is bracketed by `_gfortran_st_write` /
 * `_gfortran_st_write_done` calls on a stack-allocated `gfc_dt` descriptor
 * whose `flags` field is set to `0x600000080` (list-directed output to
 * unit 6) and whose `filename`/`line` fields point at
 * `/workspace/source/fortran/hello.f90` and the originating source line.
 *
 * @note This is the program's main entry — it takes no parameters and
 *       returns no value. The C runtime startup invokes it indirectly
 *       through libgfortran's `_gfortran_set_args` / `main` shim.
 * @note `call_count_1` is a file-scope static persisting across calls,
 *       reflecting Fortran's `SAVE` semantics for `my_sub`'s local.
 * @note Argument truncation: each argument is read into a fixed 100-byte
 *       buffer; longer arguments are silently truncated by
 *       `_gfortran_get_command_argument_i4`.
 *
 * @return None.
 */
/*
 * Fortran MAIN program (compiled by gfortran).
 *
 * Equivalent Fortran source:
 *
 *   program hello
 *     implicit none
 *     integer :: i, nargs, total_len
 *     character(len=100) :: arg
 *     integer :: global_counter
 *     common /globals/ global_counter
 *
 *     print *, "Hello, World from Fortran!"
 *
 *     nargs = command_argument_count()
 *     total_len = 0
 *     do i = 1, nargs
 *        call get_command_argument(i, arg)
 *        total_len = total_len + len_trim(arg)
 *     end do
 *
 *     print *, "Number of arguments:", nargs
 *     print *, "Total argument length:", total_len
 *     print *, "Global counter:", global_counter
 *     call my_sub()
 *   end program
 *
 *   subroutine my_sub()       ! inlined into MAIN by the optimizer
 *     integer, save :: call_count = 0
 *     call_count = call_count + 1
 *     print *, "Fortran subroutine called"
 *     print *, "Subroutine called", call_count, "times"
 *   end subroutine
 *
 * What appears below is the C-level reconstruction of the code gfortran
 * actually emitted for MAIN__.
 */

extern int  global_counter;          /* address 0x20c0 in the binary */
static int  call_count_1;            /* my_sub's SAVE'd local        */

/* gfortran runtime — opaque I/O state descriptor (st_parameter_dt). */
typedef struct gfc_dt gfc_dt;

/* Common header word stuffed into the descriptor before each WRITE.
 * Bit pattern 0x600000080 selects list-directed output to unit 6. */
#define GFC_IO_FLAGS  0x600000080LL

extern void _gfortran_st_write(gfc_dt *);
extern void _gfortran_transfer_character_write(gfc_dt *, const char *, int);
extern void _gfortran_transfer_integer_write(gfc_dt *, const void *, int);
extern void _gfortran_st_write_done(gfc_dt *);
extern int  _gfortran_iargc(void);
extern void _gfortran_get_command_argument_i4(int *idx, char *buf,
                                              int unused1, int unused2,
                                              int buflen);
extern int  _gfortran_string_len_trim(int buflen, const char *buf);

static const char SOURCE_PATH[] = "/workspace/source/fortran/hello.f90";

void MAIN__(void)
{
    gfc_dt dt;
    int    arg_index;
    int    nargs;
    int    total_len;
    char   arg_buf[100];

    /* print *, "Hello, World from Fortran!" */
    dt.flags    = GFC_IO_FLAGS;
    dt.filename = SOURCE_PATH;
    dt.line     = 12;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Hello, World from Fortran!", 26);
    _gfortran_st_write_done(&dt);

    /* nargs = command_argument_count() */
    nargs     = _gfortran_iargc();
    total_len = 0;

    /* do i = 1, nargs
     *    call get_command_argument(i, arg_buf)
     *    total_len = total_len + len_trim(arg_buf)
     * end do
     */
    for (arg_index = 1; arg_index <= nargs; ++arg_index) {
        _gfortran_get_command_argument_i4(&arg_index, arg_buf, 0, 0, 100);
        total_len += _gfortran_string_len_trim(100, arg_buf);
    }

    /* print *, "Number of arguments:", nargs */
    dt.flags    = GFC_IO_FLAGS;
    dt.filename = SOURCE_PATH;
    dt.line     = 25;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Number of arguments:", 20);
    _gfortran_transfer_integer_write(&dt, &nargs, 4);
    _gfortran_st_write_done(&dt);

    /* print *, "Total argument length:", total_len */
    dt.flags    = GFC_IO_FLAGS;
    dt.filename = SOURCE_PATH;
    dt.line     = 26;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Total argument length:", 22);
    _gfortran_transfer_integer_write(&dt, &total_len, 4);
    _gfortran_st_write_done(&dt);

    /* print *, "Global counter:", global_counter */
    dt.flags    = GFC_IO_FLAGS;
    dt.filename = SOURCE_PATH;
    dt.line     = 27;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Global counter:", 15);
    _gfortran_transfer_integer_write(&dt, &global_counter, 4);
    _gfortran_st_write_done(&dt);

    /* --- call my_sub() (inlined) --- */
    ++call_count_1;

    /* print *, "Fortran subroutine called" */
    dt.flags    = GFC_IO_FLAGS;
    dt.filename = SOURCE_PATH;
    dt.line     = 40;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Fortran subroutine called", 25);
    _gfortran_st_write_done(&dt);

    /* print *, "Subroutine called", call_count, "times" */
    dt.flags    = GFC_IO_FLAGS;
    dt.filename = SOURCE_PATH;
    dt.line     = 41;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Subroutine called", 17);
    _gfortran_transfer_integer_write(&dt, &call_count_1, 4);
    _gfortran_transfer_character_write(&dt, "times", 5);
    _gfortran_st_write_done(&dt);
}

