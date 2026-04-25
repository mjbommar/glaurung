// src/core.c
// Recovered from hello-gfortran-O2 by glaurung source-recovery

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/**
 * @brief TODO — describe this function.
 *
 * Auto-generated placeholder; no LLM was available to write docs.
 */
/* Reconstructed Fortran PROGRAM main, lowered to C against libgfortran. */

#include <stdint.h>
#include <string.h>

/* gfortran I/O descriptor (st_parameter_dt). Only the few fields the
 * compiler actually writes are modelled here; the rest is opaque scratch. */
typedef struct {
    int64_t  common;        /* packed flags|unit  (0x600000080 == unit=6, flags=0x80) */
    const char *filename;   /* source file for runtime diagnostics */
    int32_t  line;          /* source line number */
    char     pad[512];      /* remainder of the 528-byte descriptor */
} st_parameter_dt;

extern void _gfortran_st_write(st_parameter_dt *);
extern void _gfortran_st_write_done(st_parameter_dt *);
extern void _gfortran_transfer_character_write(st_parameter_dt *, const char *, int32_t);
extern void _gfortran_transfer_integer_write(st_parameter_dt *, const void *, int32_t);
extern int32_t _gfortran_iargc(void);
extern void _gfortran_get_command_argument_i4(int32_t *number,
                                              char *value, int32_t v1, int32_t v2,
                                              int32_t value_len);
extern int32_t _gfortran_string_len_trim(int32_t len, const char *s);

/* SAVEd integer in a module / BSS slot, printed as "Global counter:". */
extern int32_t global_counter;
/* SAVEd local of the contained subroutine; mangled as call_count.1 by gfortran. */
extern int32_t call_count_1;

#define IO_UNIT6_FLAGS  ((int64_t)0x600000080LL)
static const char SRC_FILE[] = "/workspace/source/fortran/hello.f90";

void MAIN__(void)
{
    st_parameter_dt dt;
    int32_t  num_args;
    int32_t  total_len;
    int32_t  arg_index;
    char     arg_buf[100];

    /* PRINT *, "Hello, World from Fortran!"   ! line 12 */
    dt.common   = IO_UNIT6_FLAGS;
    dt.filename = SRC_FILE;
    dt.line     = 12;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Hello, World from Fortran!", 26);
    _gfortran_st_write_done(&dt);

    /* num_args = COMMAND_ARGUMENT_COUNT() */
    num_args  = _gfortran_iargc();
    total_len = 0;

    /* do i = 1, num_args
     *     call get_command_argument(i, arg_buf)
     *     total_len = total_len + len_trim(arg_buf)
     * end do
     */
    for (arg_index = 1; arg_index <= num_args; ++arg_index) {
        _gfortran_get_command_argument_i4(&arg_index, arg_buf, 0, 0, sizeof arg_buf);
        total_len += _gfortran_string_len_trim(sizeof arg_buf, arg_buf);
    }

    /* PRINT *, "Number of arguments:", num_args            ! line 25 */
    dt.common   = IO_UNIT6_FLAGS;
    dt.filename = SRC_FILE;
    dt.line     = 25;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Number of arguments:", 20);
    _gfortran_transfer_integer_write(&dt, &num_args, 4);
    _gfortran_st_write_done(&dt);

    /* PRINT *, "Total argument length:", total_len         ! line 26 */
    dt.common   = IO_UNIT6_FLAGS;
    dt.filename = SRC_FILE;
    dt.line     = 26;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Total argument length:", 22);
    _gfortran_transfer_integer_write(&dt, &total_len, 4);
    _gfortran_st_write_done(&dt);

    /* PRINT *, "Global counter:", global_counter           ! line 27 */
    dt.common   = IO_UNIT6_FLAGS;
    dt.filename = SRC_FILE;
    dt.line     = 27;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Global counter:", 15);
    _gfortran_transfer_integer_write(&dt, &global_counter, 4);
    _gfortran_st_write_done(&dt);

    /* CALL my_subroutine() -- inlined by the compiler:
     *     call_count_1 = call_count_1 + 1
     *     PRINT *, "Fortran subroutine called"             ! line 40
     *     PRINT *, "Subroutine called", call_count_1, "times" ! line 41
     */
    call_count_1 += 1;

    dt.common   = IO_UNIT6_FLAGS;
    dt.filename = SRC_FILE;
    dt.line     = 40;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Fortran subroutine called", 25);
    _gfortran_st_write_done(&dt);

    dt.common   = IO_UNIT6_FLAGS;
    dt.filename = SRC_FILE;
    dt.line     = 41;
    _gfortran_st_write(&dt);
    _gfortran_transfer_character_write(&dt, "Subroutine called", 17);
    _gfortran_transfer_integer_write(&dt, &call_count_1, 4);
    _gfortran_transfer_character_write(&dt, "times", 5);
    _gfortran_st_write_done(&dt);
}

