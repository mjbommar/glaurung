/* 06_calling_conventions.c
 *
 * ABI / argument-recovery fixture. Each `sum_argN` takes N integer arguments
 * and returns a DISTINCT linear combination of ALL of them (a0*1 + a1*2 + ...),
 * so any recovery error — wrong argument order, a dropped stack argument, a
 * register/stack mix-up — changes the result. Functions with 7..10 args force
 * spills onto the stack under SysV (6 integer registers), and Win64 (4),
 * exercising stack-argument recovery on multiple ABIs.
 *
 * This file is meant to be compiled for MULTIPLE ABIs (SysV x86-64, Win64,
 * x86-32 cdecl, AArch64 AAPCS64). The harness asserts argument order, return
 * value, and stack-argument recovery are preserved end-to-end. All parameters
 * are integer (int / long) and all returns are int, so every function is
 * differential-testable and portable across those ABIs. No libc.
 *
 * Targets review #7 (calling-convention / arg recovery).
 */
#include <stdint.h>

/* 0 arguments: a fixed sentinel — verifies "no args" isn't misread as "some". */
int sum_arg0(void) {
    return 7;
}

/* 1 argument. */
int sum_arg1(int a0) {
    return a0 * 1 + 1;
}

/* 2 arguments. */
int sum_arg2(int a0, int a1) {
    return a0 * 1 + a1 * 2 + 2;
}

/* 3 arguments. */
int sum_arg3(int a0, int a1, int a2) {
    return a0 * 1 + a1 * 2 + a2 * 3 + 3;
}

/* 4 arguments (Win64 register boundary is here). */
int sum_arg4(int a0, int a1, int a2, int a3) {
    return a0 * 1 + a1 * 2 + a2 * 3 + a3 * 4 + 4;
}

/* 5 arguments. */
int sum_arg5(int a0, int a1, int a2, int a3, int a4) {
    return a0 * 1 + a1 * 2 + a2 * 3 + a3 * 4 + a4 * 5 + 5;
}

/* 6 arguments (SysV integer-register boundary is here). */
int sum_arg6(int a0, int a1, int a2, int a3, int a4, int a5) {
    return a0 * 1 + a1 * 2 + a2 * 3 + a3 * 4 + a4 * 5 + a5 * 6 + 6;
}

/* 7 arguments — a6 spills to the stack on SysV. */
int sum_arg7(int a0, int a1, int a2, int a3, int a4, int a5, int a6) {
    return a0 * 1 + a1 * 2 + a2 * 3 + a3 * 4 + a4 * 5 + a5 * 6 + a6 * 7 + 7;
}

/* 8 arguments — a6,a7 spill on SysV. */
int sum_arg8(int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7) {
    return a0 * 1 + a1 * 2 + a2 * 3 + a3 * 4 + a4 * 5 + a5 * 6 + a6 * 7 +
           a7 * 8 + 8;
}

/* 9 arguments — three stack args on SysV. */
int sum_arg9(int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7,
             int a8) {
    return a0 * 1 + a1 * 2 + a2 * 3 + a3 * 4 + a4 * 5 + a5 * 6 + a6 * 7 +
           a7 * 8 + a8 * 9 + 9;
}

/* 10 arguments — four stack args on SysV. A dropped or reordered stack slot
 * changes the weighted sum. */
int sum_arg10(int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7,
              int a8, int a9) {
    return a0 * 1 + a1 * 2 + a2 * 3 + a3 * 4 + a4 * 5 + a5 * 6 + a6 * 7 +
           a7 * 8 + a8 * 9 + a9 * 10 + 10;
}

/* Mixed int/long widths in the stack-spill region: exercises slot sizing on
 * ABIs where `long` differs from `int`. Still integer-only and portable. */
int sum_mixed_widths(int a0, long a1, int a2, long a3, int a4, long a5,
                     int a6, long a7) {
    long acc = (long)a0 * 1 + a1 * 2 + (long)a2 * 3 + a3 * 4 + (long)a4 * 5 +
               a5 * 6 + (long)a6 * 7 + a7 * 8;
    return (int)(acc + 88);
}

/* Recursive: iterative-safe factorial modulo a bound so the return stays a
 * small int and callers can drive it with any nonnegative n. Recursion
 * stresses prologue/epilogue and saved-register recovery. */
int fact_mod(int n) {
    if (n <= 1)
        return 1;
    return (int)(((long)n * fact_mod(n - 1)) % 1000000007L);
}

/* Recursive Fibonacci — a second, differently-shaped recursion. */
int fib(int n) {
    if (n < 0)
        return -1;
    if (n < 2)
        return n;
    return fib(n - 1) + fib(n - 2);
}

/* Tail-call: returns the callee's result directly. A compiler may turn this
 * into a jump (tail-call optimization); the harness asserts the observed
 * return still matches sum_arg4's contract. */
int tailcall_to_sum4(int a0, int a1, int a2, int a3) {
    return sum_arg4(a3, a2, a1, a0);   /* deliberately reversed to catch order */
}

/* Another tail position: forward the same args through, so a correct decompile
 * preserves both the call and its argument order. */
int forward_sum6(int a0, int a1, int a2, int a3, int a4, int a5) {
    return sum_arg6(a0, a1, a2, a3, a4, a5);
}

/* "noreturn-style" loop, but guarded so tests can safely avoid the hot path.
 * The loop only runs when `spin` is nonzero; the harness always passes 0, so
 * the function returns immediately. The unreachable-by-test loop still forces
 * the decompiler to structure a potentially-infinite region. */
int guarded_spin(int spin, int seed) {
    if (spin) {
        volatile int x = seed | 1;   /* nonzero */
        while (x) {
            x += 1;                  /* never reaches 0 in practice */
        }
        return x;                    /* unreachable in tests */
    }
    return seed + 5;                 /* the path the harness exercises */
}
