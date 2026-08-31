/* Variadic callees, whose x86-64 SysV prologue materialises a REGISTER SAVE
 * AREA out of registers the recovered interface never mentions.
 *
 * WHAT THE SHAPE IS. On x86-64 SysV a function declared `f(fixed, ...)` does
 * not know at compile time how many variadic arguments arrived or in which
 * class. `va_start` therefore has to spill the *whole* incoming argument
 * register file into a save area the `va_list` walks:
 *
 *     mov [rsp+0x08], rsi        ; the six integer argument registers, minus
 *     mov [rsp+0x10], rdx        ; however many the FIXED parameters consumed
 *     mov [rsp+0x18], rcx
 *     mov [rsp+0x20], r8
 *     mov [rsp+0x28], r9
 *     test al, al                ; al = how many vector registers the CALLER used
 *     je   .Lno_sse
 *     movaps [rsp+0x30], xmm0    ; ... through xmm7, 16 bytes each
 *     .Lno_sse:
 *
 * Every one of those source registers is INCOMING ABI STATE. None of them is
 * produced by an instruction inside the function, and `al` is not a return
 * value even though it lives in `rax`.
 *
 * WHY IT IS ITS OWN RECOVERY PROBLEM. A decompiler recovers a prototype from
 * the registers a function reads before writing. For a variadic function that
 * prototype is a lie by construction: the recovered signature names only the
 * FIXED parameters, because the variadic ones have no fixed arity to recover.
 * The save-area prologue then reads five to thirty-eight registers that the
 * recovered interface does not declare and no statement defines, and the
 * emitted C builds the save area out of uninitialised variables:
 *
 *     int f(int arg0) {                        // recovered arity: 1
 *         long var0; long var1; ...            // nothing ever assigns these
 *         *(long *)(&local_38[0] + 8)  = var0; // ... yet they are stored
 *         *(long *)(&local_38[0] + 16) = var1;
 *
 * Recompiled, that function's `va_arg` returns garbage. This is not a
 * formatting defect; it is the interface model missing a fact about the
 * function, and the undefined reads are the symptom.
 *
 * WHY NO EXISTING FIXTURE COVERS IT. `113_varargs.c` is the only fixture in
 * the corpus that mentions `stdarg.h`, and it cannot exhibit the shape:
 *
 *   * both of its variadic functions are `static` and are called only with
 *     compile-time-constant counts, so at -O2 they are inlined into their
 *     callers and no variadic function survives as its own body at all;
 *   * both walk their arguments with `va_arg(ap, int32_t)` and nothing else,
 *     so GCC can prove the FP half of the save area is dead and elides the
 *     `test al, al` guard and all eight `movaps` — the larger and more
 *     interesting half of the shape never gets emitted.
 *
 * The functions here are deliberately the opposite on both counts: external
 * linkage and `noinline` so a body always survives, and a spread across the
 * three save-area flavours so the recovered undefined-read count DECOMPOSES
 * into named parts of the ABI rather than being one opaque number.
 *
 * Every function is `noinline` and externally visible so that no
 * interprocedural pass may rewrite its interface, exactly as
 * `link_configuration_shapes.c` pins its own.
 */

#include <stdarg.h>
#include <stdio.h>

/* Observable sink, so a control cannot be folded away to nothing. */
volatile long vsa_sink;

/* ---------------------------------------------------------------- variadic */

/* 1. The `printf` shape: the arguments are forwarded to a `v*printf`, so the
 * callee cannot know whether any of them were floating point and the compiler
 * must emit the COMPLETE save area — five integer registers, the `test al, al`
 * guard, and all eight vector registers. This is the shape `fatal_error`,
 * `internal_error`, `sys_error` and eleven more have in /usr/bin/bash, and
 * together those seventeen functions account for 48% of that binary's
 * definition-before-use violations. */
__attribute__((noinline)) int vsa_forward(const char *format, ...)
{
    va_list arguments;
    int written;

    va_start(arguments, format);
    written = vfprintf(stderr, format, arguments);
    va_end(arguments);
    return written;
}

/* 2. Integer `va_arg` only. GCC at -O2 proves the vector half of the save area
 * is dead and emits ONLY the five integer stores, which is what makes the
 * decomposition in the test legible: this lane isolates the integer registers
 * from the vector ones. */
__attribute__((noinline)) int vsa_int_only(int count, ...)
{
    va_list arguments;
    int total = 0;
    int index;

    if (count < 0 || count > 8) {
        return -1;
    }
    va_start(arguments, count);
    for (index = 0; index < count; ++index) {
        total += va_arg(arguments, int);
    }
    va_end(arguments);
    return total;
}

/* 3. Floating-point `va_arg`. The complement of the lane above: the vector
 * save area is live and the integer one is mostly not, so between the two the
 * two halves of the ABI are separated. */
__attribute__((noinline)) double vsa_double_args(int count, ...)
{
    va_list arguments;
    double total = 0;
    int index;

    if (count < 0 || count > 8) {
        return -1;
    }
    va_start(arguments, count);
    for (index = 0; index < count; ++index) {
        total += va_arg(arguments, double);
    }
    va_end(arguments);
    return total;
}

/* ----------------------------------------------------------------- controls */

/* THE CONTROL. Six fixed integer parameters: it consumes exactly the same six
 * incoming argument registers the save area above spills, does comparable
 * arithmetic, and is compiled by the same command in the same translation
 * unit — but it is not variadic, so every register it reads is a declared
 * parameter and nothing is undefined.
 *
 * It is what makes a failure attributable. If this function ever reports an
 * undefined read, the finding is in the harness, the build or the general
 * register model, NOT in the variadic shape, and the properties below say so
 * rather than blaming `...`. */
__attribute__((noinline)) int vsa_control_fixed(int a, int b, int c, int d,
                                                int e, int f)
{
    return a + (b * 2) + (c * 3) + (d * 4) + (e * 5) + (f * 6);
}

/* Second control, mixing an integer and a floating-point fixed parameter, so
 * that a vector register is a declared parameter in at least one function. It
 * pins the claim that reading `xmm0` is only a problem when the interface
 * failed to declare it. */
__attribute__((noinline)) double vsa_control_mixed(int n, double x)
{
    return (n * 2) + (x * 3.5);
}
