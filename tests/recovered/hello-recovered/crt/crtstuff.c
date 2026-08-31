// crt/crtstuff.c
// Recovered from hello-gcc-O2 by glaurung source-recovery

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief ELF program entry point (crt1 `_start` stub).
 *
 * Prepares the initial execution environment for a dynamically linked
 * program and transfers control to `__libc_start_main`, which in turn
 * invokes `main`. This is the standard glibc `_start` trampoline that
 * the toolchain emits in `crt1.o`; the C body shown is an illustrative
 * rendering of the underlying assembly.
 *
 * The routine performs the following steps:
 *  - Recovers `argc` from `[rsp]` and `argv` from `rsp + 8` as laid out
 *    by the kernel/loader on process start.
 *  - Reads `rtld_fini` from `rdx`, where the dynamic loader places the
 *    dynamic-linker finalizer to be registered by libc.
 *  - Aligns the stack to a 16-byte boundary and pushes sentinel values
 *    for `rbp` and `rsp` to terminate backtraces at this frame.
 *  - Calls `__libc_start_main(main, argc, argv, 0, 0, rtld_fini, argv)`,
 *    passing `NULL` for both the program `init` and `fini` hooks and
 *    reusing `argv` as the `stack_end` marker.
 *
 * Control is not expected to return; if `__libc_start_main` ever does
 * return, the function executes `__builtin_trap()` (a `hlt`) to abort
 * the process rather than continue executing undefined code.
 *
 * @return This function does not return.
 *
 * @note Takes no C-level parameters: all inputs (`argc`, `argv`,
 *       `rtld_fini`) are read directly from registers and the initial
 *       stack frame established by the kernel exec loader.
 * @note `main` must be defined and externally visible for the link step
 *       to resolve the reference embedded in this stub.
 */
/*
 * ELF entry point. Sets up argc/argv from the stack, aligns the stack,
 * and hands control to __libc_start_main. This is the standard glibc
 * _start stub emitted by the toolchain; it is written in assembly in
 * the real crt1.o. The C rendering below is illustrative only.
 */
void _start(void)
{
    /* Extracted by the prologue from the initial stack layout:
     *     argc   = [rsp]
     *     argv   = rsp + 8
     * rtld_fini is passed in rdx by the kernel/loader.
     */
    register long rtld_fini __asm__("rdx");
    int    argc = (int)(long)__builtin_frame_address(0);   /* pop rdi */
    char **argv = (char **)__builtin_frame_address(0);     /* mov rsi, rsp */

    /* Align stack to 16 bytes and push sentinels (rbp, rsp). */

    __libc_start_main(
        /* main        */ main,
        /* argc        */ argc,
        /* argv        */ argv,
        /* init        */ 0,
        /* fini        */ 0,
        /* rtld_fini   */ rtld_fini,
        /* stack_end   */ argv);

    __builtin_trap();   /* hlt — unreachable */
}


/**
 * @brief Compiler-generated init stub that registers TM (transactional memory) clones.
 *
 * This is a standard function emitted by the toolchain (GCC/Clang) and placed in
 * the `.init_array` (or equivalent) section so that it runs automatically during
 * program startup, before `main()`. It simply delegates to
 * `register_tm_clones()`, which sets up bookkeeping for transactional-memory
 * clone functions when the runtime supports them.
 *
 * @note Not part of the program's public API — it is invoked by the C runtime
 *       startup machinery, not by user code. It takes no parameters and has no
 *       return value.
 * @note Paired with `__do_global_dtors_aux` / `deregister_tm_clones`, which
 *       handle the corresponding teardown at program exit.
 */
static void frame_dummy(void)
{
    register_tm_clones();
}

/**
 * @brief Module destructor helper that runs global C++/C destructors exactly once.
 *
 * Invoked by the runtime (registered via `.fini_array` / `__do_global_dtors_aux_fini_array_entry`)
 * during shared-object unload or program termination. The function is idempotent: it
 * uses the file-scope guard variable `completed.0` to ensure the cleanup body executes
 * at most once, regardless of how many times it is called.
 *
 * On the first invocation it:
 *  - Calls `__cxa_finalize(__dso_handle)` (when the symbol is resolved, i.e. non-NULL)
 *    so that any destructors registered via `__cxa_atexit` for this DSO are run.
 *  - Calls `deregister_tm_clones()` to tear down transactional-memory clone tables
 *    that were set up by the matching constructor aux routine.
 *  - Sets `completed.0` to 1 to suppress subsequent executions.
 *
 * @note This function is generated automatically by the toolchain (crtbegin/crtend
 *       glue). It takes no parameters and returns no value. It must not be called
 *       directly by user code.
 */
static void __do_global_dtors_aux(void)
{
    if (completed.0)
        return;

    if (__cxa_finalize != NULL)
        __cxa_finalize(__dso_handle);

    deregister_tm_clones();
    completed.0 = 1;
}


/**
 * @brief Deregister this module's transactional-memory clone table.
 *
 * CRT helper (paired with register_tm_clones) that is invoked during
 * shared-object/binary teardown to undo any registration performed at
 * load time. It looks up the weakly-referenced GCC TM runtime symbols
 * and, when both are present, hands the module's clone-table address
 * (&__TMC_END__) to the runtime for removal.
 *
 * The function is a no-op when either:
 *   - the weak symbol __TMC_END__ resolves to NULL (i.e. this module
 *     has no transactional-memory clone table), or
 *   - the weak symbol _ITM_deregisterTMCloneTable resolves to NULL
 *     (i.e. no TM runtime is linked into the process).
 *
 * @note Symbols __TMC_END__ and _ITM_deregisterTMCloneTable are
 *       declared with __attribute__((weak)), so unresolved references
 *       compare equal to NULL rather than causing a link failure.
 * @note This is the standard boilerplate emitted by GCC in crtbegin;
 *       it is typically wired up as a destructor and is not meant to
 *       be called from user code.
 */
static void deregister_tm_clones(void)
{
    extern void *__TMC_END__ __attribute__((weak));
    extern void _ITM_deregisterTMCloneTable(void *) __attribute__((weak));

    if (&__TMC_END__ == /* __TMC_LIST__ */ NULL)
        return;

    if (_ITM_deregisterTMCloneTable == NULL)
        return;

    _ITM_deregisterTMCloneTable(&__TMC_END__);
}


/**
 * @brief Register this module's transactional-memory clone table with the ITM runtime.
 *
 * Computes the number of entries in the compiler-generated TM clone table as
 * `(__TMC_END__ - __TMC_LIST__) / sizeof(void *)` and, if the table is
 * non-empty and the weak symbol `_ITM_registerTMCloneTable` has been resolved
 * (i.e. a GNU transactional-memory runtime is linked in), forwards the table
 * and its entry count to `_ITM_registerTMCloneTable`.
 *
 * This is part of the standard GCC startup machinery emitted per translation
 * unit and is typically invoked from a `.init_array` constructor before
 * `main()` runs. It has no effect when the binary was not built with
 * transactional-memory clones or when no ITM runtime is present.
 *
 * @note Takes no parameters and returns no value. The function is a no-op
 *       when `count == 0` or when `_ITM_registerTMCloneTable` is NULL
 *       (weak-undefined).
 * @note The symbols `__TMC_LIST__` and `__TMC_END__` delimit the TM clone
 *       table and are supplied by the linker/compiler.
 */
static void register_tm_clones(void)
{
    ptrdiff_t count = (__TMC_END__ - __TMC_LIST__) / sizeof(void *);

    if (count == 0)
        return;

    if (_ITM_registerTMCloneTable == NULL)
        return;

    _ITM_registerTMCloneTable(__TMC_LIST__, count);
}
