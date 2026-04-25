# CRT scaffolding (documentation only)

These functions were emitted into the binary by the toolchain
(libgcc / crtbegin.o / crtend.o). They are recovered here for
reference; the build does **not** include them — the real
runtime objects are linked by the C++ driver.

## `__do_global_dtors_aux`  @ `0x11a0`

- Demangled: `__do_global_dtors_aux`
- Role: `ctor_dtor`
- Confidence: 0.95

@brief Run global destructors exactly once at program/library shutdown.
Standard CRT housekeeping routine emitted by the toolchain and registered
via the .fini_array (or DT_FINI) so it is invoked when the executable or
shared object is unloaded. It is guarded by the file-scope @c completed
flag to ensure the finalization work is performed only on the first call.
On the first invocation it:
 - calls @c __cxa_finalize(__dso_handle) when @c __cxa_finalize_ptr is
   non-NULL, draining any destructors registered against this DSO;
 - calls @c deregister_tm_clones() to undo the transactional-memory clone
   table registration performed at startup;
 - sets @c completed to 1 so subsequent calls become no-ops.
@return None.
@note Not intended to be called directly from user code; it is wired into
      the module's finalization array by the linker.
@note Relies on the file-scope symbols @c completed, @c __cxa_finalize_ptr
      and @c __dso_handle.

```
static void __do_global_dtors_aux(void)
{
    if (completed)
        return;

    if (__cxa_finalize_ptr != NULL)
        __cxa_finalize(__dso_handle);

    deregister_tm_clones();
    completed = 1;
}

```

## `frame_dummy`  @ `0x11e0`

- Demangled: `frame_dummy`
- Role: `entry_stub`
- Confidence: 0.90

@brief Compiler-generated initialization stub; performs no action.
This function is emitted automatically by the toolchain (typically placed in
the .init/.fini machinery alongside `__do_global_dtors_aux`) and contains no
meaningful body. It exists to satisfy the runtime's expectation of an
initialization hook and is invoked indirectly during program startup; it is
not intended to be called by user code.
@return None.
@note The function takes no parameters and has no observable side effects.

```
static void frame_dummy(void)
{
    /* Compiler-generated stub: nothing to do. */
}

```

## `_start`  @ `0x1100`

- Demangled: `_start`
- Role: `entry_stub`
- Confidence: 0.90

@brief ELF program entry point installed by the dynamic linker.
Performs the standard System V AMD64 process start-up sequence before
transferring control to the C runtime:
  - Clears %ebp so stack unwinders stop here.
  - Saves %rdx (the dynamic linker's rtld_fini callback) into %r9.
  - Pops argc from the stack and uses the remaining %rsp as argv.
  - Aligns %rsp down to a 16-byte boundary (ABI requirement before a call).
  - Records the original stack pointer as stack_end and zeroes the
    legacy init/fini parameters.
  - Calls __libc_start_main(main, argc, argv, NULL, NULL, rtld_fini,
    stack_end).
@return This function does not return. __libc_start_main eventually
        invokes exit(); the trailing `hlt` instruction is therefore
        unreachable and exists only as a safety trap.
@note Invoked directly by the kernel/loader (e.g. via
      /lib64/ld-linux-x86-64.so.2); it is not meant to be called from
      user code. On entry %rdx holds rtld_fini and the initial stack
      layout follows the System V AMD64 ABI process start-up convention.

```
/*
 * ELF entry point. Sets up argc/argv on the stack, aligns the stack to
 * 16 bytes, and hands control to __libc_start_main. Never returns.
 */
void _start(void)
{
    /* The real implementation is written in assembly:
     *
     *     xor   %ebp, %ebp                ; clear frame pointer
     *     mov   %rdx, %r9                 ; rtld_fini
     *     pop   %rsi                      ; argc
     *     mov   %rsp, %rdx                ; argv
     *     and   $-16, %rsp                ; align stack
     *     push  %rax
     *     push  %rsp                      ; stack_end
     *     xor   %r8, %r8                  ; fini = NULL
     *     xor   %rcx, %rcx                ; init = NULL
     *     mov   $main, %rdi
     *     call  __libc_start_main
     *     hlt
     *
     * __libc_start_main does not return, so the trailing hlt is unreachable.
     */
    __libc_start_main(main, argc, argv, /*init=*/0, /*fini=*/0,
                      rtld_fini, stack_end);
    __builtin_unreachable();
}

```

## `deregister_tm_clones`  @ `0x1130`

- Demangled: `deregister_tm_clones`
- Role: `ctor_dtor`
- Confidence: 0.40

@brief CRT teardown helper that invokes __cxa_finalize on the module's DSO handle.
Compiler-generated routine emitted into every shared object / executable to
drive C++/transactional-memory style finalization at unload time. It is
paired with register_tm_clones() and is typically wired into the
.fini_array (and called from _fini) so the dynamic linker runs it when the
module is being torn down.
Behavior:
 - Returns immediately if the module-local guard `completed.0` is already
   non-zero, ensuring finalization runs at most once.
 - Loads the address of __cxa_finalize from the GOT slot
   (`__cxa_finalize_ptr`). If the slot is NULL — meaning libc did not
   provide __cxa_finalize (e.g. statically linked or stripped runtime) —
   the function returns without doing anything.
 - Otherwise it calls __cxa_finalize(&completed.0), passing the address of
   the guard as the DSO handle so libc finalizes only the destructors that
   were registered against this module.
@note This function takes no parameters and returns no value. It is not
      meant to be invoked directly by user code; it is registered by the
      toolchain as part of the module's destructor chain.
@note `completed.0` is the mangled name of a file-scope static guard
      generated by the compiler; its address doubles as the unique DSO
      handle expected by __cxa_finalize.

```
static void deregister_tm_clones(void)
{
    if (completed.0 != 0)
        return;

    void (*deregister)(void *) = __cxa_finalize_ptr; /* from GOT slot */
    if (deregister == NULL)
        return;

    deregister(&completed.0);
}
```

## `register_tm_clones`  @ `0x1160`

- Demangled: `register_tm_clones`
- Role: `ctor_dtor`
- Confidence: 0.90

@brief Compiler-generated CRT stub for registering text-modification (TM) clones.
This function is part of the standard C runtime startup/shutdown
scaffolding emitted automatically by GCC into every linked binary
(paired with __do_global_dtors_aux / deregister_tm_clones). When
transactional-memory clone tables are present, the linker patches a
slot in the GOT so this stub forwards to _ITM_registerTMCloneTable;
otherwise the slot is NULL and the function is effectively a no-op.
It takes no arguments, returns nothing, and is invoked indirectly by
the runtime via the .init_array / frame_dummy machinery before main().
It is not intended to be called directly by user code.
@return None.
@note Reproduced here as an empty function because the body has no
      observable effect in this build (no TM clone table is linked in).

```
static void register_tm_clones(void)
{
    /* Standard CRT stub emitted by GCC; calls __deregister_frame_info or
       similar via a slot in the GOT when present.  Reproduced here as a
       no-op since the body has no observable effect in normal builds. */
}

```
