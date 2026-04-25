# CRT scaffolding (documentation only)

These functions were emitted into the binary by the toolchain
(libgcc / crtbegin.o / crtend.o). They are recovered here for
reference; the build does **not** include them — the real
runtime objects are linked by the C++ driver.

## `__do_global_dtors_aux`  @ `0x18e0`

- Demangled: `__do_global_dtors_aux`
- Role: `ctor_dtor`
- Confidence: 0.95

@brief Runs global destructors exactly once at program/shared-object teardown.
Compiler-generated finalization routine placed in the `.fini_array` section
(the counterpart to `frame_dummy` in `.init_array`). It is invoked
automatically by the dynamic loader / C runtime when the module is being
unloaded (program exit or `dlclose`).
Behavior:
 - Guards against re-entry using the file-scope `completed` flag; if a
   previous invocation already finished, the function returns immediately.
 - If `__cxa_finalize` was resolved (non-NULL), it is called with
   `__dso_handle` so that destructors registered via `__cxa_atexit` for
   this DSO are run.
 - Calls `deregister_tm_clones()` to undo the transactional-memory clone
   table registration performed at startup.
 - Sets `completed = 1` so subsequent calls become no-ops.
@note Has no parameters and no return value; all state is module-global
      (`completed`, `__cxa_finalize`, `__dso_handle`).
@note Not intended to be called from user code; emitted by the toolchain
      and registered automatically via `.fini_array`.

```
static void __do_global_dtors_aux(void)
{
    if (completed)
        return;

    if (__cxa_finalize != NULL)
        __cxa_finalize(__dso_handle);

    deregister_tm_clones();
    completed = 1;
}

```

## `frame_dummy`  @ `0x1920`

- Demangled: `frame_dummy`
- Role: `ctor_dtor`
- Confidence: 0.60

@brief Compiler-generated initialization stub invoked at program startup.
This function is emitted automatically by the toolchain (placed in the
.init_array / .ctors section) and is run before main() as part of the C
runtime startup sequence. Its sole job is to delegate to
register_tm_clones(), which sets up Transactional Memory clone tables
when supported.
@note This is not user code; it is produced by GCC and should not be
      called or modified directly. It takes no arguments and returns
      no value.

```
static void frame_dummy(void)
{
    register_tm_clones();
}
```

## `_start`  @ `0x1840`

- Demangled: `_start`
- Role: `entry_stub`
- Confidence: 0.90

@brief ELF program entry point (glibc `_start` stub).
This is the symbol the kernel transfers control to after loading the
executable. It performs the standard System V AMD64 ABI start-up
sequence before delegating to glibc's `__libc_start_main`, which in
turn invokes the user-defined `main()`.
The hand-written prologue (see the inline asm comments in the source):
  - Clears `%ebp` so backtraces terminate at this frame.
  - Saves `%rdx` (the dynamic linker's `rtld_fini` callback supplied by
    the kernel/ld.so) into `%r9` for forwarding.
  - Pops `argc` off the stack into `%rsi` and captures the resulting
    `%rsp` as `argv` in `%rdx`.
  - Aligns `%rsp` down to a 16-byte boundary as required by the ABI,
    then pushes a dummy word and the original stack end.
  - Zeroes `%r8` and `%rcx` (the `fini` and `init` arguments).
  - Loads the address of `main` into `%rdi`.
Control is then transferred to `__libc_start_main`, which runs
constructors, calls `main`, and on return invokes `exit()`. It does not
return to this function.
@return This function does not return. The trailing `hlt` instruction
        emitted by the compiler/linker is a safety net that will fault
        if `__libc_start_main` ever does return.
@note Not intended to be called from C code; it is the ELF
      `e_entry` target and assumes the kernel-supplied initial stack
      layout (argc, argv[], envp[], auxv) and that `%rdx` holds
      `rtld_fini` as set up by the dynamic loader
      (`/lib64/ld-linux-x86-64.so.2`).
@note Relies on the weak symbol `__gmon_start__` resolution performed
      by libc during start-up for profiling support.

```
/*
 * ELF entry point. Standard glibc _start stub: sets up argc/argv on the
 * stack, aligns the stack to 16 bytes, zeroes the frame pointer chain
 * registers used by __libc_start_main, and hands control to libc which
 * eventually calls main(). __libc_start_main never returns; the trailing
 * hlt is a safety net.
 */
void _start(void)
{
    /* xor %ebp,%ebp                — clear the frame pointer  */
    /* mov %rdx, %r9                — rtld_fini (saved for libc) */
    /* pop %rsi                     — argc                    */
    /* mov %rsp, %rdx               — argv                    */
    /* and $0xfffffffffffffff0,%rsp — 16-byte align the stack */
    /* push %rax  ; push %rsp       — dummy + stack end       */
    /* mov $0, %r8  ; mov $0, %rcx  — fini, init = NULL       */
    /* mov $main, %rdi                                        */
    __libc_start_main(main, argc, argv, NULL, NULL, rtld_fini, stack_end);
    __builtin_unreachable();   /* hlt */
}

```

## `deregister_tm_clones`  @ `0x1870`

- Demangled: `deregister_tm_clones`
- Role: `ctor_dtor`
- Confidence: 0.55

@brief Deregister GCC transactional-memory clones at shared-object teardown.
Compiler-generated finalizer counterpart to register_tm_clones(). It is
invoked from the module's destructor path (e.g. __do_global_dtors_aux) to
unregister any transactional-memory clone table that was previously
registered for this DSO.
The function performs two short-circuit checks before doing any work:
  1. If the address of __TMC_END__ equals __dso_handle, the linker has
     collapsed the (empty) clone table into the DSO handle, meaning this
     translation unit has no TM clones to deregister, and the function
     returns immediately.
  2. Otherwise it loads the deregister callback pointer from the GOT slot
     at GOT_BASE + 0x3fe0 (typically populated by the dynamic loader with
     the address of _ITM_deregisterTMCloneTable when libitm is present).
     If that slot is NULL — i.e. no TM runtime is linked in — the function
     returns without invoking it.
Only when both a non-trivial clone table exists and a runtime callback is
available does it call `deregister(__TMC_END__)` to tear the table down.
@return None. Failures are silent: missing clones or a missing runtime
        callback are normal conditions, not errors.
@note This routine is emitted automatically by the toolchain into every
      executable/shared object; it is not intended to be called by user
      code. The hard-coded GOT offset (0x3fe0) is specific to this binary's
      link layout.
@note Symmetric with register_tm_clones(); both are wired up through
      __do_global_dtors_aux / frame_dummy in the CRT startup glue.

```
static void deregister_tm_clones(void)
{
    void (*deregister)(void *) = (void (*)(void *))__dso_handle_lookup;

    /* If __TMC_END__ resolves to itself (no transactional-memory clones to
       deregister) and the GOT slot for the deregister callback is NULL,
       there is nothing to do. */
    if (__TMC_END__ == __dso_handle)
        return;

    deregister = *(void (**)(void *))(GOT_BASE + 0x3fe0);
    if (deregister == NULL)
        return;

    deregister(__TMC_END__);
}
```

## `register_tm_clones`  @ `0x18a0`

- Demangled: `register_tm_clones`
- Role: `ctor_dtor`
- Confidence: 0.90

@brief Register the module's transactional-memory clone table with the ITM runtime.
Computes the number of entries in the TM clone table as
`(__TMC_END__ - __TMC_LIST__) / sizeof(void *)`. If the table is empty, or if
the GCC transactional-memory runtime hook `_ITM_registerTMCloneTable` is not
present (i.e. resolves to NULL via its weak reference), the function returns
without doing anything. Otherwise it forwards `__TMC_LIST__` and the computed
size to `_ITM_registerTMCloneTable` so the runtime can track this module's
transactional clones.
This is part of the standard CRT startup glue emitted by the compiler
(paired with `deregister_tm_clones`) and is normally invoked from a
`.init_array` constructor at program / shared-object load time; it is not
intended to be called directly by user code.
@note `_ITM_registerTMCloneTable` is referenced as a weak symbol, so its
      absence at link/load time is handled gracefully via the NULL check.
@note The symbols `__TMC_LIST__` and `__TMC_END__` delimit the TM clone
      table for the current module.

```
static void register_tm_clones(void)
{
    ptrdiff_t size = (__TMC_END__ - __TMC_LIST__) / sizeof(void *);

    if (size == 0)
        return;

    if (_ITM_registerTMCloneTable == NULL)
        return;

    _ITM_registerTMCloneTable(__TMC_LIST__, size);
}
```

## `_GLOBAL__sub_I_main`  @ `0x1810`

- Demangled: `_GLOBAL__sub_I_main`
- Role: `ctor_dtor`
- Confidence: 0.90

@brief Global static initializer for the translation unit containing main().
Compiler-generated constructor (named via the `_GLOBAL__sub_I_` prefix) that
runs before main() to perform static initialization for this translation
unit. It constructs the file-scope `std::ios_base::Init` object
`_ZStL8__ioinit`, which is the standard mechanism by which including
<iostream> guarantees that the standard streams (std::cin, std::cout,
std::cerr, std::clog and their wide counterparts) are initialized before
first use.
After construction, it registers the matching `~Init` destructor with
`__cxa_atexit`, tied to `__dso_handle`, so the streams are flushed and
torn down when this DSO is unloaded or the program exits.
@note This function takes no parameters and returns no value. It is
      emitted automatically by the C++ front-end and placed in the
      `.init_array` (or equivalent) section; it is not intended to be
      called by user code.
@note `_ZStL8__ioinit` is the mangled name of the TU-local
      `std::ios_base::Init __ioinit` sentinel object that <iostream>
      defines in every translation unit that includes it.
@see std::ios_base::Init
@see __cxa_atexit

```
static void _GLOBAL__sub_I_main(void)
{
    std::ios_base::Init::Init(&_ZStL8__ioinit);
    __cxa_atexit(&std::ios_base::Init::~Init, &_ZStL8__ioinit, &__dso_handle);
}

```
