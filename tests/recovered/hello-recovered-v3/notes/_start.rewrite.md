## `_start` @ 0x1840 — rewrite notes

### What the pipeline did
- **Recognised the idiom**: treated the pseudocode as the canonical glibc x86-64 `_start` and emitted the well-known C-ish stub plus an asm-comment crib of the original instruction sequence, rather than a literal transliteration of the register shuffle.
- **Discarded register-allocation noise**: pseudocode locals (`arg2`, `arg5`, `ret`, etc.) are SysV ABI register moves; no local names were preserved.
- **Reconstructed the call signature**: invented the 7-argument `__libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end)` form from ABI knowledge — these identifiers do **not** appear in the pseudocode.
- **Dropped the tail block** comparing `__TMC_END__` to `arg0` and the conditional GOT-slot indirect call, on the grounds it is unreachable after a noreturn `__libc_start_main` + `hlt`.
- **Replaced `hlt`** with `__builtin_unreachable()`.
- Omitted prototypes/externs for `__libc_start_main`, `main`, `argc`, `argv`, `rtld_fini`, `stack_end` — assumed provided by the surrounding crt1 context.

### Assumptions not mechanically provable
- That this really is stock glibc `_start` and not a customised/hardened variant where the post-call tail is meaningful (e.g. a TM-clone-table fixup or a pre-libc init shim).
- That the conditional call through `*&[var0+0x3fe0]` is genuinely dead. In some crt0 variants this block runs **before** `__libc_start_main` or is part of `_dl_relocate_static_pie`-style logic; the pseudocode ordering suggests after, but control-flow recovery on `_start` is notoriously unreliable.
- That argument register assignments match the standard 7-arg form (the pseudocode only shows `arg3=0, arg4=0` explicitly; `arg5=arg2` is asserted to be `rtld_fini` purely by convention).
- That `__TMC_END__` reference is unrelated to `__cxa_finalize`/TM-clone registration that some toolchains do emit inside `_start`.

### Reviewer checklist