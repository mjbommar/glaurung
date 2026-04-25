## `_start` @ 0x1840 — rewrite notes

### What the pipeline did
- **Recognised the idiom.** The pseudocode was identified as the canonical glibc x86-64 `_start` crt1 stub and rewritten as the textbook 7-arg `__libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end)` call rather than a literal transliteration of the register shuffle.
- **Discarded register-allocation names.** Pseudocode locals (`arg2`, `arg5`, `ret`, etc.) are SysV ABI register artefacts; they were replaced with the conventional libc parameter names. No semantic locals exist in this function.
- **Dropped the post-call tail.** The block comparing `__TMC_END__` to `arg0`, dereferencing a GOT slot, and tail-calling `__TMC_END__` was removed as unreachable (follows a noreturn `__libc_start_main` and a `hlt`).
- **Replaced `hlt` with `__builtin_unreachable()`** to express noreturn semantics without fabricating inline asm.
- **Added an explanatory comment block** annotating each original instruction inline.

### Assumptions not mechanically provable
- That the trailing `__TMC_END__`/GOT block is genuinely dead. It *looks* like dead code peeled after a noreturn call, but in some toolchains/static builds `_start` does contain a real `__libc_csu_fini`/TMC dispatch — verify it isn't a legitimately-reachable destructor hook on this binary.
- That `__libc_start_main` here uses the standard 7-argument signature. Some libc variants (musl, bionic, older glibc) use different arities; the rewrite hard-codes glibc's.
- That `main`, `argc`, `argv`, `rtld_fini`, `stack_end` are declared/visible in the surrounding compilation unit. No prototype for `__libc_start_main` is emitted.
- That replacing `hlt` with `__builtin_unreachable()` is acceptable; the binary literally traps, the rewrite merely tells the compiler control doesn't return.

### Reviewer checklist
