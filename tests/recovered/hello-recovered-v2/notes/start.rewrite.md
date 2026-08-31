# `_start` @ 0x1840 — Rewrite Audit

## What the pipeline did
- **Recognized** the function as the standard x86-64 SysV `_start` stub emitted by GCC/binutils and rewrote the body as a single `asm volatile` block. The original pseudocode could not be expressed in portable C (architectural register conventions, stack manipulation, no-return tail call into `__libc_start_main`).
- **Renamed** pseudocode `arg*` placeholders to their architectural registers (`rsi`=argc, `rdx`=argv, `rcx`/`r8`=zeroed init/fini, `rdi`=&main).
- **Added** `__builtin_unreachable()` after the asm block to model the no-return contract of `__libc_start_main` / `hlt`.
- **Dropped** the trailing `__TMC_END__` comparison + indirect call through `[var0+0x3fe0]`, asserting it is spillover from `__do_global_dtors_aux` / `deregister_tm_clones` that the disassembler glued onto `_start`.
- **Declared** `register void (*rtld_fini)(void) asm("rdx")` but never reads it — the asm clobbers `rdx` with argv, matching the original `arg2 = rsp`.

## Assumptions not mechanically provable
- The trailing `__TMC_END__` block is *not* actually part of `_start`. This is a pattern-match on idiomatic GCC output, not proven from the binary's symbol/section boundaries.
- The zeroings of `rcx` / `r8` correspond to the standard `__libc_start_main` `init`/`fini` slots in the order glibc expects (the comments in the rewrite admit ABI-version ambiguity here).
- `push rax` is semantically equivalent to the original `push(ret)` — assumes `ret` in pseudocode is the rax-class scratch register used as alignment padding, not a meaningful value.
- `main` is externally resolvable at link time with the standard signature.

## Reviewer checklist
