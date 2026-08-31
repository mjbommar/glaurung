## `_start` @ 0x1840 — reviewer note

### What the pipeline did
- Recognised this as the standard glibc `_start` / crt1 stub and rewrote it as an **illustrative C rendering** rather than a faithful instruction-for-instruction translation. The header comment explicitly says so.
- Renamed the SysV AMD64 register-argument slots (`arg1..arg5`) into named locals `argc`, `argv`, `rtld_fini` and labelled each `__libc_start_main` argument with a comment.
- Replaced `unknown(hlt)` with `__builtin_trap()` as a non-returning marker.
- **Dropped** the tail fragment (`__TMC_END__` vs `*(var0+0x3fe0)` compare + conditional tailcall), categorising it as optimiser/linker padding reachable only after `__libc_start_main` returns (which it doesn't).
- Commented out the stack-alignment/sentinel pushes (`push rbp=0; push rsp`) as stylistic.

### Assumptions that are not mechanically provable
- That the dropped `__TMC_END__`/GOT-slot tailcall is genuinely unreachable. `__libc_start_main` is `noreturn` in practice, but the pseudocode does encode a real conditional call; this is a behavioural omission if ever reached.
- That register→argument mapping for `__libc_start_main` follows SysV AMD64 (main, argc, argv, init, fini, rtld_fini, stack_end). Not verified from the pseudocode ordering alone.
- That `init`/`fini` being 0 reflects a modern PIE crt1 rather than a decoder artefact.
- That `stack_end` pushed on the stack equals `argv` — asserted as "typically the same address" but not proven.

### Known divergences from original
- `argc`/`argv` are reconstructed via `__builtin_frame_address(0)` rather than the `pop rdi` / `mov rsi,rsp` the pseudocode performs. **Runtime values will not match.**
- `__builtin_trap()` emits `ud2`, not `hlt`.
- Sentinel pushes required by the ABI for backtrace termination are omitted.
- Conditional `__TMC_END__` tailcall path is removed entirely.

### Bottom line
This is a **documentation-grade rewrite**, not a faithful decompilation. Do not ship it as a replacement for crt1.o; treat it as a comment on what the entry stub does.
