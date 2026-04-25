## `_start` @ 0x1100 — rewrite notes

### What the pipeline did
- Recognised the function as the standard glibc x86-64 `_start` CRT stub and replaced the literal register-shuffling pseudocode with a single idiomatic `__libc_start_main(main, argc, argv, 0, 0, rtld_fini, stack_end)` call.
- Renamed the SysV-ABI register args to their conventional names (`argc`, `argv`, `rtld_fini`, `stack_end`); treated `main` and friends as externally-supplied symbols rather than declaring them.
- Replaced the unreachable `hlt` with `__builtin_unreachable()`.
- **Dropped** the trailing `completed.0` / `*(var0+0x3fe0)` compare-and-call block, asserting it leaked from an adjacent `__do_global_dtors_aux` during disassembly.
- Preserved the original asm verbatim in a comment for traceability.

### Assumptions not mechanically provable
- That the trailing destructor-pointer block genuinely belongs to a *different* function and is a disassembly artefact, not part of `_start`. This is the load-bearing assumption — if wrong, a registered finaliser is silently no longer called.
- That this binary uses the conventional glibc CRT `_start` (vs. musl, a custom stub, or a static-pie variant), so the SysV register-to-arg mapping is correct.
- That `main`, `rtld_fini`, `stack_end` are the right symbolic names; the rewrite does not actually push `%rax`/`%rsp` for `stack_end`, just names it.
- `__libc_start_main` is `noreturn`, justifying the `__builtin_unreachable()`.

### Reviewer checklist
