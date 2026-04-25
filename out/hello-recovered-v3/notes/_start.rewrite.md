## `_start` @ 0x1840 — Rewrite Audit Note

### What the pipeline did
- **Recognised the idiom**: treated the pseudocode as the canonical glibc x86-64 `_start` and emitted the well-known crt1 form rather than a literal transliteration of register shuffles.
- **Re-derived arguments from the SysV ABI**: the pseudocode's `arg2/arg3/arg4/arg5` were discarded in favour of the standard 7-argument `__libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end)` shape. None of those identifiers (`argc`, `argv`, `rtld_fini`, `stack_end`) come from the pseudocode — they are inferred.
- **Dropped a tail block**: the post-call `__TMC_END__` comparison, GOT-slot deref, and indirect call were removed as dead code on the assumption that `__libc_start_main` is `noreturn` and the `hlt` traps first.
- **Replaced `hlt`** with `__builtin_unreachable()`.
- **Annotated the body with the original asm** as comments, but emitted no actual instructions — the function body is now just the libc call plus the unreachable marker.
- **Omitted prototypes/externs** for `__libc_start_main`, `main`, `argv`, `rtld_fini`, `stack_end`; relies on an ambient crt1-like translation unit.

### Assumptions not mechanically provable
- That the dropped tail (TMC_END comparison + indirect call) is genuinely unreachable. In stock crt1 it is, but if this binary's `__libc_start_main` is a custom/wrapped variant that *can* return, we have silently deleted a `__cxa_finalize`-style cleanup path.
- That the GOT slot at `[var0+0x3fe0]` is `__cxa_finalize`/registration glue and not something semantically important.
- That this file compiles in a context where `main`, `argv`, `rtld_fini`, `stack_end` are declared — as written it will not compile standalone.
- Argument *order* is correct only if this really is glibc's 7-arg `__libc_start_main`; older/musl/bionic variants have different signatures.

### Reviewer checklist
