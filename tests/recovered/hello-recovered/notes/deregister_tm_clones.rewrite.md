## deregister_tm_clones @ 0x1870 — review note

### What the pipeline did
- Recognized the function as the canonical **gcc/glibc crtstuff.c `deregister_tm_clones`** boilerplate and reconstructed it from the standard source template rather than transliterating ops.
- Mapped pseudocode artifacts to the idiom:
  - `arg0` → `__TMC_LIST__` (the address compared against `&__TMC_END__` to detect an empty TM clone table).
  - `*&[var0+0x3fe0]` → GOT slot for the weak `_ITM_deregisterTMCloneTable`.
  - `ret(__TMC_END__)` → indirect call `_ITM_deregisterTMCloneTable(&__TMC_END__)`.
- Replaced the first comparison with `&__TMC_END__ == NULL` plus a `/* __TMC_LIST__ */` comment — a cosmetic simplification, not a literal translation of the original `== arg0` compare.
- Declared both symbols as `extern ... __attribute__((weak))` locally inside the function.

### Assumptions not mechanically provable
- That this function really is the unmodified crtstuff boilerplate and not a hand-rolled variant (e.g., an attacker/custom TM hook reusing the prologue shape).
- That `arg0` is `__TMC_LIST__`. The pseudocode shows an actual parameter compare; the rewrite drops that parameter entirely (function is `void`).
- That the GOT offset `0x3fe0` resolves specifically to `_ITM_deregisterTMCloneTable` (not some other weak symbol at a nearby slot).
- That `__TMC_END__` is a `void *` object. In real crtstuff it's typically declared as an array/function-like weak symbol; the exact type doesn't matter for codegen but differs from the canonical declaration.

### Caveats
- Signature changed from taking an argument to `void` — callers (if any non-crt caller exists) would break. In standard crt usage this function is only referenced by `.init_array`/`_init`, so this should be safe.
- The `== NULL` comparison is not literally what the binary does; it's the source-level idiom the compiler lowers to this compare. Fine for a boilerplate match, wrong if the function is not boilerplate.
