## deregister_tm_clones @ 0x1870 — review note

### What the pipeline did
- Recognized this as the standard GCC-emitted CRT stub `deregister_tm_clones` and reshaped it accordingly.
- Renamed opaque temporaries (`ret`, `t0`) to a single local `deregister` of function-pointer type, eliminating the dead-store chain.
- Inverted the `goto L_1898` skip pattern into two early `return`s (idiomatic source shape for this stub).
- Reinterpreted `arg0` (which the pseudocode showed as a parameter) as `__dso_handle` — the function is actually nullary in source; the "arg0" is an artifact of ABI register reuse.
- Replaced the RIP/PIC-relative load `*&[var0+0x3fe0]` with a symbolic `*(... *)(GOT_BASE + 0x3fe0)` access and named the target as the GOT slot for `_ITM_deregisterTMCloneTable`.
- Marked the function `static` (file-local CRT helper).

### Assumptions not mechanically provable
- That the function takes no arguments — the pseudocode's `arg0` is assumed to be `__dso_handle` accessed via the ABI's first-arg register coincidentally, not a real parameter.
- That the loaded slot is specifically `_ITM_deregisterTMCloneTable` (symbol name is not in the binary; identified by pattern only).
- That `GOT_BASE + 0x3fe0` is the correct symbolic spelling of `var0 + 0x3fe0`; `GOT_BASE` is invented and must resolve to the same slot.
- That the dead initializer to `__dso_handle_lookup` is acceptable stylistically (it's overwritten before use).

### Reviewer checklist
