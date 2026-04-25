## register_tm_clones @ 0x1160 — Rewrite Notes

### What the pipeline did
- Recognized this as the **standard GCC-emitted `register_tm_clones` stub** and replaced the decompiled arithmetic with the canonical C idiom.
- Replaced the strength-reduced signed division `((diff>>3) + (diff>>63)) >> 1` (i.e. `diff / 16`) with `(__TMC_END__ - __TMC_LIST__) / sizeof(void *)` — note this is `/8` on 64-bit, not `/16`.
- Renamed the GOT slot `*(ret+0x3fe8)` to the weak symbol `_ITM_registerTMCloneTable`.
- Converted the indirect tail call `ret()` into a named call, inferring its two arguments (`__TMC_LIST__`, count) from the standard ABI/idiom — the args are not visible in the pseudocode.
- Dropped dead stores on `ret`/`diff` produced by the optimizer.
- Consolidated the two early-exit branches into two guarded `return` statements.

### Assumptions not mechanically provable
- That this really is the GCC stub and not a hand-rolled routine that happens to look similar.
- That the call-site argument list matches the standard `_ITM_registerTMCloneTable(void *, size_t)` signature — pseudocode shows `ret()` with no args.
- That `__TMC_END__ - __TMC_LIST__` is always a multiple of 16, making the divisor discrepancy (8 vs 16) irrelevant in practice.

### Known divergences from pseudocode
- **Divisor mismatch (medium):** original computes `diff/16`, rewrite computes `diff/sizeof(void*)` (=`diff/8`). The numeric argument passed to `_ITM_registerTMCloneTable` differs by a factor of 2 for any non-empty table.
- **Zero-check scope (low):** original checks `(diff/16) == 0`; rewrite checks `diff == 0`. Differ for `diff ∈ {1..15}`, which shouldn't occur for a well-formed table.
- **Call args (low):** inferred, not observed.

### Reviewer checklist
