## register_tm_clones @ 0x18a0 — Reviewer Note

### What the pipeline did
- Recognized the function as the canonical GCC `crtstuff.c` `register_tm_clones` and **reconstructed it from the standard idiom** rather than translating the pseudocode line-by-line.
- Collapsed the `(x>>63 + x>>3) >> 1` sequence into a signed division, expressed as `(__TMC_END__ - __TMC_LIST__) / sizeof(void *)`.
- Replaced the indirect GOT-slot call (`*(... + 0x3ff0)`) with a direct weak-symbol reference to `_ITM_registerTMCloneTable` plus a NULL check.
- Substituted `__TMC_LIST__` for the second `__TMC_END__` operand in the subtraction (treated as a decompiler artifact).
- Dropped dead register-shuffle stores and merged the two zero-check branches into two early returns.

### Assumptions that are NOT mechanically provable
1. The second operand of the subtraction is really `__TMC_LIST__`, not `__TMC_END__` as literally shown. If the pseudocode is faithful, the function is a no-op (size always 0) and the rewrite is a behavioral change.
2. The GOT load at offset `+0x3ff0` resolves to `_ITM_registerTMCloneTable` (not `_ITM_registerTMCloneTable` vs some other ITM symbol, and not e.g. `deregister`'s slot).
3. The divisor is `sizeof(void *)`. **The pseudocode arithmetic actually computes `x / 16`**, i.e. `sizeof(void *) * 2`. The rewriter's own assumption says `*2` but the emitted code omits it — this is an off-by-2× bug in the size argument passed to the callback.
4. This is in fact the GCC crtstuff idiom and not a hand-rolled lookalike with different semantics.

### Reviewer checklist