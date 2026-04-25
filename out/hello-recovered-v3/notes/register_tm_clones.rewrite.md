## register_tm_clones @ 0x18a0 — rewrite notes

This function was reconstructed as the **canonical GCC `crtstuff.c` `register_tm_clones`** rather than as a literal transcription of the pseudocode. The pipeline pattern-matched the shape of the routine (TMC table size computation + GOT-slot indirect call) and emitted the well-known idiom.

### Transformations applied
- Replaced the signed-division-by-power-of-two idiom `(x>>63 + x>>3) >> 1` with a plain pointer-subtraction divided by an element size.
- Rewrote the GOT-relative indirect call `*(reg+0x3ff0)` as a weak-symbol NULL-check + direct call to `_ITM_registerTMCloneTable`.
- Dropped dead register-shuffle assignments (`ret = arg1`, etc.) as optimizer artefacts.
- Collapsed two early-exit branches into two plain `if (...) return;` statements.
- Renamed locals to `size`.

### Assumptions not mechanically provable
- The second operand of the subtraction is `__TMC_LIST__`. **The pseudocode literally shows `__TMC_END__ - __TMC_END__`** (always 0); the rewriter substituted `__TMC_LIST__` based on the crtstuff idiom. If the pseudocode is faithful, the rewrite changes behavior (original is a no-op, rewrite may invoke the callback).
- The GOT slot at `+0x3ff0` resolves to `_ITM_registerTMCloneTable` (assumed from idiom; not verified against the relocation/GOT layout).
- The divisor is `sizeof(void *)`. **Inconsistency:** the shift idiom `(x>>63 + x>>3) >> 1` computes `x/16`, i.e. `sizeof(void*)*2 = 16`, and the rewriter's own assumption text says so — but the emitted code uses `sizeof(void *)` (8). This doubles the `size` value passed to the callback compared to the original arithmetic.
