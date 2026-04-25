## register_tm_clones @ 0x18a0 — review note

### What the pipeline did
- Recognized this as the **canonical GCC `crtstuff.c` `register_tm_clones`** boilerplate and reconstructed it from the idiom rather than translating the pseudocode literally.
- Replaced the signed division-by-constant bit pattern `((x>>63) + (x>>3)) >> 1` with a plain `(end - list) / sizeof(void*)` expression.
- Replaced the indirect call through a GOT slot (`*(base+0x3ff0)`) with a direct weak-symbol reference to `_ITM_registerTMCloneTable`.
- Substituted `__TMC_LIST__` for what the pseudocode shows as a second `__TMC_END__` operand.
- Dropped dead register-shuffle moves and renamed `arg0/arg1/ret` to readable names.
- Added an early-return for `size == 0` and a NULL guard before the call (matches the two `goto L_18d8` paths).

### Assumptions not mechanically provable
- The two symbol references in `end - start` are really `__TMC_END__` and `__TMC_LIST__`; the pseudocode literally shows `__TMC_END__ - __TMC_END__` (always 0). Trusted to be a decompiler symbol-resolution artifact.
- The `0x3ff0` GOT slot resolves to `_ITM_registerTMCloneTable` (assumed from idiom; not verified against the binary's relocation table).
- The divisor is `sizeof(void*)` (=8). **However the original arithmetic divides by 16** (= `sizeof(void*)*2`). The rewriter's own assumption text says "sizeof(void*)*2" but the emitted code uses `sizeof(void *)`. This is an off-by-2× bug in the rewrite *if* we treat the pseudocode as authoritative — but matches the canonical crtstuff source, which also divides by `sizeof(void*)` only. Worth confirming against a known-good crtstuff disassembly for this toolchain.

### Risk
Low overall — this is compiler-emitted boilerplate and rarely behaviorally significant. The two flagged divergences (divisor and the `END-END` operand) both stem from trusting the canonical idiom over the literal pseudocode. If the pseudocode is faithful, the rewrite changes behavior; if it's a decompiler artifact (most likely), the rewrite is correct.
