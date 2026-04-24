## register_tm_clones @ 0x18a0 — Rewrite Notes

### What the pipeline did
- **Pattern recognition**: Identified this as the standard GCC crtstuff `register_tm_clones` boilerplate and rewrote it to the canonical form rather than a literal transcription.
- **Symbol re-resolution**: Reinterpreted the first `__TMC_END__` load in the pseudocode as `__TMC_LIST__`, treating the duplicate symbol as a decompiler symbol-resolution artefact.
- **Arithmetic consolidation**: Collapsed the signed divide idiom `((x>>3) + (x>>63)) >> 1` into a single division expression. Note: the source writes `/ sizeof(void *)` (=/8 on 64-bit), but the actual hardware arithmetic divides by 16 (pair-of-pointers stride). End-to-end semantics still match standard crtstuff because the call receives the count of 16-byte entries, but the textual divisor is arguably misleading.
- **Indirect call reconstruction**: Interpreted `*&[var0+0x3ff0]` as the GOT slot for the weak `_ITM_registerTMCloneTable` and reconstructed the call with the conventional `(__TMC_LIST__, count)` argument list — arguments are not visible in the pseudocode (register-passed).
- **Control flow**: Merged the two `goto L_18d8` early-exits into two sequential `if (...) return;` guards. Dropped temporary register shuffles (`ret`, `t0`).

### Assumptions not mechanically provable
- Target is 64-bit with 16-byte TMC entries (pair of pointers).
- The duplicate `__TMC_END__` in the pseudocode is really `__TMC_LIST__`.
- The GOT slot at `+0x3ff0` really resolves to `_ITM_registerTMCloneTable` (not `_ITM_deregisterTMCloneTable` — easy to swap with the sibling `deregister_tm_clones`).
- The indirect callee's signature is `(void *, size_t)` matching standard crtstuff.

### Reviewer checklist
