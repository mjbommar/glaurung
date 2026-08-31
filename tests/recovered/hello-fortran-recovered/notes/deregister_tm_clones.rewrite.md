## deregister_tm_clones @ 0x1130 — Rewrite Notes

### What the pipeline did
- Recognized this as the **canonical crtstuff stub** the compiler emits and produced the textbook idiomatic form rather than a literal transliteration.
- **Renamed** `t0`/`ret` → `deregister` to express the function-pointer role.
- **Collapsed** the two `goto L_1158` jumps into early `return` statements (semantics-preserving).
- **Abstracted** the raw GOT load `*(base+0x3fe0)` into a named symbol `_ITM_deregisterTMCloneTable_ptr`.
- **Abstracted** the `arg0` comparison sentinel into `__TMC_END__` and dropped the parameter, changing the signature from `(arg0)` to `(void)`.
- Preserved the call-site argument as `completed.0` (not `&__TMC_END__`) per prior feedback.

### Assumptions not mechanically provable
- The GOT slot at `+0x3fe0` is specifically `_ITM_deregisterTMCloneTable`'s entry — based on idiom, not relocation data.
- The compared sentinel is `__TMC_END__` and matches what the linker-generated init array passes as `arg0`.
- The callee's signature is `void (*)(void *)`; the pseudocode only shows one argument passed.
- No `completed.0 = 1` post-call store exists (intentionally not invented; pseudocode doesn't show one, but real crtstuff usually has it).
- Dropping the function parameter is safe because the only caller is the linker-synthesized init code passing `__TMC_END__`.

### Reviewer checklist
