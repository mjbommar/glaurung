## __do_global_dtors_aux — rewrite notes

This is the standard compiler-emitted CRT helper. The pipeline reconstructed it into the canonical libc/CRT idiom rather than a literal transliteration.

### What the pipeline did
- **Renamed anonymous globals** to conventional names: `ctx+0x4010` → `completed`, `ctx+0x4008` → `__dso_handle`, `ctx+0x3ff0` → `__cxa_finalize_ptr`. These names are inferred from pattern, not from symbols in the binary.
- **Identified the indirect call** `0x10c0(...)` as `__cxa_finalize` based on the surrounding dtor-aux shape.
- **Replaced the magic-value test** `*(ctx+0x3ff0) == 0x3ff000000000` with a `!= NULL` check. The replacement is *semantically* the standard "weak symbol bound?" pattern, but the literal sentinel `0x3ff000000000` is **not preserved** in source.
- **Dropped the rbp prologue/epilogue** as ABI noise.
- **Merged the two exit paths** (L_11c7 and the post-call return) into a single fallthrough; both ran `deregister_tm_clones()` and set `completed = 1`, so behavior is equivalent.

### Assumptions not mechanically provable
- That `0x10c0` really is `__cxa_finalize` (no symbol; inferred from context).
- That the global names map to `completed` / `__dso_handle` / `__cxa_finalize_ptr`.
- That `0x3ff000000000` is a "not-bound" sentinel and a NULL comparison is an acceptable substitute. The two are not bit-identical tests; they are equivalent only under the assumption this is the conventional CRT pattern.
- That this function is in fact compiler-generated boilerplate and not a hand-rolled lookalike with subtly different semantics.

### Reviewer checklist
- Confirm `0x10c0` is the PLT/stub for `__cxa_finalize` (check disassembly at that address).
- Confirm `ctx+0x4008` holds `__dso_handle` (typically points into `.data` near the DSO descriptor).
- Confirm `ctx+0x4010` is a single-byte guard in `.bss` only written here.
- Decide whether losing the literal `0x3ff000000000` sentinel matters for your audit — if exact-test fidelity is required, restore it as an explicit comparison or comment.
- Verify this TU is built from compiler-generated CRT glue (so the canonical rewrite is appropriate); if it's user code, reject the idiomatic substitution.
- Confirm dropping the rbp save/restore is acceptable for your reproducibility goals.
