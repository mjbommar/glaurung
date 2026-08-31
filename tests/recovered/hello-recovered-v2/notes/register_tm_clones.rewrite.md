## register_tm_clones @ 0x18a0 — Rewrite Notes

### What the pipeline did
- Recognised this as the **canonical GCC `crtstuff.c` `register_tm_clones`** boilerplate and rewrote it to its conventional C form rather than transliterating the pseudocode.
- Renamed the lone local to `size` and dropped decompiler-only temporaries (`arg0`, `arg1`, `ret`, `t0`) that had no semantic effect.
- Replaced the bitshift sequence `(x>>3) + ((x>>3)>>63)) >> 1` with `/ sizeof(void *)` (see divergence below).
- Reconstructed the indirect GOT call `*&[var0+0x3ff0]` as the weak symbol `_ITM_registerTMCloneTable` and added the standard NULL-guard.
- Consolidated the two early-exit branches (zero-size, null pointer) into two `if (...) return;` statements.
- Substituted `__TMC_LIST__` for the second `__TMC_END__` in the subtraction (decompiler showed the same symbol twice).

### Assumptions not mechanically provable
- That the second operand of the subtraction is `__TMC_LIST__` — the pseudocode literally shows `__TMC_END__ - __TMC_END__`, which would be a constant zero. Reliance on convention.
- That the GOT slot at `var0+0x3ff0` is `_ITM_registerTMCloneTable` (not e.g. `_ITM_deregisterTMCloneTable`, which is the sibling routine). Distinguished only by which symbol the linker placed at that GOT offset.
- That the divisor is `sizeof(void *)` (8). The pseudocode actually performs signed `/16` (shift by 4 total). The rewriter chose 8 because that's what canonical GCC source uses; this is a real semantic deviation from the bytes.
- Use of unsigned `size_t` arithmetic vs. the original signed-rounding division — equivalent only when `__TMC_END__ >= __TMC_LIST__`.

### Reviewer checklist
- Confirm divisor: disassemble and verify shift count is `>>3` then `(x+(x>>63))>>1` ⇒ `/16`, and decide whether to keep `/sizeof(void*)` (canonical source) or correct to `/(2*sizeof(void*))` to match bytes.
- Verify the GOT entry at `var0+0x3ff0` resolves to `_ITM_registerTMCloneTable` and not its deregister counterpart.
- Confirm both `__TMC_END__` references in the pseudocode are indeed a decompiler artefact (check the actual relocations/symbols at the two load sites — one should be `__TMC_LIST__`).
- Confirm the function is paired correctly with a `deregister_tm_clones` and is invoked from `__do_global_dtors_aux` / frame_dummy as expected for crtstuff.
- Confirm `static` linkage and absence of stack frame match the original (no leaked locals/spills).
- Sanity-check that `__TMC_END__ >= __TMC_LIST__` always holds so the unsigned cast is safe.