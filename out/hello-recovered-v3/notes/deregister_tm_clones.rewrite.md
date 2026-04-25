## deregister_tm_clones @ 0x1870 — review note

### What the pipeline did
- Recognized this as the **standard GCC CRT stub** `deregister_tm_clones` and rewrote in the canonical source form (early-returns instead of goto/label chain).
- Renamed the anonymous loaded pointer (`ret`/`t0`) to a single local `deregister` and dropped the redundant `ret = ...; t0 = ret` dead-store chain.
- Reinterpreted `arg0` as `__dso_handle` — the function is actually `void (void)` at source level; the "arg0" in pseudocode is just whatever was in the first arg register at entry, which GCC's stub doesn't read. The comparison is `__TMC_END__ == __dso_handle`.
- Modeled `*&[var0+0x3fe0]` as a GOT load via an invented `GOT_BASE` symbol; the underlying weak symbol is `_ITM_deregisterTMCloneTable` but that name is not in the binary.
- Marked `static` (file-local CRT helper).

### Unprovable assumptions
- That this really is the unmodified GCC `deregister_tm_clones` and not a customized variant — only the shape matches; there's no symbol-name evidence in the supplied pseudocode.
- That `arg0` is genuinely unused at the source level (the stub takes no args). If the caller actually passes something meaningful, the rewrite changes the ABI surface.
- That `var0+0x3fe0` is a GOT slot for the TM deregister callback rather than some other data pointer.

### Stylistic / cosmetic
- The initializer `= (void (*)(void *))__dso_handle_lookup` is dead (overwritten before use) and the symbol `__dso_handle_lookup` is fabricated; should likely be removed or replaced with `= NULL`.
- `GOT_BASE` is a placeholder — won't compile as-is unless the build provides it.
