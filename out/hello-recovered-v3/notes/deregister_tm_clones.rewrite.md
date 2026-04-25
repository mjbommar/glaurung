## deregister_tm_clones — rewriter notes

**What the pipeline did**
- Recognized this as the standard GCC-emitted CRT stub `deregister_tm_clones` and reshaped it accordingly.
- Inverted `goto L_1898` control flow into two early `return` statements.
- Collapsed the dead-store chain (`ret = ...; t0 = ret; if (t0 == 0)`) into a single local named `deregister`.
- Renamed `arg0` → `__dso_handle` and the loaded function pointer → `deregister` (intended to represent `_ITM_deregisterTMCloneTable`).
- Replaced the RIP/PIC-base relative load `*&[var0+0x3fe0]` with a synthetic `GOT_BASE + 0x3fe0` expression.
- Added `static` linkage and a descriptive comment.

**Assumptions not mechanically provable**
- That `arg0` is actually `__dso_handle` — the pseudocode just shows an unnamed parameter; the compared value is inferred from CRT idiom, not from the binary.
- That the GOT slot at `+0x3fe0` is `_ITM_deregisterTMCloneTable` specifically (symbol name is not preserved).
- That this function is file-local (`static`) — original linkage is not visible from the snippet.
- That the function takes no parameters: pseudocode references `arg0`, but the rewrite declares `(void)`. The comparison `__TMC_END__ == arg0` was reinterpreted as a comparison against a global, dropping the parameter.

**Known divergences (flagged low)**
- Dead initializer to `__dso_handle_lookup` (immediately overwritten).
- Invented `GOT_BASE` symbol — won't compile as-is without a definition.
- `__dso_handle_lookup` symbol is also invented and unused.

**Compileability concern:** `GOT_BASE` and `__dso_handle_lookup` are not real symbols; this file likely will not build without substitution or replacement with the proper extern weak symbol declaration of `_ITM_deregisterTMCloneTable`.
