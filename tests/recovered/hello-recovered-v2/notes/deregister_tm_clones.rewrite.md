## deregister_tm_clones @ 0x1870 — review note

### What the pipeline did
- Recognized the function as the **canonical GCC CRT `deregister_tm_clones`** stub and rewrote it to its idiomatic C source form rather than a literal transliteration of the PIC-relative pseudocode.
- Replaced the indirect GOT load `*&[var0+0x3fe0]` with a direct reference to the weak symbol `_ITM_deregisterTMCloneTable`, declared `extern __attribute__((weak))`.
- Declared `__TMC_END__` as an `extern char[]` so the symbol decays to its address at the call site, matching the pseudocode's use of the symbol value as the argument.
- **Dropped the first early-return** (`ret == arg0` where both sides are `__TMC_END__`) on the grounds that it is a self-equality the linker collapses; only the weak-symbol NULL check is preserved.
- Renamed the implicit register temporary `ret`/`t0` away — the rewritten form has no locals.

### Assumptions not mechanically provable
- That this really is the stock GCC CRT pattern and not a customized variant — the dropped first compare is assumed dead, but the pseudocode literally shows it being evaluated against `arg0` (the function actually takes an argument in the pseudocode, but is declared `void` in the rewrite).
- That GOT offset `0x3fe0` corresponds specifically to `_ITM_deregisterTMCloneTable` (inferred from idiom, not verified against the binary's relocations/GOT layout).
- That the called pointer's argument convention matches `void(*)(void*)` — the pseudocode shows a single arg being passed; signature is assumed.
- That `__TMC_END__` is the correct symbol passed (canonical pattern uses it; pseudocode is consistent but the symbol identity is inferred from the CRT idiom).

### Behavioral note
The rewrite changes the function's source-visible signature from one-arg to zero-arg. At the ABI level for this CRT stub this is conventional, but a caller passing an argument would now be ignored.

### Reviewer checklist
- Confirm the binary's GOT slot at `var0+0x3fe0` actually relocates to `_ITM_deregisterTMCloneTable` (check relocations / `readelf -r`).
- Confirm `__TMC_END__` is defined in this binary (typically by `crtend.o`) and is the symbol loaded as the call argument.
- Verify no caller of `deregister_tm_clones` relies on the original `arg0` parameter — the rewrite drops it.
- Confirm dropping the first `ret == arg0` early-return is safe (i.e. this is the stock GCC stub, not a hand-modified variant where the two operands could differ at runtime).
- Spot-check that the companion `register_tm_clones`/`__do_global_dtors_aux` routines were recovered consistently with this idiom.
- Confirm the weak attribute and `extern char __TMC_END__[]` declarations compile cleanly in the surrounding TU without colliding with toolchain-provided versions.