## deregister_tm_clones @ 0x1130 — Rewrite Notes

**What the pipeline did**
- Recognized this as the canonical compiler-emitted `crtstuff.c` stub that calls `_ITM_deregisterTMCloneTable` from the `.init_array`.
- Renamed the reloaded GOT value (`t0`/`ret`) to a typed function pointer `deregister`.
- Replaced `*&[var0+0x3fe0]` with a named symbol `_ITM_deregisterTMCloneTable_ptr` and the comparand with `__TMC_END__`.
- Collapsed both `goto L_1158` exits into early `return`s.
- Changed signature from `(arg0)` → `void` (no params), since the canonical stub takes none; the original `arg0` is modeled as `__TMC_END__`.

**Assumptions not mechanically provable**
- The GOT slot at base+0x3fe0 actually corresponds to `_ITM_deregisterTMCloneTable` (offset/symbol mapping not verified against the relocation table).
- The pseudocode's `arg0` is `__TMC_END__` — true for the standard crt invocation but the rewrite drops the parameter from the signature.
- Argument type to the resolved callback is `void *` (unconfirmed; canonical prototype takes no args, so this is also a minor deviation).
- No `completed.0 = 1` (or similar "already ran" flag write) was added, even though the real crtstuff stub typically performs one. The pseudocode does not show it, so it was left out — but this means if the real binary does set the flag, the rewrite is missing a side effect.

**Behavioral risk**
- Low if this is genuinely the standard stub invoked once from `.init_array`. Higher if (a) the binary sets a completion flag we dropped, or (b) `arg0` is ever something other than `__TMC_END__`.
