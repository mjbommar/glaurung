## frame_dummy @ 0x1920 — rewrite notes

### What the pipeline did
- Collapsed the entire decompiled body into a single call: `register_tm_clones();`.
- The original pseudocode is the classic inlined `register_tm_clones` body:
  - Computes `(__TMC_END__ - __TMC_END__) >> 3` plus sign-adjusted shift (array length / 8).
  - If length is zero → return.
  - Loads a callback pointer from `GOT[+0x3ff0]`; if null → return; else indirect-call it.
- Dropped all the intermediate arithmetic and the indirect call as dead once rewritten as a call to the already-named helper.
- Ignored the supplied string-literal rename table (correctly — no strings are referenced here).

### Assumptions not mechanically proven
- That the inlined code really is `register_tm_clones` and not some customized variant. This is inferred from the shape (TMC_END subtraction, `>>3`, GOT slot load, indirect call) matching the standard GCC `crtstuff.c` pattern.
- That a separately-recovered `register_tm_clones` function exists in the output and is semantically equivalent to the inlined body here (same GOT slot, same arithmetic).
- That `var0+0x3ff0` resolves to the ITM deregistration GOT entry and is not used for anything else.

### Reviewer checklist