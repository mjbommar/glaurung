## frame_dummy @ 0x1920 — review note

### What the pipeline did
- Collapsed the entire body of `frame_dummy` into a single call: `register_tm_clones();`.
- Dropped the inlined `(__TMC_END__ - __TMC_LIST__)` subtraction, the `>> 3` (divide by `sizeof(void*)`), the sign-bit correction (`+ (x >> 63)`), and the final `>> 1` — moving them conceptually into `register_tm_clones`.
- Dropped the NULL-check on the GOT slot at `var0+0x3ff0` and the conditional indirect tail-call; rewrote as an unconditional direct call.
- Dropped dead stores, the trailing `nop`, and the `goto L_18a0` back edge (which looks like a disassembly artifact / unreachable fallthrough).

### Assumptions not mechanically provable
- That this is the **canonical GCC crtstuff `frame_dummy`** wrapper. Pattern-matching only — not verified against the toolchain that produced the binary.
- That the indirect call through `*(GOT + 0x3ff0)` resolves to `register_tm_clones` (and not, e.g., `__cxa_finalize` or a different ITM/TM helper). The offset is plausible but unverified.
- That the size/NULL guards being absent in the C source is acceptable because `register_tm_clones` re-performs them. If the original `frame_dummy` was hand-rolled or from a non-standard crt, the guards would be observable.
- The `goto L_18a0` edge was treated as unreachable noise rather than a real loop.

### Reviewer checklist
