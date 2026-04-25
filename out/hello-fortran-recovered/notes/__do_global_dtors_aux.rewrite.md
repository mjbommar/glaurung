## `__do_global_dtors_aux` — rewrite note

### What the pipeline did
- Recognized this as the **canonical GCC-emitted `__do_global_dtors_aux`** crt stub and rewrote it to its standard textbook form rather than a literal transliteration.
- Renamed memory slots to their canonical symbolic names:
  - `[ctx+0x4010]` → `completed.0` (guard flag)
  - `[ctx+0x3ff0]` → weak `__cxa_finalize` symbol
  - `[ctx+0x4008]` → `__dso_handle`
  - indirect call `0x10c0(...)` → `__cxa_finalize(...)` via PLT
- **Inverted** the guard check (`t10 == 0` → goto-return) into the canonical positive `if (completed.0) return;` early-out. Semantically equivalent.
- **Collapsed two return paths** (L_11c7 and fallthrough) into a single tail running `deregister_tm_clones()` + `completed.0 = 1`, since they only differ in whether `__cxa_finalize` is called.
- Dropped `rbp` push/pop as ABI prologue/epilogue noise.

### Assumptions not mechanically provable
- The constant `0x3ff000000000` in the original compare is treated as a weak-symbol non-NULL test. This **does not match a literal `!= 0`** check; the rewriter is relying on pattern-matching to GCC's canonical stub rather than literal semantics. If the disassembler decoded the immediate or operand wrong, this could mask a real different comparison.
- The mapping of offsets `0x4010 / 0x3ff0 / 0x4008` to `completed.0 / __cxa_finalize / __dso_handle` is by convention only; nothing in the pseudocode proves these identities.
- The PLT target `0x10c0` is assumed to be `__cxa_finalize` without symbol-table confirmation shown.

### Reviewer checklist
