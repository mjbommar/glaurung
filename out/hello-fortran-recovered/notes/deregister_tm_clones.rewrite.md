## deregister_tm_clones @ 0x1130 — Rewrite Notes

This is a **compiler-emitted CRT stub**, not user code. The rewriter recognized the canonical `deregister_tm_clones` pattern emitted by GCC/Clang and reconstructed an idiomatic C analog rather than a literal transliteration of the pseudocode.

### Pipeline transformations
- **Pattern-matched the stub**: identified the GOT-relative load at `+0x3fe0` as the weak `_ITM_deregisterTMCloneTable` (or `__cxa_finalize`) pointer slot.
- **Collapsed the zero-register comparison**: `completed.0 == arg0` (where `arg0` is a register the compiler zeroed via `xor`) was rewritten as `completed.0 != 0`. This drops the explicit zero-register parameter from the model.
- **Renamed** the GOT slot to `__cxa_finalize_ptr` (canonical name is `_ITM_deregisterTMCloneTable`).
- **Removed the `ret` temp dead-store chain** and the fall-through `L_1158` label; replaced with early-return structure.
- **Reinterpreted the indirect call argument**: pseudocode shows `ret(completed.0)` (passing the value, ~0), but the rewrite emits `deregister(&completed.0)` (passing the address).

### Non-mechanically-provable assumptions
1. `arg0` really is always 0 on entry (depends on caller / ABI / xor-zeroing convention).
2. The GOT slot at `+0x3fe0` is the TM/finalize hook and not some other weak symbol.
3. The indirect call's intended argument is the guard's address, not its value — **this contradicts the literal pseudocode**.
4. The missing `completed.0 = 1` write-back (canonical stubs set this after calling) is genuinely absent in this binary, not lost during lifting.

### Reviewer checklist
