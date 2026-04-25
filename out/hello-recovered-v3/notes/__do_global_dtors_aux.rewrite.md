# Review Note: `__do_global_dtors_aux` @ 0x18e0

## What the pipeline did
- Recognized the function as the standard GCC-emitted `__do_global_dtors_aux` crt boilerplate and rewrote it to its canonical idiomatic C form.
- **Renamed** the byte flag at `ctx+0x4150` to `completed` (matches GCC's `completed.0` guard).
- **Renamed** indirect call target `0x11a0` → `__cxa_finalize` and its argument `*&[ctx+0x4008]` → `__dso_handle`.
- **Reinterpreted** the comparison `flag == 0x3fd000000000` as a `NULL` check on a weak symbol; the magic constant is treated as a relocation/strength-reduction artifact rather than a real value.
- **Consolidated control flow**: the two distinct return paths in the pseudocode (one that calls `__cxa_finalize`, one that skips it) were merged into a single linear sequence, since both tail-call `deregister_tm_clones()` and set `completed = 1`.
- **Dropped** the `push rbp` / epilogue as ABI noise.

## Non-mechanically-provable assumptions
- That `0x11a0` is genuinely `__cxa_finalize` and `ctx+0x4008` is `__dso_handle` — based on pattern recognition, not symbol resolution.
- That `0x3fd000000000` is a relocation artifact representing a weak-symbol NULL test, not a meaningful runtime value.
- That `ctx+0x4150` is the `completed` guard byte (vs. some other module-local flag).
- That collapsing the two return paths is safe — they are *textually* identical post-rewrite, but the original pseudocode shows them as distinct basic blocks.

## Reviewer checklist
- Confirm `0x11a0` resolves to a PLT/IFUNC stub for `__cxa_finalize` (check the binary's PLT or relocation entries).
- Confirm `ctx+0x4008` holds the address of `__dso_handle` (check `.data`/`.got` layout).
- Confirm `ctx+0x4150` is a 1-byte `completed` flag in `.bss` and is not referenced by any other function.
- Verify the `0x3fd000000000` constant is the result of a weak-symbol relocation (inspect the original instruction's relocation entry); if it's a real runtime comparison, the rewrite is wrong.
- Sanity-check that no other function depends on `rbp` being preserved across this call (it shouldn't — this is a leaf-ish crt routine).
- Confirm the function is in a `.text.startup`/`.fini_array`-referenced section consistent with crt destructor boilerplate.
