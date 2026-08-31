## __do_global_dtors_aux @ 0x18e0 — Rewrite Notes

### What the pipeline did
- **Recognized boilerplate**: Identified this as the canonical GCC-emitted `__do_global_dtors_aux` and rewrote it to its idiomatic source form rather than a literal transliteration.
- **Renamed memory slots** to their conventional names:
  - `*(ctx+0x4150)` → `completed` (the `completed.0` guard byte)
  - `*(ctx+0x3fd0)` → weak reference to `__cxa_finalize`
  - `*(ctx+0x4008)` → `__dso_handle`
  - indirect call `0x11a0(...)` → `__cxa_finalize(...)`
- **Collapsed control flow**: The two distinct return paths in the pseudocode (one calling `__cxa_finalize`, one not — both then doing `deregister_tm_clones()` and setting `completed=1`) were merged into one linear sequence guarded by a NULL check.
- **Reinterpreted the magic constant**: The compare against `0x3fd000000000` is treated as a NULL test on the weak `__cxa_finalize` symbol (relocation strength-reduction artifact).
- **Dropped frame artifacts**: `push rbp` / restore rbp removed as ABI noise.

### Assumptions not mechanically provable
- That the three ctx-relative offsets (0x4150, 0x3fd0, 0x4008) really map to `completed.0`, the `__cxa_finalize` GOT slot, and `__dso_handle` respectively. This is inferred from the GCC pattern, not proven from the binary alone.
- That `0x11a0` is in fact `__cxa_finalize` (only the call shape was matched).
- That `0x3fd000000000` is a relocation/PIE artifact equivalent to a NULL check, rather than a genuine value comparison.
- That nothing observable depends on the exact structure of the two original return paths (e.g., a debugger or profiler distinguishing them).

### Reviewer checklist
