## `__do_global_dtors_aux` @ 0x18e0 — rewrite notes

This is the standard GCC-emitted destructor-aux stub. The pipeline recognized the canonical pattern and rewrote the disassembly into the textbook source form.

### What the pipeline did
- **Renamed locals/globals** to match the GCC source convention:
  - `*(ctx+0x4150)` → `completed` (the `completed.0` guard byte)
  - `*(ctx+0x3fd0)` → weak reference to `__cxa_finalize`
  - `*(ctx+0x4008)` → `__dso_handle`
  - indirect call `0x11a0(...)` → `__cxa_finalize(__dso_handle)`
- **Collapsed control flow**: the two distinct return paths in the pseudocode (one taking the `__cxa_finalize` call, one skipping it) were merged into a single linear sequence, since both set `completed = 1` and call `deregister_tm_clones()`.
- **Replaced the odd compare** `t10 == 0x3fd000000000` with an idiomatic `__cxa_finalize != NULL` test, on the theory that the magic constant is a relocation/strength-reduction artifact of the weak-symbol GOT check.
- **Dropped** the `push rbp` / epilogue restore as ABI noise.

### Assumptions not mechanically provable
- That `0x3fd000000000` truly is a relocation artifact and the test is semantically equivalent to a NULL check on `__cxa_finalize`. If the linker/loader leaves this as a literal value comparison, the rewrite changes behavior.
- That the offsets `0x4150`, `0x3fd0`, `0x4008` correspond to `completed`, the weak `__cxa_finalize` slot, and `__dso_handle` respectively (inferred from the canonical pattern, not verified against this binary's symbol table).
- That `0x11a0` resolves to `__cxa_finalize` (assumed from call-site shape, not confirmed via PLT/symbol lookup).
- The two-path → one-path collapse assumes no other observable difference between the branches (true for the shown pseudocode, but worth a glance).

### Reviewer checklist
