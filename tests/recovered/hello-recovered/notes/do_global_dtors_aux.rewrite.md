## do_global_dtors_aux @ 0x18e0 — review note

### What the pipeline did
- Recognized the function as the standard GCC-emitted `__do_global_dtors_aux` crt boilerplate and rewrote it to the canonical form.
- Renamed the flag at `[var0+0x4150]` to `completed.0` (the conventional static guard name).
- Reinterpreted the call target `0x11a0` as the PLT stub for `__cxa_finalize`, and `[var0+0x4008]` as `__dso_handle`.
- Collapsed the two branches after the weak-symbol test: both originally called `deregister_tm_clones()` and set the completion flag, so the rewrite factors that tail into a single path and only guards the `__cxa_finalize` call.
- Dropped `push rbp` / rbp-restore as pure ABI/frame artifacts.

### Assumptions not mechanically provable
- That `0x11a0` actually resolves to `__cxa_finalize` (not verified against the PLT/relocation table here) and that `[var0+0x4008]` is `__dso_handle`.
- That the `== 0x3fd000000000` compare is a decompiler rendering artifact for a RIP-relative `cmp qword ptr [rip+disp], 0` against a weak `__cxa_finalize` symbol (i.e. the literal is the absolute address of the GOT slot, not a real magic value). This is the usual GCC pattern but should be confirmed.
- That both original branches are semantically equivalent modulo the `__cxa_finalize` call — the rewrite assumes no other side effects differ between the two paths.

### Reviewer checklist
