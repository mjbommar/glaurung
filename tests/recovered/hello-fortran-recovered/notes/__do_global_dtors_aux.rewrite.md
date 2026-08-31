## __do_global_dtors_aux — rewrite notes

This is the standard GCC-emitted CRT helper that runs once at shutdown. The pipeline recognized the canonical three-part shape and reconstructed the conventional C form.

### What the pipeline did
- **Pattern-matched** the function against the canonical `__do_global_dtors_aux` template emitted by GCC.
- **Renamed memory operands** to their conventional names: `[ctx+0x4010]` → `completed.0`, `[ctx+0x4008]` → `__dso_handle`, `[ctx+0x3ff0]` → `__cxa_finalize` (weak).
- **Mapped indirect call** through `0x10c0` to `__cxa_finalize` (PLT stub).
- **Inverted the guard** (`t10 == 0` → goto-return) into the idiomatic `if (completed.0) return;` early exit.
- **Collapsed** the two tail paths (L_11c7 and fallthrough) into a single `deregister_tm_clones(); completed.0 = 1;` epilogue, since they differ only by the optional `__cxa_finalize` call.
- **Dropped** rbp prologue/epilogue and label L_11d8 as artefacts.

### Assumptions not mechanically proven
- That `[ctx+0x3ff0]` is genuinely the weak `__cxa_finalize` symbol slot. The original compares against `0x3ff000000000` (not 0), which is unusual — the rewriter assumes this is a decompiler artefact / encoded weak-NULL test typical of canonical GCC output, not a real magic-value comparison.
- That `0x10c0` is the `__cxa_finalize` PLT stub (not some other function).
- That `[ctx+0x4008]` is `__dso_handle` rather than another global.
- That the function is in fact the unmodified compiler-emitted helper and not a hand-rolled lookalike.

### Reviewer checklist