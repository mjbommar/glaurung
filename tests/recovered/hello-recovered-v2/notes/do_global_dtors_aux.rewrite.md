## `__do_global_dtors_aux` @ 0x18e0 — rewrite notes

### What the pipeline did
- Recognized this as the canonical GCC-emitted `__do_global_dtors_aux` and rewrote it against that template rather than a literal transcription.
- Renamed the guard byte at `ctx+0x4150` to `completed.0` (standard GCC name).
- Modeled the `*&[ctx+0x3fd0] == 0x3fd000000000` test as `__cxa_finalize != NULL` — i.e. the weak-symbol GOT check. The magic constant is the PIC self-reference pattern GCC emits for absent weak symbols.
- Interpreted the indirect call `0x11a0(*&[ctx+0x4008])` as `__cxa_finalize(__dso_handle)`.
- Merged the two tail paths (`L_1907` and fall-through) into a single post-`if` tail, since both run `deregister_tm_clones()` and set `completed.0 = 1`; the only difference is whether `__cxa_finalize` was called.
- Dropped the leading `nop`/endbr, and the `push rbp`/epilogue frame setup as non-observable artefacts.

### Assumptions not mechanically verified
- `0x11a0` is actually `__cxa_finalize` (inferred from pattern, not from symbol resolution shown here).
- `*&[ctx+0x4008]` is `__dso_handle` (inferred, not resolved).
- The magic `0x3fd000000000` genuinely encodes the weak-symbol-null test for this binary's PIC layout, not some other comparison that happens to match the template.
- The guard flag semantics (1-byte `completed.0`) match what the surrounding runtime expects.

### Reviewer checklist
