## frame_dummy @ 0x1920 — review note

### What the pipeline did
- Replaced the entire decompiled body with a single call: `register_tm_clones();`.
- This is a heavy semantic collapse, not a literal translation. The pseudocode shows the full body of `register_tm_clones` inlined (or mislabeled): it computes `(__TMC_END__ - __TMC_END__) >> 3`, halves it, checks for a non-null `*__TMC_END__`, and does an indirect call. The rewriter recognized this as the standard glibc CRT idiom and emitted the canonical one-liner.
- Dropped the sign-correction shift (`>> 63` then add) used by the compiler for signed `/8`.
- Dropped a dead `goto L_18a0` that follows `return`.

### Assumptions not mechanically provable
- That this binary uses the standard glibc CRT, where `frame_dummy` is just a tail call into `register_tm_clones`. The disassembly at this address actually looks like `register_tm_clones`'s body, suggesting either symbol mislabeling in the pseudocode or that the two were merged/inlined. Either way, the rewrite assumes standard CRT semantics rather than reproducing the observed instructions.
- That `register_tm_clones` is (or will be) defined elsewhere in the rewritten output with the standard glibc behavior.
- That no custom logic has been spliced into this CRT stub (e.g. by a packer or build-time hook) — a literal rewrite would catch that, this collapsed form would not.

### Reviewer checklist
