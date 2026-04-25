## frame_dummy @ 0x11e0 — Reviewer Note

### What the pipeline did
- Collapsed the entire decompiled body to an empty `static void frame_dummy(void)` stub.
- Discarded the `completed.0 - completed.0` computation, the `>>63` sign-extract / `>>>3` / `>>>1` shift sequence, and the conditional indirect call through `*(GOT+0x3fe8)` as compiler/optimizer artefacts.
- Dropped the trailing `goto L_1160` (loop back-edge) on the assumption it is unreachable.
- Renamed nothing meaningful — the entire body was treated as dead code.

### Assumptions not mechanically proven
- That this really is the standard glibc crt `frame_dummy` and not a custom function that happens to share the name/shape. Identification is by pattern, not by symbol provenance.
- That `completed.0` is genuinely the static guard variable such that `x - x == 0` holds at the source level (the pseudocode shows two reads of `completed.0`, which *should* be identical, but the rewriter assumed both loads see the same value with no intervening side effect — true here, but a semantic assumption).
- That `*(rip+0x3fe8)` (the JCR/`__JCR_END__` or deregister pointer) is NULL in this binary, so the indirect call is never taken at runtime. Not verified against the actual section contents.
- That the `goto L_1160` tail is the conventional `register_tm_clones`-style loop epilogue and not a live edge.

### Risk
Low. If the binary is built with a non-trivial JCR list (very old toolchains, or `-fuse-ld` quirks), the omitted indirect call would actually run at startup and the empty stub would silently skip frame registration. On any modern glibc/gcc/clang target this is a no-op.

### Reviewer checklist
