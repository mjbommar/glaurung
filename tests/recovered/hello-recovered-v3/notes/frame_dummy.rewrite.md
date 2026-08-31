## frame_dummy @ 0x1920 — Reviewer Note

### What the pipeline did
- Collapsed the entire body to a single call: `register_tm_clones();`.
- Treated the function as the standard glibc CRT `frame_dummy` idiom, which on most toolchains is just a tail-call into `register_tm_clones`.
- Discarded the visible body (the `(__TMC_END__ - __TMC_END__)/8/2` size computation, the sign-correction `>>63` for signed division, the load of `*&[var0+0x3ff0]`, and the conditional indirect call).
- Dropped the unreachable `nop; goto L_18a0;` tail after `return`.

### Assumptions not mechanically provable
- That this symbol really is `frame_dummy` and the disassembled body is misattributed (or that the compiler inlined `register_tm_clones` into `frame_dummy`). The rewriter explicitly notes the pseudocode body looks like `register_tm_clones`, not `frame_dummy`.
- That a separate `register_tm_clones` symbol exists in the rebuilt translation unit and is semantically equivalent to the inlined body shown.
- That the indirect call target `*(&var0+0x3ff0)` is the conventional `__TMC_END__[0]` / deregister hook and not something custom.

### Risk
Low for behavior on a normal glibc target (this is boilerplate CRT scaffolding the loader/CRT calls once). Higher risk if this binary is non-glibc, statically linked oddly, or has a customized CRT — in that case the collapse hides real logic.

### Reviewer checklist
- Confirm symbol at 0x1920 is actually `frame_dummy` (check ELF symtab / `.init_array`).
- Confirm a `register_tm_clones` function exists in the rebuilt source and matches the inlined body (size = (__TMC_END__ − __TMC_START__)/8, halved, indirect-call guard on `__TMC_END__`).
- Verify the original used `__TMC_END__` for both operands (true zero-size, dead code) vs `__TMC_END__ - __TMC_START__` — pseudocode shows `__TMC_END__` twice, which may itself be a disassembler artifact worth checking against raw asm.
- Verify `var0+0x3ff0` resolves to the expected `__TMC_END__` / GOT slot for the deregister hook.
- Confirm dropping the unreachable `goto L_18a0` matches the original CFG (no other edge into L_18a0 from elsewhere).
- Sanity-check `.init_array` / `.fini_array` still wires up correctly after rewrite.