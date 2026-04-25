## frame_dummy @ 0x1920 — review note

### What the pipeline did
- Replaced the entire decompiled body with a single call to `register_tm_clones()`, matching the standard glibc CRT idiom for `frame_dummy`.
- Dropped all the literal arithmetic from the pseudocode: the `__TMC_END__ - __TMC_END__` subtraction, the signed-division-by-8 sign-correction (`>> 63` then `>>> 3`), the divide-by-2, and the zero-check guard around the indirect call through `*__TMC_END__`.
- Dropped the unreachable `goto L_18a0` tail after `return` (dead code / NOP padding artefact).
- No locals were renamed because the rewrite contains none; the rewrite is structural, not a literal translation.

### Assumptions not mechanically provable
- The pseudocode body shown does **not** match a typical `frame_dummy` (which is usually just a tail-call to `register_tm_clones`); it instead looks like the body of `register_tm_clones` itself. The rewriter assumed the symbol/prototype is correct and that collapsing to `register_tm_clones()` is behaviorally equivalent to what the original CRT does at this address.
- Assumed this is unmodified glibc CRT scaffolding and not a custom/obfuscated routine that happens to resemble it.
- Assumed the indirect call `ret()` through `*__TMC_END__[0]` and the loop/divide logic are exactly the canonical TM-clone registration pattern, not something subtly different (e.g. a different table, different stride).

### Risk
Low. `frame_dummy` is boilerplate; if this is a stock binary the rewrite is correct. If the binary is non-standard, the rewrite hides real logic.
