# register_tm_clones @ 0x1160 — Rewrite Note

## What the pipeline did
**Effectively nothing.** The "final source" is a stub: a `void sub_1160(void)` wrapper
whose body is the original pseudocode pasted verbatim inside the braces. This is not
compilable C — it still contains `fn register_tm_clones { ... }`, `%zf`, `>>>`,
`*&[var0+0x3fe8]`, and a bare `ret()` call.

The rewriter explicitly declared: *"Heuristic rewrite — LLM not consulted; treat
output as lightly-substituted pseudocode, not real source."* The verification step
also flagged that equivalence could not be checked because the LLM was unavailable.

## Semantic content (for reference)
This is the standard CRT `register_tm_clones` stub emitted by GCC. The arithmetic
(`(end - start) / sizeof(ptr) / 2` via shift-right-3 then shift-right-1 with sign
correction) computes whether the `__TMC_END__ - __TMC_LIST__` range is empty; if
non-empty and `_ITM_registerTMCloneTable` (loaded from GOT at `var0+0x3fe8`) is
non-NULL, it tail-calls it. Otherwise returns.

## Assumptions not mechanically provable
- That this function can safely be left as a non-compiling stub in the output tree
  (i.e., downstream build/link does not require it).
- That nobody will mistake the pasted pseudocode for real C.

## Recommendation
Either (a) drop this function from the rewritten output entirely since it is
compiler-generated CRT boilerplate that the linker/CRT will resupply, or
(b) hand-write a proper C equivalent before merging. Do **not** merge as-is — the
file will not compile.
