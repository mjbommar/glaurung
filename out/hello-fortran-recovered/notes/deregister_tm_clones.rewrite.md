# `deregister_tm_clones` @ 0x1130 — Reviewer Note

## What the pipeline did
**Effectively nothing.** This is a heuristic fallback: the rewriter wrapped the
original pseudocode verbatim inside a `void sub_1130(long arg0)` C function
shell. No real translation occurred:

- The pseudocode block (`fn deregister_tm_clones { ... }`) is pasted as-is
  inside the C function body, which is **not valid C** and will not compile.
- No locals were renamed, no control flow was reconstructed, no `goto`
  lowering, no call site for the indirect dispatch (`ret(completed.0)`) was
  emitted as a real C call.
- The function name in the wrapper (`sub_1130`) does not match the symbol
  (`deregister_tm_clones`).

## Assumptions not mechanically provable
- That `arg0` is the correct (and only) parameter — the symbol is normally
  the standard CRT `deregister_tm_clones()` taking **no arguments**; `arg0`
  likely reflects a register the disassembler couldn't prove dead.
- That `completed.0` is compared to a parameter rather than to a constant
  (in the canonical CRT stub it's compared against an address loaded via
  PC-relative arithmetic, not a function argument).
- That `*&[var0+0x3fe0]` is a load from `.got`/`_ITM_deregisterTMCloneTable`;
  the rewriter never resolved this.

## Divergences
- LLM was unavailable; no equivalence check was performed. Output should be
  treated as pseudocode, not source.

## Bottom line
Do **not** merge as C. This needs a real rewrite pass (or simply replace
with the well-known stock `deregister_tm_clones` CRT stub).
