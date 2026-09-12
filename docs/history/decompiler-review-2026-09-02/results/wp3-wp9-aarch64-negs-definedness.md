# WP3/WP9 AArch64 `negs` definedness

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `ca0927e7` closes the two strict AArch64 `signed_remainder`
expected-failure cells. Capstone spells `subs dst, xzr, src` as the `negs`
alias. The AArch64 lifter recognised plain `neg` but emitted `negs` as
`Unknown`, losing both its destination definition and the fresh condition
flags consumed by the following `csneg ..., mi`.

`negs` now emits the negated destination plus result zero/sign facts. This
keeps the instruction semantics target-local, as WP9 requires, while restoring
the WP3 def-use chain. The emitted O0 and O2 functions now have the source's
single parameter and no undefined predicate or arithmetic operand. The
definedness invariant was also strengthened to include rendered predicate
identities such as `slt_0`, which previously escaped its `varN`-only scan.

## Evidence

- The exact encoded `negs x2,x1` lifter regression passes and rejects both an
  opaque instruction and a missing sign-condition definition.
- All 47 AArch64 lifter module tests pass.
- A fresh release extension emits one-parameter, definition-complete
  `signed_remainder` functions for both AArch64 O0 and O2.
- The defined-value and source-arity invariant families pass all 16 selected
  architecture/optimisation cells.
- The six-function decompiler smoke slice remains green on the preceding
  fresh build.

The generated test census was not updated in this commit: the shared checkout
currently contains 17 additional uncommitted Rust tests from another lane in
addition to this increment's one test. Regenerating now would pin unfinished
foreign work. Census regeneration remains due after that lane lands. No broad
suite, DecBench run, or upstream interaction was performed.
