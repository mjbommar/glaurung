# WP3 typed simplification and widening require identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `76cf5679` deletes the identity-free entry points for the remaining two
typed width-transformation packages:

- consumed machine-extension simplification; and
- contextual widening-cast insertion.

Both recursive traversals now require `ValueIdentities`. Promoted-store
eligibility uses only producer-owned stack-object facts, and declared source or
destination widths query the same required sidecar. The widening API also keeps
target machine width mandatory, so ILP32 callers cannot silently inherit an
LP64 default.

Legacy tests now construct explicit parameter, promoted-object, and generated-
value identities. One first rerun exposed exactly that stale setup: the
`exact_narrow_value_assignment_keeps_wrapping_arithmetic_narrow` test expected
`var0` to remain narrow but had supplied no identity for it. Adding the value's
explicit test identity restored the intended contract; production code was not
relaxed.

## Focused evidence

```text
ir::typed_simplify::tests:  7 passed, 0 failed
ir::widen::tests:          25 passed, 0 failed
ir::const_fold::tests:     82 passed, 0 failed
decbench_ render tests:    86 passed, 0 failed
```

A fresh release build completed and `tools/build_guard.py` reported `fresh`
with native SHA-256
`2846696835b4fbd2828579da948a9bc39d5a1969ff235b3561e30805d79a229e`.
All four `@widths` fixture lanes passed with no scoped regression. The periodic
six-cell cross-architecture Hello checkpoint passed on the immediately
preceding declaration-plan increment and was not repeated.

No tests were added, so the census is unchanged. Other shared-worktree edits
were not staged. No broad Rust, Python, fixture, DecBench, or Joern suite ran.

## Scope

Typed constant folding, typed simplification, and contextual widening now all
require the pipeline-owned identity sidecar. Early copy propagation and other
explicit pre-sidecar compatibility paths remain to be classified and migrated
before `tag_phys` can be removed. WP3 is not complete.
