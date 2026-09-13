# WP3 signed-comparison domains require identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `092fec66` closes a hidden display-name dependency in high-variable
signedness refinement. The pass may reinterpret an exact narrow high-bit
literal as unsigned when every use proves that its positive value is preserved.
A signed comparison against a genuinely wide signed value is one such proof,
but the recursive use analysis previously asked a no-sidecar declaration helper
whether the opposite operand was wide. Consequently, an arbitrary unowned
register spelled `arg99` could provide the proof and change the candidate's C
signedness.

The recursive statement/expression analysis now carries the already-required
`ValueIdentities` sidecar. A register supplies a wide signed comparison domain
only when it has unambiguous physical-storage identity or an authoritative
source-parameter slot, and its selected declaration is signed and eight bytes.
The standalone AST compatibility helper remains unchanged after its owning
const-fold tests proved that deleting it would be a separate migration.

## Red/green evidence

The new regression failed before the production change:

```text
unowned_arg_spelling_does_not_supply_a_wide_signed_comparison_domain
left:  Some(Int { signed: false, width: 4 })
right: Some(Int { signed: true, width: 4 })
```

It passed after identity authority reached the comparison-domain decision. The
exact opaque-storage and legacy wide-domain positive controls also passed.
Focused owning and adjacent modules then reported:

```text
ir::high_variables::tests:  38 passed, 0 failed
ir::ast::return_ctype:       8 passed, 0 failed
ir::const_fold::tests:      82 passed, 0 failed
ir::typed_simplify::tests:   7 passed, 0 failed
```

The first attempt to delete the shared no-sidecar declaration helper produced
four red const-fold compatibility contracts. That attempt was fully reverted;
the same 82-test module then passed.

A fresh release build completed and `tools/build_guard.py` reported `fresh`
with native SHA-256
`dad8cf8b23fc217619e3e73dda2e215ab6974a6ab8fbf135a3c833d2dfefb6a0`.
The existing signed-bound fixture also stayed green:

```text
uv run --no-sync python tools/dectest.py \
  28_euler_ode:gcc:O0:euler_decay_q16 --show
SCOPED: 1 lane of 838 (0%) -- no regressions in scope
```

The test census records this increment's one new Rust IR test (`total_declared`
`5349 -> 5350`, `ir` `2615 -> 2616`). The live generator also saw 24 tests in
another lane's uncommitted shared-worktree edits, so its aggregate output was
not committed. No broad Rust, Python, fixture, DecBench, or Joern suite ran.

## Scope

This closes the high-variable positive-value analysis's dependence on legacy
parameter spelling. It does not migrate the standalone renderer/const-fold
compatibility APIs, declaration planning, or the remaining WP3 invalidation and
origin work.
