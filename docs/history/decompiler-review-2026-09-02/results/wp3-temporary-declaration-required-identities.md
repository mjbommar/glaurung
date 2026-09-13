# WP3 temporary declarations require identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `b16ba838` removes the last `varN` spelling authority from the shared
declared-integer-type query when the pipeline-owned identity sidecar is
installed. Constant folding, typed simplification, widening, and high-variable
analysis can use a narrow or unsigned temporary declaration only when the
sidecar proves its physical storage, parameter slot, or promoted stack object.
An unowned value now remains the conservative signed machine-word type even if
its display name looks like a generated temporary.

The unused `declared_int_type` no-sidecar wrapper was deleted. Explicit callers
must now select `declared_int_type_with_identities`, making the compatibility
choice visible at the call site.

## Red and green evidence

The new contract was observed red against the old condition:

```text
declared_integer_temporaries_require_identity_when_sidecar_is_installed
left:  Some((false, 4))
right: Some((true, 8))
```

After the repair, the focused direct-consumer modules passed:

```text
ir::ast::return_ctype::tests:  9 passed, 0 failed
ir::high_variables::tests:    38 passed, 0 failed
ir::const_fold::tests:        82 passed, 0 failed
ir::typed_simplify::tests:     7 passed, 0 failed
ir::widen::tests:             25 passed, 0 failed
```

A fresh release build completed and `tools/build_guard.py` reported `fresh`
with native SHA-256
`507ab31742248478126d8107f9bc0ff04fc4f30e87b590a4f03298992387f073`.
The directly relevant real-binary control also remained green:

```text
uv run --no-sync python tools/dectest.py \
  28_euler_ode:gcc:O0:euler_decay_q16 --show
SCOPED: 1 lane of 838 (0%) -- no regressions in scope
```

The census advances by the one owned Rust test (`total_declared` 5,351 to
5,352; `ir` 2,617 to 2,618). Other source edits in the shared worktree were not
staged. No broad Rust, Python, fixture, DecBench, or Joern suite ran for this
bounded increment.

## Scope

This closes one declaration/type-semantic consumer of generated temporary
spelling. It does not complete the remaining WP3 semantic-reader audit,
universal origin attribution, or removal of `tag_phys` inside value numbering.
