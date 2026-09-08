# WP3 callee bank-return storage identities

Commit `858f8957` moves promoted-scalar classification in aggregate bank-return
composition from display spelling to pipeline-owned `ValueIdentities`.

For split INTEGER/SSE, SSE-pair, and AAPCS64 homogeneous-float returns, the
callee pass proves that every return reads one complete stack object. One real
O0 form first copies that object load through a promoted scalar represented as
a bare-register `Stmt::Store`. Previously `scan_returns` accepted the copy only
when its destination began with `local_*` or `stack_*`. That both missed an
opaque renamed object and trusted an unowned pointer store with suggestive
spelling.

`compose_bank_returns` remains as the identity-free compatibility API. The new
`compose_bank_returns_with_identities` carries one optional sidecar through the
whole recursive return scan, and the final production renderer calls it with
the identities it already owns. Exact promoted ownership admits the scalar
copy; absent ownership refuses it without partially rewriting the function.

Focused validation on the debug Rust build and a fresh rebuilt extension:

```text
cargo test --features python-ext --lib ir::callee_return_bank::tests::an_opaque_promoted_return_copy_is_composed_by_identity -- --exact --test-threads=1
1 passed; 4649 filtered out

cargo test --features python-ext --lib ir::callee_return_bank::tests::an_unowned_local_spelling_is_not_a_return_copy -- --exact --test-threads=1
1 passed; 4649 filtered out

cargo test --features python-ext --lib ir::callee_return_bank::tests:: -- --test-threads=4
23 passed; 4627 filtered out

uv run maturin develop
success

uv run python tools/build_guard.py
fresh

uv run python tools/dectest.py 197_homogeneous_float_aggregates:gcc:O0:hfa197_make_trio3f --show
1 scoped lane; no regressions
```

The two new adversarial contracts were not run against the old implementation
before patching, so this result does not label them observed-red. Their positive
and negative shapes directly encode the removed name dependency, and the
existing 23-test module retains all-or-nothing, size, second-bank, join, class,
and origin-preservation controls.

The isolated committed-tree census records 5,182 declared Rust tests, 2,477 in
IR, and zero outside every gate. This closes the stack-copy reader inside
callee bank composition; it does not complete WP3's remaining wildcard audit,
pre-AST SSA migration, or universal identity lifecycle.
