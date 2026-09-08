# WP3 adjacent guard-value identities

Commit `2b29137a` gives adjacent eager-guard propagation an identity-aware
production entry point. This pass folds a physical scratch's sole immediately
adjacent use into an `if` condition so later loop recovery sees the original
predicate or load.

Previously the scratch decision was based on `local_*` and `stack_*` spelling.
An opaque promoted stack object could therefore be deleted and treated as an
SSA-like scratch. The production prepare pipeline now supplies
`ValueIdentities` at both invocations, and the identity authority is threaded
through nested branches, loops, and switches. Exact promoted ownership refuses
the rewrite; missing or ambiguous identity fails closed. The identity-free
wrapper retains legacy behavior for compatibility callers.

Focused validation on the debug Rust build and rebuilt Python extension:

```text
cargo test --features python-ext --lib ir::copy_prop::adjacent::tests::identity_aware_guard_fold_rejects_opaque_stack_destination -- --exact
1 passed; 4639 filtered out

cargo test --features python-ext --lib ir::copy_prop:: -- --test-threads=4
71 passed; 4569 filtered out; test execution 0.01s

uv run maturin develop
success

uv run pytest python/tests/test_effectful_loop_rotation.py -q
1 passed
```

This closes one more WP3 copy-propagation consumer seam. It does not complete
pre-AST SSA migration, identity-aware read accounting, universal invalidation,
or expression-origin coverage. The four-cell Hello matrix was not repeated:
the compiled effectful-loop fixture directly exercises the changed guard and
loop-recovery path.
