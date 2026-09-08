# WP3 switch-entry copy identities

Commit `7ea07705` gives late switch-entry copy propagation an identity-aware
production entry point and keeps the same authority for the whole pass
transaction.

This pass carries a dominating straight-line alias into newly recovered switch
arms. Previously recursive arm substitution called the store-lvalue boundary
without identities, then its cleanup deleted dead copies without identities.
An opaque promoted stack object copied through a scratch could therefore turn
an indirect case-arm store into a bare stack assignment.

The prepare pipeline now supplies `ValueIdentities`; recursive branches,
switches, and nested discovery retain it, store-address substitution uses it,
and the following dead-copy fixpoint uses the same sidecar. Exact promoted
ownership preserves lvalue category. Missing or ambiguous production identity
fails closed, while the identity-free wrapper retains legacy behavior for
compatibility callers.

Focused validation on the debug Rust build and rebuilt Python extension:

```text
cargo test --features python-ext --lib ir::copy_prop::switch_entry::tests::identity_aware_switch_store_preserves_opaque_stack_lvalue_boundary -- --exact
1 passed; 4643 filtered out

cargo test --features python-ext --lib ir::copy_prop::switch_entry::tests:: -- --test-threads=4
4 passed; 4640 filtered out

cargo test --features python-ext --lib ir::copy_prop:: -- --test-threads=4
75 passed; 4569 filtered out; test execution 0.01s

uv run maturin develop
success

uv run pytest python/tests/test_decompiler_control_flow_semantics.py::test_gcc_o0_state_dispatch_recovers_switch_and_round_trips -q
1 passed
```

This closes the switch-entry portion of the current WP3 copy consumer audit. It
does not complete the planned pre-AST SSA implementation, universal
invalidation, or expression-origin coverage. The compiled switch fixture
directly covers the changed path, so the four-cell Hello matrix was not repeated
for this storage-role migration.
