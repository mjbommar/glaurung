# WP3 adjacent overwritten-value identities

Commit `1290c291` gives adjacent consumed-and-overwritten value folding an
identity-aware production entry point. This pass recognizes shapes such as
`result = predicate; result = table[result]` and substitutes the first value
into the second assignment without pretending the physical result role is
globally SSA.

Previously the candidate destination was classified from `local_*` and
`stack_*` spelling. An opaque promoted stack object could therefore be deleted
as though it were a disposable physical scratch. The production prepare
pipeline now supplies `ValueIdentities`, threaded through branches, loops,
switches, and exception bodies. Exact promoted ownership refuses the rewrite;
missing or ambiguous identity fails closed. The identity-free wrapper retains
legacy behavior for compatibility callers.

Focused validation on the debug Rust build and rebuilt Python extension:

```text
cargo test --features python-ext --lib ir::copy_prop::adjacent::tests::identity_aware_overwrite_fold_rejects_opaque_stack_destination -- --exact
1 passed; 4640 filtered out

cargo test --features python-ext --lib ir::copy_prop:: -- --test-threads=4
72 passed; 4569 filtered out; test execution 0.01s

uv run maturin develop
success

uv run pytest python/tests/test_flag_predicate_roundtrip.py::test_gcc_o2_loop_flags_round_trip -q
1 passed; two compiled functions round-tripped
```

This advances WP3's production consumer migration. It does not complete
pre-AST SSA migration, identity-aware read accounting, universal invalidation,
or expression-origin coverage. The compiled optimized predicate fixture
directly covers the affected output path, so the four-cell Hello matrix was not
repeated for this storage-role-only increment.
