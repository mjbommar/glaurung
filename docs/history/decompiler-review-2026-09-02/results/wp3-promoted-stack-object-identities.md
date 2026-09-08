# WP3 promoted stack-object identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `c591c7e5` removes one more production dependency on presentation names.
Stack promotion now publishes the exact storage objects it minted through the
pipeline-owned `ValueIdentities` sidecar. Final cleanup uses that ownership to
remove pure writes to unread machine bookkeeping, rather than treating every
name beginning with `local_` or `stack_` as a promoted stack object.

The legacy predicate remains only behind the explicit no-sidecar compatibility
entry point. With the authoritative sidecar installed, missing ownership fails
closed: a coincidentally named `local_4` is retained.

## Focused validation

Only tests owned by this change were run:

```text
cargo test --features python-ext --lib \
  ir::direct_output::tests::unread_opaque_stack_object_is_removed_by_typed_ownership \
  -- --exact --nocapture
1 passed; 4,589 filtered out

cargo test --features python-ext --lib \
  ir::direct_output::tests::an_unowned_local_spelling_is_not_treated_as_stack_storage \
  -- --exact --nocapture
1 passed; 4,589 filtered out

cargo test --features python-ext --lib ir::direct_output::tests:: -- --nocapture
18 passed; 4,572 filtered out

uv run pytest python/tests/test_test_census.py -q
6 passed
```

The regenerated census records 5,127 declared Rust tests and zero tests outside
every gate.

## Real-binary check

After `uv run maturin develop`, `tools/build_guard.py` reported the native
extension fresh with SHA-256
`4a681472b5030ddd6a2db271eb7ea519368c41b11630b2e7aee4268073b16c89`.
The repository's `link_configuration_shapes.c` was compiled as a real Clang O0
non-PIE executable, then only `main` was decompiled in DecBench-style C. It
retained the observable calls and return while emitting no invented promoted
return-slot local.

No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane ran.

## Remaining boundary

This closes one production name parser, not WP3. The no-sidecar compatibility
path still recognizes old promoted names, and the wider `tag_phys`, remaining
consumer, naming-as-render-map, and origin/mapping work remains ordered in the
plan.
