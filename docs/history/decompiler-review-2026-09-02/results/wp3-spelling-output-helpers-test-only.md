# WP3: spelling-only output helpers are test-only

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `feb3a9ab` removes four legacy spelling-authority implementations from
non-test builds:

- `materialize_direct_output`;
- `prune_unread_promoted_locals`;
- `prune_void_entry_result_restores`; and
- `remove_redundant_return_constant_assignments`.

A repository-wide caller audit found each production preparation branch uses
its `ValueIdentities` form. Every remaining bare call is inside the
`#[cfg(test)]` compatibility scheduler or a unit-test module. The functions
and the redundant-return re-export therefore now compile only for tests.

This does not delete the compatibility contracts: they still characterize the
old spelling behavior in unit tests. It makes that authority unavailable to a
shipped library build and keeps future product code from selecting it by
accident.

## Focused evidence

Before the change, `cargo check --features python-ext --lib` reported all four
functions as unused in the non-test crate. After the change, the check exits
zero and none of those four dead-code warnings appears.

```text
cargo test -q --features python-ext --lib ir::direct_output::tests::
24 passed; 0 failed

cargo test -q --features python-ext --lib ir::ast::return_folds::tests::
14 passed; 0 failed

cargo test -q --features python-ext --lib ir::ast::prepare::fixpoint_tests::
4 passed; 0 failed
```

No fixture, DecBench, Joern, GED, or performance run was used because product
behavior is intentionally unchanged. The required post-source-commit Python
gate ran in fail-fast mode and again reached 11% before its first ordinary
failure:

```text
uv run pytest python/tests/ -q -x
stopped at 11%: 1 failed
```

The failure is the established
`test_real_thumb_leaf_frame_save_does_not_become_a_source_local` defect with
the same `*(int *)((&local_18[0] + 20)) = var0;` output. It is not on a changed
product path, but the whole gate remains red and incomplete.

The identity-free public `lower` compatibility entry point is a separate
boundary: it still has example, integration-test, and internal diagnostic
callers that must be migrated or deliberately retained before it can become
test-only.
