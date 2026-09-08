# WP3 eager-boolean expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `66e533d7` makes safe eager SETcc boolean-tree recovery recursively
transparent to expression-origin carriers. An attributed byte-view tree that
feeds `!= 0` now recovers readable `&&`/`||` control while retaining terminal,
cast, tree, and individual predicate-leaf origins at their surviving nodes.

The byte-view requirement, two-leaf minimum, short-circuit safety proof, and
memory/effect refusal are unchanged. This is one bounded constant-fold
migration, not completion of WP3.

## Focused verification

The five-owner test was observed red first because the recursive recognizer
had no origin-carrier case and left the eager flag tree untouched. After
repair:

```text
cargo test --features python-ext \
  ir::const_fold::tests::attributed_eager_boolean_tree_recovers_logical_origins \
  -- --exact
1 passed; 0 failed; 4,367 filtered out

cargo test --features python-ext 'ir::const_fold::tests::'
66 passed; 0 failed; 4,302 filtered out
```

The touched-module run includes the memory-read/effect refusal and checked-in
real-binary end-to-end test. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
