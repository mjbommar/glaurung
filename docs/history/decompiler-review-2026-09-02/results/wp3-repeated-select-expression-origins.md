# WP3 repeated-select expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `3b1f34ca` makes repeated-condition select collapse compare semantic
predicates rather than provenance-bearing syntax. Attributed
`c ? (c ? yes : prior) : no` and its dual now discard the unreachable prior
value while preserving the outer select and the removed inner select/condition
origins on the replacement. The unreachable arm's owner is excluded.

The repeatable-condition and effect-safety refusal rules are unchanged. This
is one bounded constant-fold migration, not completion of WP3.

## Focused verification

The attributed test was observed red before repair because distinct origin
carriers made the two predicates compare unequal. After repair:

```text
cargo test --features python-ext \
  ir::const_fold::tests::attributed_repeated_select_unions_removed_control_origins \
  -- --exact
1 passed; 0 failed; 4,365 filtered out

cargo test --features python-ext 'ir::const_fold::tests::'
64 passed; 0 failed; 4,302 filtered out
```

The module run includes the effectful-condition refusal and checked-in
real-binary end-to-end test. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
