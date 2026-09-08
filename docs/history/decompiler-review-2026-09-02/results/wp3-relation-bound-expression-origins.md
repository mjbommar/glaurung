# WP3 relation-bound expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `8f499b04` makes terminal mixed-view relation recovery transparent to
origin carriers on its repeated constant bound. Attributed constants from the
unsigned equality and signed strict-less contributors are compared by semantic
value; the bound in the recovered readable `K < signed(x)` relation retains
their exact origin union.

The constants must still agree and be non-negative and signed-representable at
the proven source width. This is one bounded wildcard-consumer migration, not
completion of WP3.

## Focused verification

The strengthened terminal-relation test was observed red first because the raw
constant matcher could not see through either carrier. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_terminal_mixed_view_relation_unions_consumed_origins \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
76 passed; 0 failed; 4,302 filtered out; 0.02 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
