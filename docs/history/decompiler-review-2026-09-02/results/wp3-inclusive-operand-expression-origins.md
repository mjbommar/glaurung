# WP3 inclusive-comparison operand origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `321d205b` makes inclusive-comparison recovery compare attributed
operands by semantic value instead of by carrier identity. Equivalent
`(x == y) | (x < y)` inputs now recover `x <= y` even when the equality and
strict-less instructions give each occurrence a distinct origin. Each
surviving operand receives the exact union of its two contributing owners;
the comparison retains its equality/less owner union.

Operand value, ordering, and signedness must still agree, so the switch-range
provenance guard remains unchanged. This is one bounded wildcard-consumer
migration, not completion of WP3.

## Focused verification

The strengthened inclusive-relation test was observed red first because raw
operand equality treated different carriers as different values. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_equality_or_less_merges_and_unions_origins \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
76 passed; 0 failed; 4,302 filtered out; 0.01 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
