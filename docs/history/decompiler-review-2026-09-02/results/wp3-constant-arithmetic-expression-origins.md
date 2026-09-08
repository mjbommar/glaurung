# WP3 constant-arithmetic expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `14eef6d2` makes safe constant arithmetic transparent to expression
origin carriers. Two attributed constants now fold to the same constant as
their unattributed forms, and the result retains the deterministic union of
the enclosing operation and both operands. Existing division-by-zero and
invalid-shift refusals are unchanged.

This is one bounded constant-fold migration, not completion of WP3.

## Focused verification

The three-owner multiplication test was observed red first because the operand
carriers blocked the constant matcher. After repair:

```text
cargo test --features python-ext \
  ir::const_fold::tests::attributed_constant_arithmetic_folds_and_unions_origins \
  -- --exact
1 passed; 0 failed; 4,369 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
68 passed; 0 failed; 4,302 filtered out; 0.01 s
```

Filtered tests were not executed. The touched-module run includes the existing
constant-fold refusals and checked-in real-binary control. No full Rust,
Python, fixture, architecture, DecBench, or Joern suite was run.
