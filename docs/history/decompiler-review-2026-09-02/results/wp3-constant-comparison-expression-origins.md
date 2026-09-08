# WP3 constant-comparison expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `e2df3e60` makes constant-comparison folding transparent to expression
origin carriers. Two attributed constants now produce the same boolean
constant as their unattributed forms, and the result retains the deterministic
union of the enclosing comparison and both operands. Signed and unsigned
comparison semantics are unchanged.

This is one bounded constant-fold migration, not completion of WP3.

## Focused verification

The three-owner signed comparison test was observed red first because operand
carriers blocked the constant matcher. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_constant_comparison_folds_and_unions_origins \
  -- --exact
1 passed; 0 failed; 4,370 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
69 passed; 0 failed; 4,302 filtered out; 0.02 s
```

Filtered tests were not executed. The touched-module run includes the existing
signed/unsigned comparison controls and checked-in real-binary control. No
full Rust, Python, fixture, architecture, DecBench, or Joern suite was run.
