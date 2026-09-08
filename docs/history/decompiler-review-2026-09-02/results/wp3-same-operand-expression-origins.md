# WP3 same-operand expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `ff0ced1c` makes the same-operand algebraic family transparent to
expression origin carriers. Separately attributed copies of the same semantic
value now match for `x ^ x`, `x - x`, `x & x`, and `x | x`. Zero-producing
folds and value-preserving folds both retain the deterministic union of the
enclosing operation and the two operand owners.

This is one bounded constant-fold migration, not completion of WP3.

## Focused verification

The three-owner XOR test was observed red first because carrier identity hid
semantic equality. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_same_operand_identity_unions_both_owners \
  -- --exact
1 passed; 0 failed; 4,371 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
70 passed; 0 failed; 4,302 filtered out; 0.02 s
```

Filtered tests were not executed. The touched-module run includes existing
same-operand, origin, refusal, and checked-in real-binary controls. No full
Rust, Python, fixture, architecture, DecBench, or Joern suite was run.
