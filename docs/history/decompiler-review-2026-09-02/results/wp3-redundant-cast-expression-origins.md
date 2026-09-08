# WP3 redundant-cast expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `c79f57db` makes redundant literal and exact-boolean cast removal
transparent to expression origin carriers. The replacement keeps the inner
value owner and the enclosing cast owner. The special refusal for a widened
literal used as a shift's left operand is unchanged, preserving the width that
defines C shift semantics.

This is one bounded constant-fold migration, not completion of WP3.

## Focused verification

The two-owner literal-cast test was observed red first because the inner
carrier blocked the matcher. After repair:

```text
cargo test --features python-ext --lib \
  ir::const_fold::tests::attributed_redundant_literal_cast_unions_cast_and_value_origins \
  -- --exact
1 passed; 0 failed; 4,373 filtered out

cargo test --features python-ext --lib 'ir::const_fold::tests::'
72 passed; 0 failed; 4,302 filtered out; 0.01 s
```

Filtered tests were not executed. The touched-module run includes the existing
shift-left refusal, cast, origin, and checked-in real-binary controls. No full
Rust, Python, fixture, architecture, DecBench, or Joern suite was run.
