# WP3 latch-predicate expression-origin composition

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `ab046385` makes latch-predicate folding recognize attributed predicate
registers and attributed saved-value copies. The replacement predicate retains
its original expression owner and receives the consumed latch-register owner;
the saved-value assignment remains intact with its own owner.

The proof still requires one straight-line snapshot, one predicate definition,
the exact final carried-value update, and no intervening writes or control-flow
bypass. This is a bounded WP3/WP4 migration, not completion of either package.

## Focused verification

The existing latch-fold fixture now independently attributes the saved-value
copy, predicate expression, predicate statement, and consumed latch condition.
It was observed red first because the attributed predicate left four loop-body
statements instead of removing its assignment. After repair:

```text
cargo test --features python-ext --lib \
  ir::latch_predicate::tests::folds_predicate_across_final_carried_value_assignment \
  -- --exact
1 passed; 0 failed; 4,377 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::latch_predicate::tests::'
12 passed; 0 failed; 4,366 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
