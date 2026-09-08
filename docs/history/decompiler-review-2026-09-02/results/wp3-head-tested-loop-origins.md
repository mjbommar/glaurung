# WP3 head-tested loop origin composition

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `eb414739` makes exact head-tested-loop recovery recognize an attributed
semantic `while (1)` condition. Its owner is composed with the attributed exit
predicate owner on the reconstructed loop condition after the predicate is
inverted.

The guard must still be the first statement with an exact single `break` arm;
no statement motion or broader control-flow speculation is enabled. This is a
bounded WP3/WP4 migration, not completion of either package.

## Focused verification

The exit-value/head-test fixture now attributes its constant loop condition and
exit predicate independently and requires their complete union on the
reconstructed condition. It was observed red first because the attributed
constant blocked both seeding and head-test recovery. After repair:

```text
cargo test --features python-ext --lib \
  ir::loop_form::tests::exit_value_copy_is_seeded_before_a_head_tested_loop \
  -- --exact
1 passed; 0 failed; 4,377 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::loop_form::tests::'
30 passed; 0 failed; 4,348 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
