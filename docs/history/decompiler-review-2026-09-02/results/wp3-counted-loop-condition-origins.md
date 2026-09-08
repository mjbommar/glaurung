# WP3 counted-loop condition origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `82deec7a` makes guarded counted-loop promotion recognize an attributed
semantic `while (1)` condition. The owner of that consumed condition moves to
the reconstructed `for` statement, while the attributed exit predicate is
inverted semantically and retains its owner on the reconstructed `for`
condition.

The adjacent initializer, exact break guard, same induction variable, unit
increment, and iterator-bypass refusals remain mandatory. This is a bounded
WP3/WP4 migration, not completion of either package.

## Focused verification

The guarded counted-loop fixture now attributes both its constant loop
condition and exit predicate, and requires both owners at their surviving
boundaries. It was observed red first because the attributed constant prevented
promotion. After repair:

```text
cargo test --features python-ext --lib \
  ir::loop_form::tests::promotes_a_guarded_counted_loop_with_adjacent_initializer \
  -- --exact
1 passed; 0 failed; 4,377 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::loop_form::tests::'
30 passed; 0 failed; 4,348 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
