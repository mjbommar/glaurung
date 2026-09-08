# WP3 counted-loop step origin transparency

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `2fac94e2` makes counted-loop promotion recognize an attributed unit
increment, including independently attributed addition, induction-variable,
and constant nodes. The original step is copied unchanged into the
reconstructed `for`, so every owner survives without an additional transfer.

The step must still be an exact unit addition for the same induction variable,
and width-changing cast and iterator-bypass proofs remain mandatory. This is a
bounded WP3/WP4 migration, not completion of either package.

## Focused verification

The guarded counted-loop fixture now attributes the complete increment tree
and requires the exact attributed step in the reconstructed `for`. It was
observed red first because the carrier hid the addition from shape recognition.
After repair:

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
