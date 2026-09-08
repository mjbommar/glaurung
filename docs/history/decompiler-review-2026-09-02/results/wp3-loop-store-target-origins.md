# WP3 loop store-target origin transparency

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `1bc1f57f` makes counted-loop promotion recognize attributed stack-local
address expressions as the initializer and step target. Both original stores
are copied unchanged into the reconstructed `for`, so their address owners
survive without transfer.

The target must still be an exact `local_` or `stack_` register and the same
induction variable must own the initializer, condition, and unit step. Existing
iterator-bypass refusals remain mandatory. This is a bounded WP3/WP4 migration,
not completion of either package.

## Focused verification

The switch-and-early-return counted-loop fixture now gives the initializer and
step address expressions distinct owners and requires the exact stores in the
reconstructed `for`. It was observed red first because the carriers hid both
store targets. After repair:

```text
cargo test --features python-ext --lib \
  ir::loop_form::tests::promotes_counted_loop_with_switch_and_early_return \
  -- --exact
1 passed; 0 failed; 4,377 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::loop_form::tests::'
30 passed; 0 failed; 4,348 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
