# WP3 guarded-sentinel origin composition

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `9523e980` makes guarded `do/while` rotation compare the entry and latch
sentinels by semantic value when their origin carriers differ. The recovered
pre-tested `while` bound receives the deterministic union of both instruction
owners instead of either blocking rotation or retaining only one contributor.

The sentinel values must still agree, and all entry-result, stable-prelude,
carried-latch, zero-iteration, and trailing-control proofs remain mandatory.
This is a bounded WP3/WP4 migration, not completion of either package.

## Focused verification

The guarded-loop fixture now uses distinct owners for its entry and latch null
sentinels and requires both on the reconstructed bound. It was observed red
first because carrier-sensitive equality left six statements instead of five.
After repair:

```text
cargo test --features python-ext --lib \
  ir::loop_form::tests::guarded_do_while_rotates_back_to_pre_tested_while \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::loop_form::tests::'
30 passed; 0 failed; 4,348 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
