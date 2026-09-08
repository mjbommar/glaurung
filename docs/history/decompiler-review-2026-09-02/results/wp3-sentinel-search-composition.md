# WP3 sentinel-search origin composition

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `fa8b0656` makes coalesced sentinel-search loop recovery compose the
owners of all four semantically equal sentinel occurrences consumed by the
rewrite: the entry comparison, entry return, loop-exit comparison, and
loop-exit return. The reconstructed `while` bound and final return retain the
same deterministic union instead of silently keeping only one contributor.

The sentinels must still agree semantically, and the existing stable-value,
seed, carried-register, exit-shape, and effect refusals remain mandatory. This
is a bounded WP3/WP4 migration, not completion of either package.

## Focused verification

The coalesced sentinel fixture now gives each of its four zero constants a
different instruction owner and requires their complete union on both
reconstructed uses. It was observed red first because only one owner survived.
After repair:

```text
cargo test --features python-ext --lib \
  ir::loop_form::tests::coalesced_sentinel_result_rotates_to_a_null_guarded_loop \
  -- --exact
1 passed; 0 failed; 4,377 filtered out; 0.00 s

cargo test --features python-ext --lib 'ir::loop_form::tests::'
30 passed; 0 failed; 4,348 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
