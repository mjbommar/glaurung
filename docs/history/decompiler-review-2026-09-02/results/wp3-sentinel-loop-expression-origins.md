# WP3 sentinel-loop expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `bfeb4974` makes sentinel-search loop recovery transparent to expression-
origin carriers on the sentinel and equality operands. An attributed null
sentinel no longer leaves the six-statement rotated machine form; the pass
recovers the three-statement source-like initialization, guarded `while`, and
final sentinel return.

The sentinel owner remains attached to both the recovered loop condition and
the final return. Stable-value, seed-count, carried-register, exit-shape, and
effect refusal rules remain unchanged. This is a bounded WP3/WP4 migration, not
completion of either package.

## Focused verification

The exact sentinel-search fixture now attributes every cloned null sentinel and
requires that owner in both reconstructed uses. It was observed red first
because the raw constant matcher left all six original statements. After
repair:

```text
cargo test --features python-ext --lib \
  ir::loop_form::tests::exact_sentinel_search_rotates_to_a_null_guarded_loop \
  -- --exact
1 passed; 0 failed; 4,377 filtered out

cargo test --features python-ext --lib 'ir::loop_form::tests::'
30 passed; 0 failed; 4,348 filtered out; 0.00 s
```

Filtered tests were not executed. No full Rust, Python, fixture, architecture,
DecBench, or Joern suite was run.
