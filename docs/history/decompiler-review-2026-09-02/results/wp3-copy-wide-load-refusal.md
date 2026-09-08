# WP3 copy wide-load refusal

> **Kind:** result · **Date:** 2026-09-08

Commit `de1cd148` makes counted copy propagation's wide-load and unknown-value
refusals inspect semantic expressions beneath origin carriers. A single-use
128-bit load remains materialized as its own value identity rather than being
substituted into a scalar expression context.

The public-pass regression was observed RED first: the attributed 16-byte
definition disappeared and the return directly contained the load. The fix
restores the existing width-safety rule without narrowing ordinary scalar
propagation.

```text
cargo test --features python-ext --lib \
  ir::copy_prop::tests::attributed_wide_load_is_not_scalarized_at_its_single_use \
  -- --exact
1 passed; 0 failed; 4,385 filtered out

cargo test --features python-ext --lib ir::copy_prop::
56 passed; 0 failed; 4,330 filtered out
```

No full Rust, Python, fixture, DecBench, or Joern sweep was run for this bounded
WP3 increment.
