# WP3 copy self-reference origins

> **Kind:** result · **Date:** 2026-09-08

Commit `be69b02b` makes copy propagation's self-reference predicate compare the
semantic expression beneath an origin carrier. An attributed `x = x` is no
longer recorded as a useful alias by ordinary propagation, switch-entry
propagation, or dead-copy handling.

The direct invariant was observed RED first. Validation remained within the
copy-propagation module:

```text
cargo test --features python-ext --lib \
  ir::copy_prop::env::tests::attributed_self_copy_is_still_a_self_reference \
  -- --exact
1 passed; 0 failed; 4,383 filtered out

cargo test --features python-ext --lib ir::copy_prop::
54 passed; 0 failed; 4,330 filtered out
```

No full Rust, Python, fixture, DecBench, or Joern sweep was run for this bounded
WP3 increment.
