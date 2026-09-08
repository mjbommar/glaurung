# WP3 copy store read counts

> **Kind:** result · **Date:** 2026-09-08

Commit `13b1143a` makes copy propagation's shared read walker classify an
origin-wrapped promoted-local store target as a destination, not a pointer
read. Whole-function use counts therefore remain identical to the unwrapped
semantic AST, allowing valid single-use folds instead of retaining artificial
temporaries.

The count regression was observed RED first: the attributed destination added
one false read of `local_0`. Validation remained within copy propagation:

```text
cargo test --features python-ext --lib \
  ir::copy_prop::tests::attributed_promoted_store_target_is_not_counted_as_a_read \
  -- --exact
1 passed; 0 failed; 4,386 filtered out

cargo test --features python-ext --lib ir::copy_prop::
57 passed; 0 failed; 4,330 filtered out
```

No full Rust, Python, fixture, DecBench, or Joern sweep was run for this bounded
WP3 increment.
