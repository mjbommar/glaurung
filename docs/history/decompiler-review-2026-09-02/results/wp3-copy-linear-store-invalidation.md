# WP3 copy linear-store invalidation

> **Kind:** result · **Date:** 2026-09-08

Commit `82d7f3db` makes both linear copy-propagation walkers invalidate aliases
when a register store target is wrapped in expression provenance. This prevents
an entry snapshot from being rewritten to the post-store value of its source.

The end-to-end AST test was observed RED first: `var0 = local_0; local_0 = 1;
return var0;` incorrectly became a return of `local_0` when only the store
target carried an origin. The corrected pass retains `var0` as the pre-write
snapshot.

```text
cargo test --features python-ext --lib \
  ir::copy_prop::tests::attributed_store_target_invalidates_an_earlier_snapshot \
  -- --exact
1 passed; 0 failed; 4,384 filtered out

cargo test --features python-ext --lib ir::copy_prop::
55 passed; 0 failed; 4,330 filtered out
```

No full Rust, Python, fixture, DecBench, or Joern sweep was run for this bounded
WP3 increment.
