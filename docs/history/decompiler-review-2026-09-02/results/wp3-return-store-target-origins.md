# WP3 return store target origins

> **Kind:** result · **Date:** 2026-09-08

Commit `08f0f858` makes exhaustive branch-return recovery recognize an origin
carrier around a promoted result-slot store target. When that store becomes a
direct return, the consumed target-expression owner is retained on the returned
value alongside the store's existing value provenance.

The focused test was observed RED first: attributed `local_0` targets left the
exhaustive `if` and its shared return unfolded. Validation remained within the
owning module:

```text
cargo test --features python-ext --lib \
  ir::ast::return_folds::tests::attributed_exhaustive_if_recognizes_promoted_store_target_carriers \
  -- --exact
1 passed; 0 failed; 4,381 filtered out

cargo test --features python-ext --lib ir::ast::return_folds::tests::
10 passed; 0 failed; 4,372 filtered out
```

No full Rust, Python, fixture, DecBench, or Joern sweep was run for this bounded
WP3 increment.
