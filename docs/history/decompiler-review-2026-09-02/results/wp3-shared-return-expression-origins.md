# WP3 shared return expression origins

> **Kind:** result · **Date:** 2026-09-08

Commit `de7c13d1` makes exhaustive branch-return recovery transparent to an
origin carrier on the shared return expression.  The pass now finds the root
result register through an attributed register/cast template, and each
synthesized arm return retains the template's exact expression origins.

The focused regression was observed RED first: an attributed shared result
register left the exhaustive `if` plus trailing return unfolded.  Validation
was confined to the owning module:

```text
cargo test --features python-ext --lib \
  ir::ast::return_folds::tests::attributed_exhaustive_if_recognizes_return_expression_carrier \
  -- --exact
1 passed; 0 failed; 4,380 filtered out

cargo test --features python-ext --lib ir::ast::return_folds::tests::
9 passed; 0 failed; 4,372 filtered out
```

No full Rust, Python, fixture, DecBench, or Joern sweep was run for this bounded
WP3 increment.
