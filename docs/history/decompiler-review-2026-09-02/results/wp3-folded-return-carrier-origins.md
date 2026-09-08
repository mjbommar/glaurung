# WP3 folded return carrier origins

> **Kind:** result · **Date:** 2026-09-08

Commit `767664db` makes the basic `result = E; return result;` fold recognize
an origin carrier around the returned result register. The deleted definition
owner and the consumed returned-register expression owner are deterministically
unioned on the surviving value; the return instruction remains statement-level
control provenance.

The strengthened existing provenance test was observed RED first because the
raw register pattern left both statements untouched. Validation was confined
to the owning module:

```text
cargo test --features python-ext --lib \
  ir::ast::return_folds::tests::attributed_return_fold_moves_definition_owner_to_returned_expression \
  -- --exact
1 passed; 0 failed; 4,380 filtered out

cargo test --features python-ext --lib ir::ast::return_folds::tests::
9 passed; 0 failed; 4,372 filtered out
```

No full Rust, Python, fixture, DecBench, or Joern sweep was run for this bounded
WP3 increment.
