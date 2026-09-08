# WP3 late return expression origins

> **Kind:** result · **Date:** 2026-09-08

Commit `5b8909b3` makes the late redundant-return cleanup transparent to
expression origin carriers.  An attributed constant assignment immediately
before an identically attributed constant return is now recognized by semantic
value, and deleting the assignment transfers both its statement owner and its
constant-expression owner to the surviving return statement and expression.
The existing mismatched-constant refusal is unchanged.

The focused regression was observed RED before the implementation: the pass
left both statements because its direct `Expr::Const` pattern did not see
through `Expr::Origin`.

Validation used only the affected Rust module:

```text
cargo test --features python-ext --lib \
  ir::ast::return_folds::tests::attributed_late_return_cleanup_recognizes_expression_carriers \
  -- --exact
1 passed; 0 failed; 4,379 filtered out

cargo test --features python-ext --lib ir::ast::return_folds::tests::
8 passed; 0 failed; 4,372 filtered out
```

No full Rust, Python, fixture, DecBench, or Joern sweep was run for this bounded
WP3 increment.
