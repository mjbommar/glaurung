# WP3 attributed typed promoted-value folding

Commit `0e7aa4bb` makes the existing typed promoted-value width proof
transparent to `Expr::Origin`. A width-proven attributed comparison stored to a
one-use promoted local now folds directly into its return instead of leaving an
artificial temporary in the rendered C. The comparison keeps its exact source
owner.

The change does not infer a new width: it applies the existing constant,
comparison, select, or cast proof to the semantic expression. Wider values and
unproved expressions retain the existing fail-closed behavior.

## Focused evidence

The end-to-end regression was observed red before the production change: the
attributed comparison remained as a store followed by a return of the local.

```text
cargo test --features python-ext --lib \
  ir::copy_prop::adjacent::tests::attributed_typed_scalar_promoted_store_folds_into_return \
  -- --exact

1 passed; 0 failed; 4,389 filtered out; test body 0.00s
```

The complete touched submodule then passed:

```text
cargo test --features python-ext --lib ir::copy_prop::adjacent::

20 passed; 0 failed; 4,370 filtered out; test bodies 0.00s
```

No fixture matrix, full Rust/Python suite, DecBench, or Joern run was used for
this bounded increment.
