# WP3 typed-view identity consumer

Commit `05a524e8` migrates redundant unsigned machine-view cleanup from
presentation-name heuristics to the pipeline-owned opaque SSA identity sidecar.

The compatibility entry point retains its previous behavior when no sidecar is
available. The production DecBench renderer supplies the sidecar explicitly. An
opaque AST value receives its recovered integer declaration only when it maps to
one exact SSA identity; multiple candidate identities fail closed and preserve
the explicit cast. Existing argument, promoted-local, and `varN` behavior is
unchanged. Origin carriers on a removed view continue to be unioned onto the
surviving expression.

The two new tests were observed red before the identity-aware entry point
existed. Focused validation after implementation:

```text
cargo test --features python-ext --lib ir::const_fold::tests::exact_opaque_identity_removes_its_redundant_unsigned_view -- --exact
1 passed; 4,405 filtered out

cargo test --features python-ext --lib ir::const_fold::tests::ambiguous_opaque_identity_keeps_its_unsigned_view -- --exact
1 passed; 4,405 filtered out

cargo test --features python-ext --lib ir::const_fold::tests::exact_typed_register_view_is_removed_before_contextual_widening -- --exact
1 passed; 4,405 filtered out

cargo test --features python-ext --lib ir::const_fold::tests::narrow_fact_does_not_erase_a_machine_word_locals_comparison_view -- --exact
1 passed; 4,405 filtered out

cargo test --features python-ext --lib ir::const_fold::tests::attributed_typed_register_view_unions_both_cast_and_source_origins -- --exact
1 passed; 4,405 filtered out
```

No broad Rust, Python, fixture, DecBench, or Joern suite was run for this bounded
consumer migration. This closes one more name-based WP3 consumer; it does not
complete WP3. The adjacent typed-comparison and contextual-widening consumers
still require the same exact-or-ambiguous identity contract.
