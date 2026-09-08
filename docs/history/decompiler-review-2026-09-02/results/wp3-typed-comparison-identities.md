# WP3 typed-comparison identity consumer

Commit `49a78f31` migrates signed relational-comparison extension cleanup from
presentation-name heuristics to the pipeline-owned opaque SSA identity sidecar.

The production renderer now supplies the sidecar to this pass. Two equally
extended opaque operands collapse to their declared source-width values only
when both roles have one exact SSA identity and matching recovered integer
types. If either role is ambiguous, the comparison retains both explicit
machine-width extensions. Compatibility callers without a sidecar preserve
their prior behavior, and equality comparisons keep their existing
expression-oriented rule.

The two new tests were observed red before the identity-aware entry point
existed. Focused validation after implementation:

```text
exact_opaque_identities_remove_matching_comparison_extensions
1 passed; 4,407 filtered out

ambiguous_opaque_identity_keeps_comparison_extensions
1 passed; 4,407 filtered out

equal_sign_extensions_fold_only_with_matching_declared_types
1 passed; 4,407 filtered out

typed_comparison_views_preserve_cast_and_source_origins
1 passed; 4,407 filtered out

equal_zero_extensions_keep_the_source_width_without_a_wide_compare
1 passed; 4,407 filtered out
```

Each case used `cargo test --features python-ext --lib
ir::const_fold::tests::<name> -- --exact`. No broad Rust, Python, fixture,
DecBench, or Joern suite was run. This is another bounded WP3 consumer
migration, not WP3 completion. Contextual widening and typed consumed-extension
cleanup remain name-based consumers.
