# WP3 ABI-width identity consumer

Commit `ee65638e` migrates prepared-AST definition-width refinement from the
presentation-only `varN` convention to the role-projected opaque SSA identity
sidecar.

The production declaration and width maps now use the identity-aware entry
point. A value with one exact identity may be widened from its exact
per-value width evidence even when its displayed role has an opaque name. A
role representing multiple SSA candidates declines the refinement and keeps
its prior type. Existing `varN` behavior remains available during incremental
consumer migration.

Focused validation:

```text
ir::ast::abi_widths::identity_tests::exact_opaque_identity_authorizes_definition_width_refinement
1 passed; 4,398 filtered out

ir::ast::abi_widths::identity_tests::ambiguous_opaque_identity_declines_definition_width_refinement
1 passed; 4,398 filtered out

cargo test --features python-ext --lib ir::ast::tests::decbench_abi
7 passed; 4,392 filtered out

ir::ast::tests::a_wide_scalar_definition_widens_a_coalesced_local_declaration
1 passed; 4,398 filtered out

ir::ast::tests::a_narrow_definition_does_not_inherit_a_wide_source_register_hint
1 passed; 4,398 filtered out
```

This is a bounded WP3 consumer migration. It does not replace the legacy
eligibility path, establish full invalidation coverage, or complete WP6's
constraint-based type solver.
