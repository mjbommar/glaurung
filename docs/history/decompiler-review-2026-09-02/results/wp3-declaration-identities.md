# WP3 declaration-plan identity consumer

Commit `48cf15a0` carries the role-projected opaque SSA identity sidecar into
the immutable declaration plan that decides the C types emitted by the final
renderer.

Compatibility render entry points remain unchanged and supply no identity
sidecar. The pipeline-owned deepest renderer supplies the sidecar explicitly.
For a local with recovered type evidence, one exact identity makes the local
eligible for that recovered declaration independently of a `varN` spelling.
Multiple identity candidates fail closed and retain the conservative `long`
declaration. Existing source-local and `varN` behavior remains intact.

Focused validation:

```text
cargo test --features python-ext --lib ir::ast::declaration_plan::identity_tests::
4 passed; 4,399 filtered out

ir::high_variables::tests::pointer_copy_into_conflicted_word_keeps_explicit_machine_cast
1 passed; 4,402 filtered out

ir::ast::tests::decbench_pointer_assignment_casts_a_pointer_fact_with_integer_declaration
1 passed; 4,402 filtered out
```

The identity tests prove both the semantic eligibility decision and its final
`char *` versus `long` local declaration. This remains a bounded WP3 consumer
migration, not completion of all declaration/type identity paths or WP6.
