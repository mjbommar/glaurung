# WP3 AST-native identity renames

Commit `3afd711a` establishes the first mutation-aware identity boundary inside
the prepared AST pipeline.

The loop-entry coalescer previously changed every occurrence of a dead seed into
its loop carrier while the immutable identity sidecar kept the old keys. The
pass now returns the exact `seed -> carrier` rename map. The renderer owns a
local identity snapshot, applies that map in the same pass transaction, removes
the dead key, and unions both candidate sets under the surviving carrier. A
refused rewrite returns an empty map and leaves identities unchanged.

The exact rename assertions were observed red before the pass returned a map
and before `ValueIdentities::apply_renames` was available to AST passes. Focused
validation after implementation:

```text
opaque_exact_identities_authorize_loop_entry_coalescing
1 passed; 4,418 filtered out

ambiguous_opaque_identity_keeps_loop_entry_copy
1 passed; 4,418 filtered out

coalesces_dead_source_identity_with_immediately_entered_loop_carrier
1 passed; 4,418 filtered out
```

Each case used `cargo test --features python-ext --lib
ir::latch_predicate::tests::<name> -- --exact`. No broad Rust, Python, fixture,
DecBench, or Joern suite was run. This is the first AST-native identity mutation
contract, not completion of every renaming/coalescing pass.
