# WP3 AST-native identity renames

Commits `3afd711a` and `d8da5f13` establish the first two mutation-aware
identity boundaries inside the prepared AST pipeline.

The loop-entry coalescer previously changed every occurrence of a dead seed into
its loop carrier while the immutable identity sidecar kept the old keys. The
pass now returns the exact `seed -> carrier` rename map. The renderer owns a
local identity snapshot, applies that map in the same pass transaction, removes
the dead key, and unions both candidate sets under the surviving carrier. A
refused rewrite returns an empty map and leaves identities unchanged.

The adjacent source-loop update coalescer had the same stale-sidecar defect: it
rewrote a typed scratch into its protected source carrier and removed the
scratch assignment without reporting `scratch -> carrier`. It now returns that
rename and the renderer applies it transactionally. The positive test proves
both SSA candidates survive under the carrier; the two nearest refusal tests
prove an old-carrier use and a semantic-width mismatch still change nothing.

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

coalesces_a_typed_loop_update_scratch_into_its_source_carrier
1 passed; 4,418 filtered out

keeps_a_loop_update_scratch_when_the_old_carrier_is_still_needed
1 passed; 4,418 filtered out

keeps_a_loop_update_scratch_with_a_different_semantic_width
1 passed; 4,418 filtered out
```

Each case used `cargo test --features python-ext --lib
ir::latch_predicate::tests::<name> -- --exact`. No broad Rust, Python, fixture,
DecBench, or Joern suite was run. These are the first two AST-native identity
mutation contracts, not completion of every renaming/coalescing pass.
