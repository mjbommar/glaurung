# WP3 AST-native identity renames

Commits `3afd711a`, `d8da5f13`, and `97f65ae6` establish the first three
mutation-aware identity boundaries inside the prepared AST pipeline.

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

The final authoritative-local and canonical-loop naming passes also changed AST
keys without changing the identity sidecar subsequently passed to typed
rendering. Both maps now move candidates in the same presentation transaction.
When multiple old roles acquire one rendered name, their candidates are unioned
and `exact` deliberately refuses the ambiguous result.

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

presentation_renames_move_identity_candidates_to_the_rendered_name
1 passed; 4,420 filtered out

colliding_presentation_renames_preserve_explicit_identity_ambiguity
1 passed; 4,420 filtered out
```

Each case used `cargo test --features python-ext --lib
ir::latch_predicate::tests::<name> -- --exact`. No broad Rust, Python, fixture,
DecBench, or Joern suite was run. These are the first three AST-native identity
mutation contracts, not completion of every renaming/coalescing pass.
