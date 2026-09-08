# WP3 typed parameter-role metadata

Commit `7eeb84ca` extends `ValueIdentities` with source-parameter slot metadata.
The common pipeline attaches its authoritative `parameter_slots` while
projecting exact AST role aliases. A slot is recorded directly as a semantic
fact; an arbitrary alias merely spelled `argN` cannot create one. Renames move
slot candidates with value candidates, and collisions remain explicitly
ambiguous.

Commit `53eb97ec` migrates the first consumer. Callee-contract pointer
back-propagation now recognizes a source parameter through
`ValueIdentities::parameter_slot` whenever the authoritative sidecar is
installed. A fake `arg99` therefore cannot acquire pointer type from its
spelling, while an owned `arg0` and the compatibility no-sidecar copy-chain
path retain their established behavior.

Commit `14f6d24a` completes the authority migration across this pointer-copy
decision chain. Structured call discovery, recursive definition compatibility,
expression classification, and parameter-origin tracing all receive the same
identity context. With a sidecar installed, only exact values, typed parameters,
and separately modelled promoted storage are trusted. An unowned `var2` copy no
longer transports a pointer fact merely because of its spelling; an exact
`var2` still transports the owned `arg0` fact.

Commit `11ae7601` migrates exact type-role projection. The remapper already
receives pipeline-owned `param_slots`; it now derives the protected role set
from those slots rather than parsing every alias that looks like `argN`.
Consequently the real `arg0` remains protected from later storage definitions,
while an unrelated exact role called `arg99` is projected normally.

Commit `5c88a5bd` applies the same rule to exact-definition-width merging. The
production caller now passes `param_slots` into the merge instead of forcing it
to rediscover parameters from names. A later subregister definition remains
unable to narrow an owned parameter prototype, an unrelated `arg99` can receive
its legitimate exact width, and ordinary local narrowing is unchanged. This
removes the final `parse_arg_index` call from `type_maps.rs`.

Commit `f6c9d0ce` migrates high-half ABI-width refinement. When the identity
sidecar is installed, only values with `parameter_slot` metadata are widened as
source parameters; the name parser remains solely in the compatibility path.
Thus a 32-bit `arg0` used above bit 31 becomes 64-bit, while an otherwise
identical unowned role called `arg99` remains 32-bit.

Commit `f3781342` migrates source-loop update eligibility. The production pass
now receives the identity sidecar and rejects a scratch only when
`parameter_slot` identifies it as a source parameter. An exact unowned scratch
called `arg99` can therefore coalesce normally; attaching slot 99 to the same
value preserves the parameter refusal. The no-sidecar compatibility path keeps
the legacy parser.

Commit `4219eee0` migrates optimized DWARF register-local merging. The common
pipeline now supplies its authoritative parameter-slot set directly; the merge
protects only the canonical roles owned by those slots instead of treating
every `argN` spelling as a parameter. An exact register local bound to an
unowned role called `arg99` therefore receives its DWARF name and type, while
the same role with owned slot 99 remains protected. Existing range, lifetime,
identifier-safety, ambiguity, and widest-claimant behavior is unchanged.

Commit `0c1d0819` migrates nominal library-call type refinement. The production
renderer now passes its renamed AST identity sidecar into call-contract
observation collection. A role receives an observation only when that sidecar
maps the exact value to a unique source-parameter slot; an ordinary value
merely spelled `arg0` cannot change the caller's prototype. The explicit
no-sidecar API retains name parsing for compatibility, and the existing
compatible and conflicting-use behavior remains pinned there.

Commit `40cb2904` migrates constant folding's parameter-address load rule. The
shared early AST pipeline supplies its authoritative parameter slots; the
post-promotion preparation fixpoint and all later renderer folds supply the
projected AST identity sidecar. Consequently a full-width load through the
address of an owned scalar parameter still becomes the parameter, while an
unowned value merely spelled `arg0` remains a dereference. Partial loads remain
explicit. The no-authority entry point retains its legacy behavior for tests,
benchmarks, and compatibility callers.

Commit `d5b69f98` migrates parameter-spill coalescing. The identity context now
flows through both promoted named-slot and frame-array-home discovery,
including cast stripping, straight-line scratch aliases, repeated-store
validation, nested control flow, and the final redundant-store conversion. An
unowned value called `arg0` cannot cause storage deletion or renaming; attaching
source-parameter slot 0 preserves the established coalescing and origin
behavior. Compatibility-only preparation still supplies no sidecar and keeps
the legacy spelling path.

Commit `964b66d6` migrates declared integer classification, shared by return
typing and typed expression cleanup. When the identity sidecar is installed,
parameter narrowing now requires `parameter_slot` ownership; an unowned role
called `arg0` remains the conservative machine-word integer instead of taking a
parameter-only 32-bit type. Exact non-parameter SSA values continue through
their value-specific type path, promoted locals remain storage-typed, and the
no-sidecar compatibility entry point retains legacy parsing.

Commit `b0197ec9` carries source-parameter ownership into promoted stack
storage. `SlotVal::parameter_slot` is derived once from the normalized frame
coordinate, calling convention, and authoritative parameter bound. A
full-width store becomes a parameter assignment only when that stored fact is
present, and little-endian adjacent-slot composition refuses actual parameter
storage rather than every local whose display name happens to match `argN`.
The same coordinate function now owns both name allocation and typed ownership,
so their ABI interpretations cannot drift independently.

Focused validation used exact Rust tests only:

```text
role_projection_records_parameter_slots_without_parsing_alias_spelling
1 passed; 4,424 filtered out

role_projection_preserves_original_keys_and_explicit_ambiguity
1 passed; 4,424 filtered out

callee_pointer_contract_does_not_trust_an_unowned_arg_spelling
1 passed; 4,425 filtered out

attributed_authoritative_callee_refines_a_forwarded_argument
1 passed; 4,425 filtered out

recovered_callee_pointer_flows_back_through_one_exact_parameter_copy
1 passed; 4,425 filtered out

callee_pointer_contract_does_not_follow_an_unowned_var_copy
1 passed; 4,426 filtered out

recovered_callee_pointer_flows_back_through_one_exact_parameter_copy
1 passed; 4,426 filtered out

attributed_authoritative_callee_refines_a_forwarded_argument
1 passed; 4,426 filtered out

exact_role_projection_uses_parameter_slots_instead_of_arg_spelling
1 passed; 4,427 filtered out

float_role_projection_uses_opaque_identity_instead_of_numbered_spelling
1 passed; 4,427 filtered out

definition_width_merge_does_not_parse_unowned_arg_spelling
1 passed; 4,428 filtered out

later_subregister_definition_does_not_narrow_a_parameter_prototype
1 passed; 4,428 filtered out

a_narrowing_definition_still_types_a_local_on_a_sixty_four_bit_target
1 passed; 4,428 filtered out

high_half_parameter_width_uses_typed_slots_not_arg_spelling
1 passed; 4,429 filtered out

exact_opaque_identity_authorizes_definition_width_refinement
1 passed; 4,429 filtered out

ambiguous_opaque_identity_declines_definition_width_refinement
1 passed; 4,429 filtered out

coalesces_a_typed_loop_update_scratch_into_its_source_carrier
1 passed; 4,429 filtered out

keeps_a_loop_update_scratch_when_the_old_carrier_is_still_needed
1 passed; 4,429 filtered out

keeps_a_loop_update_scratch_with_a_different_semantic_width
1 passed; 4,429 filtered out

register_local_merge_uses_parameter_slots_not_arg_spelling
1 passed; 4,430 filtered out

python_bindings::ir::tests::dwarf_register_
7 passed; 4,424 filtered out

register_local_role_uses_opaque_identity_not_numbered_spelling
1 passed; 4,430 filtered out

opaque_parameter_refinement_uses_typed_parameter_roles
1 passed; 4,431 filtered out

compatible_library_uses_recover_an_opaque_caller_parameter
1 passed; 4,431 filtered out

conflicting_library_uses_do_not_invent_a_nominal_parameter_type
1 passed; 4,431 filtered out

parameter_address_load_requires_a_typed_parameter_role
1 passed; 4,432 filtered out

full_width_load_of_parameter_address_is_the_parameter
1 passed; 4,432 filtered out

attributed_full_width_parameter_load_unions_address_and_load_origins
1 passed; 4,432 filtered out

partial_load_of_parameter_address_is_not_widened
1 passed; 4,432 filtered out

ir::ast::param_spills::tests::
4 passed; 4,431 filtered out

ir::ast::return_ctype::tests::
5 passed; 4,431 filtered out

argument_assignment_does_not_trust_an_unowned_arg_spelling
1 passed; 4,436 filtered out

composition_does_not_trust_an_unowned_arg_spelling
1 passed; 4,437 filtered out

a_full_width_write_to_a_
2 passed; 4,435 filtered out

a_narrow_write_to_a_cdecl32_argument_slot_stays_a_store
1 passed; 4,436 filtered out

a_wide_load_over_an_incoming_parameter_slot_is_not_concatenated
1 passed; 4,436 filtered out

stack_arguments
10 passed; 4,428 filtered out
```

Each command was `cargo test --features python-ext --lib
<focused-test>`, with `-- --exact` on the individually named cases. No broad
Rust, Python, fixture, DecBench, or Joern suite was run. Remaining
parameter-role consumers are still open under WP3.
