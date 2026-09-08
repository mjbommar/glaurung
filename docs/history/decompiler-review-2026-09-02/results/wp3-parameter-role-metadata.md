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

Commit `bc8c7755` migrates declaration-plan fact admission. Recovered pointer
pointee width, integer signedness/width, and pre-canonicalization machine width
now recognize a parameter through `ValueIdentities::parameter_slot` whenever
the authoritative sidecar is installed. A stray type-map row named `arg0` or
`arg1` can therefore no longer alter body casts or pointer-index rendering.
Exact SSA identities and promoted stack locals remain separately eligible, and
the explicit no-sidecar compatibility path retains legacy spelling.

Commit `973d1931` migrates the recursive identifier census used by the
production renderer. Every nested expression and statement receives the same
identity sidecar, so signature arity, locals, stack objects, wide-vector
storage, and call-result declaration facts agree on parameter ownership. The
type-map arity fallback uses the same predicate. With an empty authoritative
sidecar, a value merely named `arg0` renders as a local in a zero-argument
function; attaching slot 0 restores the parameter signature. The health-only
and public compatibility paths explicitly pass no sidecar and retain legacy
behavior.

Commit `5cbb36bd` makes that census result the renderer's sole parameter-role
authority. `DecIdents` records each displayed role with its proven slot, and
`DeclarationPlan` carries the map immutably beside parameter names and types.
Lvalue spelling, frame-object address rendering, and call-argument pointer
classification now query the plan; `dec_render.rs` contains no `argN` parser.
The observed defect declared `unsigned char arg0[4]` but returned
`(void *)(arg0)`. It now consistently returns the local object's address,
while an identity-owned slot still uses the parameter-value representation.

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

declaration_facts_do_not_trust_an_unowned_arg_spelling
RED: unowned arg0 produced Some((false, 4)); 1 failed, 4,438 filtered out
GREEN: 1 passed; 4,438 filtered out

ir::ast::declaration_plan::identity_tests::
6 passed; 4,433 filtered out

identifier_census_does_not_trust_an_unowned_arg_spelling
RED: rendered long census_identity(long arg0); 1 failed, 4,439 filtered out

ir::ast::decbench_render::identity_census_tests::
3 passed; 4,439 filtered out

stack_address_rendering_does_not_trust_an_unowned_arg_spelling
RED: declared unsigned char arg0[4] but returned (void *)(arg0)
1 failed; 4,442 filtered out

ir::ast::decbench_render::identity_census_tests::
5 passed; 4,439 filtered out

ir::ast::declaration_plan::identity_tests::
6 passed; 4,438 filtered out
```

Each command was `cargo test --features python-ext --lib
<focused-test>`, with `-- --exact` on the individually named cases. No broad
Rust, Python, fixture, DecBench, or Joern suite was run. Remaining
parameter-role consumers are still open under WP3.

## Pre-naming direct-output authority

Commit `e79bb7b5` removes a distinct `ret` spelling dependency from
prototype-backed output recovery. `materialize_prototype_output` runs before
`apply_role_names`, so a value already spelled `ret` at that boundary is not a
pipeline-owned result role. The pass now admits body-written output storage
only through the selected calling convention's ABI register predicate. Its
ordinary post-naming compatibility sibling continues to accept canonical
`ret`; replacing that path requires typed result-role transport and is not
claimed here.

Focused RED/GREEN evidence:

```text
cargo test --features python-ext --lib \
  prototype_output_does_not_trust_an_unowned_ret_spelling -- --nocapture
RED: 1 failed; 4,444 filtered out
GREEN: 1 passed; 4,444 filtered out

cargo test --features python-ext --lib ir::direct_output::tests -- --nocapture
14 passed; 4,431 filtered out
```

No fixture matrix, broad Rust/Python suite, DecBench, or Joern lane was run for
this single-module semantic correction.

## Typed post-naming result roles

Commit `e30c727f` carries the source result role beside opaque SSA identities.
Role projection records `ret` only when a value with actual identity was mapped
there by the pipeline, and later AST renames move that fact with the value.
Production source preparation consumes this fact: an arbitrary local named
`ret` no longer supplies a bare return, while a pipeline-owned `ret` continues
to do so. The no-sidecar compatibility function remains explicitly spelling-
based and is not mistaken for production authority.

Focused RED/GREEN evidence:

```text
cargo test --features python-ext --lib \
  attributed_output_does_not_trust_an_unowned_ret_spelling -- --nocapture
RED: compile failure because the identity-aware entry point did not exist
GREEN: 1 passed; 4,446 filtered out

cargo test --features python-ext --lib \
  attributed_output_accepts_a_pipeline_owned_ret_role -- --nocapture
1 passed; 4,446 filtered out

cargo test --features python-ext --lib ir::direct_output::tests -- --nocapture
16 passed; 4,431 filtered out

cargo test --features python-ext --lib value_number::tests:: -- --nocapture
51 passed; 4,396 filtered out
```

This increment ran 69 directly relevant tests. It did not run the broad Rust or
Python suites, fixture matrix, DecBench, or Joern.

## Typed late-return cleanup

Commit `e27ab2cc` migrates the late `ret = constant; return constant;` cleanup
to the same result-role authority. Both production cleanup call sites pass the
identity sidecar. A local merely spelled `ret` is preserved; a pipeline-owned
result assignment is removed, with the existing origin-transfer behavior
unchanged. The no-sidecar helper remains the explicit compatibility path.

Focused RED/GREEN evidence:

```text
cargo test --features python-ext --lib \
  late_return_cleanup_does_not_trust_an_unowned_ret_spelling -- --nocapture
RED: compile failure because the identity-aware cleanup did not exist
GREEN: 1 passed; 4,448 filtered out

cargo test --features python-ext --lib \
  late_return_cleanup_accepts_a_pipeline_owned_ret_role -- --nocapture
1 passed; 4,448 filtered out

cargo test --features python-ext --lib ir::ast::return_folds::tests -- --nocapture
12 passed; 4,437 filtered out
```

Only these 14 directly relevant executions ran. No broad Rust/Python suite,
fixture matrix, DecBench, or Joern lane ran.

## Typed pre-render verification

Commit `aab2921d` threads result-role authority into the final verifier. Its
structured walk, goto-aware CFG builder, and whole-function definition census
share one explicit decision: a call without a destination implicitly defines
`ret` only when the pipeline identity sidecar owns that result role. Explicit
call destinations remain definitions. The no-sidecar verifier retains its
legacy behavior for compatibility and health-only callers.

Focused evidence:

```text
cargo test --features python-ext --lib \
  production_verifier_does_not_let_a_call_define_an_unowned_ret_spelling \
  -- --nocapture
1 passed; 4,449 filtered out

cargo test --features python-ext --lib \
  production_verifier_accepts_a_call_defining_an_owned_ret_role \
  -- --nocapture
1 passed; 4,450 filtered out

cargo test --features python-ext --lib ir::verify_defs::tests -- --nocapture
41 passed; 4,410 filtered out
```

No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane ran.

## Exact plain-typed role projection

Commit `32698e2e` removes the guessed `remap_type_map` path from the production
plain `types=True` renderer. Type recovery now runs over the prepared numbered
LLIR and projects through the exact canonical role map plus opaque SSA
identities. An integer value renamed from `eax#1` to `var0` therefore keeps its
recovered `int` fact rather than remaining under an internal key the rendered
AST never uses. The old calling-convention reconstruction function and its last
caller are gone.

Focused evidence:

```text
cargo test --features python-ext --lib \
  plain_typed_render_projects_exact_integer_roles -- --nocapture
1 passed; 4,457 filtered out

cargo test --features python-ext --lib \
  python_bindings::ir::type_maps::tests -- --nocapture
20 passed; 4,438 filtered out
```

No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane ran.

## Typed dead-store call clobbers

Commit `fbb7f596` migrates the production post-naming dead-store pass from the
literal `ret` spelling to typed result-role authority. A call no longer makes a
preceding assignment to an unrelated local named `ret` appear dead. When role
projection proves that canonical `ret` is the ABI result role, the established
call-clobber cleanup remains active.

Focused evidence:

```text
cargo test --features python-ext --lib \
  call_does_not_kill_an_unowned_ret_spelling -- --nocapture
1 passed; 4,454 filtered out

cargo test --features python-ext --lib \
  call_kills_a_pipeline_owned_ret_role -- --nocapture
1 passed; 4,454 filtered out

cargo test --features python-ext --lib ir::dead_stores::tests -- --nocapture
42 passed; 4,413 filtered out
```

The three cached commands completed in 0.38 seconds total. No broad
Rust/Python suite, fixture matrix, DecBench, or Joern lane ran.

## Typed stacked-parameter naming

Commit `b3210392` makes stack promotion retain the source-parameter slot it
already proves for promoted incoming stack storage. Production canonical naming
consumes that typed map instead of preserving every identifier whose text can
be parsed as `argN`. An unowned `arg99` now receives an ordinary stable `varN`
name; a genuine promoted `arg6` remains the sixth source parameter. The public
compatibility path keeps its legacy spelling fallback when no typed stack facts
are supplied.

Focused evidence:

```text
cargo test --features python-ext --lib \
  production_naming_does_not_trust_an_unowned_arg_spelling -- --nocapture
1 passed; 4,456 filtered out

cargo test --features python-ext --lib \
  production_naming_preserves_a_proven_stack_parameter_role -- --nocapture
1 passed; 4,456 filtered out

cargo test --features python-ext --lib \
  a_full_width_write_to_a_sysv_stacked_argument_slot_assigns_the_parameter \
  -- --nocapture
1 passed; 4,456 filtered out

cargo test --features python-ext --lib stack_argument -- --nocapture
13 passed; 4,444 filtered out

cargo test --features python-ext --lib ir::naming::tests -- --nocapture
20 passed; 4,437 filtered out
```

No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane ran.

## Typed direct and exhaustive return folding

Commit `c599ac49` migrates the production `result = value; return result;`
folds to typed result-role authority. Both source-preparation stages use the
identity-aware direct fold, including the normalization performed before
exhaustive `if` and `switch` return promotion. An arbitrary local named `ret`
is no longer classified as exact machine result storage. A pipeline-owned
`ret`, and exact versioned ABI storage such as `rax#7`, retain their established
folds. No-sidecar lowering and compatibility APIs retain their legacy behavior.

Focused evidence:

```text
cargo test --features python-ext --lib \
  return_fold_does_not_trust_an_unowned_ret_spelling -- --nocapture
1 passed; 4,452 filtered out

cargo test --features python-ext --lib \
  return_fold_accepts_a_pipeline_owned_ret_role -- --nocapture
1 passed; 4,452 filtered out

cargo test --features python-ext --lib ir::ast::return_folds::tests -- --nocapture
14 passed; 4,439 filtered out
```

No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane ran.
