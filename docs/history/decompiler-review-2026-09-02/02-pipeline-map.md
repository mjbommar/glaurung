# 02. Pipeline map

> **Kind:** record · **Date:** 2026-09-02

The ordered schedule of `decompile_at_session`
(`src/python_bindings/ir.rs:145-509`) with `style = "decbench"` and
`types = true`, which is the only configuration that runs the full pipeline.
Line numbers are at `master` @ `5c4df8d2`.

Roughly **110 transform invocations over about 70 distinct passes** run on
this path: 12 at the LLIR stage, 19 named blocks in `run_ast_passes`, about 62
invocations in `prepare_for_decbench`, and 20 in `decbench_text`.

## Stage A: image and program facts (`ir.rs:170-260`)

1. `session.discover_functions` (CFG discovery under `src/analysis/cfg*`, 10,319 LOC) - `ir.rs:197`.
2. `name_resolve::collect_address_map_with_pdb_cache_and_data_symbols`, then discovered and referenced names - `ir.rs:220-225`.
3. `session.environment(...)` program-level prototypes - `ir.rs:235` (decbench only).
4. `lift_function::lift_function_from_image` - `ir.rs:240`. Per block, `lift_window` dispatches on `CodeMode` to `lift_x86` / `lift_arm32` / `lift_arm64` (`src/ir/lift_function.rs:341-425`). Residual `Op::Unknown` is rewritten to an opaque `Op::Intrinsic` by `lower_unknowns` (`:866`).
5. `inline_soft_helper_calls_in`, then `annotate_calls_in` = `abi::annotate_calls` + `call_contracts::apply_known_llir_call_contracts` (`pipeline.rs:20-40`). Comment: must be pre-SSA.
6. `function_tables::collect_function_pointer_tables`, `session.call_graph_for`, `recover_direct_callee_layouts` (recursive callee analysis, `ir/callee_contracts.rs:682`), `apply_recovered_direct_callee_effects` (`:332`) - `ir.rs:246-266`.
7. Analyst rename overlay, applied after the name-keyed callee analysis - `ir.rs:275-283`.

## Stage B: LLIR preparation, `prepare_llir_for_lowering` (`pipeline.rs:410-531`)

8. `normalize_definedness_and_compute_ssa` (`:351`): `exception::with_exceptional_successors` -> `ssa::compute_ssa` (**SSA #1**) -> `definedness::BitDemandOracle::analyze` -> `erase_unobserved_masked_inputs`; if anything was erased, `compute_ssa` again (**SSA #2**).
9. Provisional parameter slots: `value_number::value_number_with_parameter_slots(...).2` - a full value-numbering run whose numbered function is discarded (`:423`).
10. `recover_decbench_prototype` (`ir.rs:769`) -> `types_recover::recover_prototype_with_arm_vfp_args` (`types_recover.rs:1327`), which runs `recover_types_valued` (SSA-keyed) and `prototype_width::ObservableParameterWidths` and joins against the raw register `TypeMap`. Program-environment facts layered on (`:440-455`).
11. `types_recover::materialize_return_values` (`:1103`); if it changed anything, step 8 runs again (**SSA #3 / #4**) - `pipeline.rs:456-459`.
12. `indirect_targets::resolve_indirect_jumps` (`:471`) - PLT and GOT slots only; table dispatch is "left entirely alone" (`indirect_targets.rs`, test at `:274`).
13. **Structuring runs here, on LLIR + SSA, before any AST exists**: `structure::recover_verified_with_health_and_destinations` (`:479`).
14. `value_number_with_parameter_slots_and_lifetimes` - the real value numbering (`:486`); produces `numbered` LLIR with `reg#version` string names.
15. `lock_parameter_slots_from_prototype` (`:522`).
16. Back in `ir.rs:314`: `refine_passthrough_parameter_hints` computes `ssa::compute_ssa(&lf_raw)` once more on the raw function.

## Stage C: AST lowering and `run_ast_passes` (`pipeline.rs:83-303`)

`ast::lower` (`ir.rs:340`, on a dedicated big-stack thread; `ast/lower_region.rs:1-15`), then in order:

```
exception_recover::mark_landing_pads
vector_copy::recover_wide_copies
expr_reconstruct::reconstruct
const_fold::fold_constants                          (fold #1)
select_fold::fold_boolean_masks
dce::prune_overwritten_flags + dce::prune_dead_flags
got_fold::fold_got_pointer_loads
name_resolve::resolve_names                         (resolve #1)
function_tables::resolve_function_table_entries
call_args::recover_resolved_direct_tail_calls
call_args::recover_resolved_tail_calls
call_args::reconstruct_args_with_layouts
call_contracts::apply_recovered_callee_prototypes
call_contracts::apply_known_call_contracts
call_result_split::split_call_result_lifetimes
strings_fold::fold_string_literals
canary::recognise_canary                            (canary #1)
aapcs64_indirect_result::indirect_result_buffer_hints
stack_locals::promote_stack_locals_with_facts
aapcs64_indirect_result::bind_indirect_result_buffers
recognise_machine_frame                             (frame #1: match cc -> x86 / arm32 prologue recognisers + prune_callee_saved_spills)
direct_output::materialize_prototype_output         (gated on RecoveredOutputKind::Direct)
callee_return_pair::compose_pair_returns
value_split::split_argument_storage_reuse
naming::apply_role_names_with_parameter_roles
canary::collapse_canary_save
arm64_prologue::recognise_arm64_prologue            (AArch64 only)
dead_stores::eliminate_dead_stores
stack_idiom::rematerialise_stack_ops
label_prune::prune_unreferenced_labels
```

Then in `ir.rs:378-407`: `apply_analyst_locals`,
`merge_dwarf_register_local_facts`, decbench-only
`exception_recover::{recover_typed_handlers, mark_int_throws_with_address_map, recover_throws}`,
`recognise_machine_frame` (**frame #2**), `pdb_fields::annotate_function_fields`.

## Stage D: types, `decbench_type_maps` (`src/ir/type_maps.rs:483-627`)

`recover_types_for` on `lf_raw` and again on `lf_numbered`; each remapped by
role name through `remap_type_map_impl` (`:65`); then two eight-step
refinement sequences, duplicated verbatim, build the `decl` map
(`:513-534`) and the `width` map (`:548-604`).

## Stage E: prepare, verify, render, `decbench_text` (`src/ir/ast/decbench_render.rs:84-458`)

`ast::prepare_for_decbench_with_output_and_protected_locals`
(`src/ir/ast/prepare.rs:162-288`), about 62 invocations including:

- `settle_copies_and_constants`: 4 rounds of `copy_prop::propagate_copies` + `const_fold::fold_constants` (`:55-62`).
- `direct_output::clear_return_values`, `materialize_direct_output`, `label_prune::prune_unreachable_tails`.
- `dce::prune_overwritten_flags`, `prune_dead_flags`, `copy_prop::propagate_adjacent_promoted_values`, `propagate_adjacent_guard_values`.
- The control-flow list reproduced in 01-architecture-as-built.md section 3, including a 2-round `recover_forward_exit_regions` / `recover_linear_latched_do_whiles` loop (`:241-244`), `recover_switches` twice (`:205, :259`), `guard_chain::collapse_*` three times, `recover_guarded_do_whiles` twice (`:250, :279`), `collapse_assignment_diamonds` twice.
- `copy_prop::move_adjacent_effectful_scratch_values`, `propagate_switch_entry_copies`.

Then in `decbench_render.rs:170-190`: `recognise_machine_frame`
(**frame #3**), `fold_exhaustive_if_returns`, `fold_constants`,
`resolve_names` (**resolve #2**), `recognise_canary` (**canary #2**),
`collapse_canary_save`.

Then 20 named `pass!` / `refine!` steps (`:255-428`):

```
refine_decbench_abi_widths
high_variables::refine_pointer_high_variables
latch_predicate::coalesce_loop_entry_copies
latch_predicate::coalesce_source_loop_updates
copy_prop::propagate_adjacent_typed_promoted_values
const_fold::fold_typed_declared_views
typed_simplify::fold_consumed_extensions
const_fold::fold_typed_comparison_extensions
cmp_fusion::fuse_comparisons
const_fold::fold_constants                          (fold #3)
readonly_fold (+ propagate_copies + fold_constants) (fold #4)
guarded_switch::collapse_range_guards_with_types
fold_exhaustive_switch_returns
fold_typed_return_abi_extensions
widen::insert_widening_casts_for_machine_width
call_contracts::refine_call_site_specs
dwarf_fields::annotate_function_fields
naming::apply_authoritative_local_names
exception_recover::recover_typed_handlers           (2nd)
exception_recover::recover_throws                   (2nd)
dead_stores::prune_unobserved_promoted_object_stores
callee_return_bank::compose_bank_returns            ("Deliberately the LAST semantic pass")
```

Finally `verify_defs::verify_before_render` (`:437`) ->
`health::record_render_verification` ->
`render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types`
(`:446`).

## Environment gates

None changes semantics. `GLAURUNG_DUMP_PASSES` (16 sites),
`GLAURUNG_PASS_HEALTH` (`health.rs:351`), `GLAURUNG_VERIFY_DEFS` (splices
comments into the output, `decbench_render.rs:456`), `GLAURUNG_PASS_STATS`,
`GLAURUNG_ACCOUNT_STRUCTURE` (`structure.rs:167`), `GLAURUNG_PIPELINE_PROFILE`,
`GLAURUNG_LOWERING_STACK_MB`.

## Repeats, in one table

| pass | invocations on the decbench path |
|---|---:|
| `ssa::compute_ssa` | up to 4 (+1 in `refine_passthrough_parameter_hints`) |
| `const_fold::fold_constants` | 4, plus the 4-round settle loop |
| `recognise_machine_frame` | 3 |
| `guard_chain::collapse_*` families | 3 |
| `value_number` | 2 (one discarded) |
| `name_resolve::resolve_names` | 2 |
| `switch_ladder::recover_switches` | 2 |
| `canary::recognise_canary` | 2 |
| `loop_form::recover_guarded_do_whiles` | 2 (fires 0 times) |
| `select_fold::collapse_assignment_diamonds` | 2 |
| `exception_recover::recover_typed_handlers` / `recover_throws` | 2 each |
