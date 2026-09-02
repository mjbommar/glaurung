# 01. The architecture as built

All paths are relative to the repository root at `master` @ `5c4df8d2`.
"The code does X" is cited to a `file:line`; "the doc says X" is cited to a
document under `docs/`.

## 1. Size

`src/ir/` is 202 files and 164,779 lines (tests included). By owner:

| owner | LOC |
|---|---:|
| top-level `src/ir/*.rs` | 116,230 |
| `ast/` | 12,519 |
| `lift_x86/` | 5,455 |
| `mir/` | 4,550 |
| `stack_locals/` | 4,522 |
| `copy_prop/` | 3,298 |
| `call_args/` | 3,024 |
| `memory_objects/` | 2,930 |
| `structure/` | 2,604 |
| `types_recover/` | 2,506 |
| `value_number/` | 2,065 |
| `lift_arm32/` | 1,539 |
| `lift_arm64/` | 1,476 |

The ten largest files, with the line where `mod tests` begins:

| file | total | tests start |
|---|---:|---:|
| `ast.rs` | 9,710 | 1,731 |
| `lift_x86.rs` | 9,556 | 2,271 |
| `call_args.rs` | 5,699 | 1,330 |
| `types_recover.rs` | 5,539 | 1,913 |
| `stack_locals.rs` | 4,928 | 873 |
| `lift_arm32.rs` | 4,030 | 1,981 |
| `lift_arm64.rs` | 3,598 | 2,062 |
| `structure.rs` | 3,032 | 491 |
| `value_number.rs` | 2,692 | 435 |
| `loop_form.rs` | 2,571 | 1,262 |

Tests dominate several of these; `ast.rs` is 82% tests by line.

The two structuring layers, product and tests together:

| layer | files | LOC |
|---|---|---:|
| LLIR structurer | `structure.rs`, `structure/*.rs`, `structure_accounting.rs` | 7,041 |
| AST control-flow rewrites | `loop_form`, `switch_ladder`, `guard_chain`, `guarded_switch`, `label_prune`, `select_fold`, `terminal_loop`, `latch_predicate`, `effectful_loop`, `guarded_call`, `control_semantics`, `structured_reaching` | 11,303 |

## 2. Intermediate representations

| IR | where | status |
|---|---|---|
| LLIR (`LlirFunction`, `Op`, `VReg`, `Value`) | `src/ir/types.rs` | Production. `Op::Bin { dst, op, lhs, rhs }` carries no width (`types.rs:301-306`). `Value` is `Reg / Const(i64) / Addr` (`:146`). `Op` has `IndirectJump`, `Ite`, `Intrinsic`, `Undef` and no `Switch`; `cfg_edges.rs:16-19` derives `SwitchDefault` from successor counts. |
| SSA | `src/ir/ssa.rs` | A sidecar `SsaInfo` keyed by `InstrAddr`. `SsaValue { base, version }` exists (`:30-42`). Flags are now versioned (`:256-258`, `VReg::FlagValue` at `types.rs:107-112`). |
| Value-numbered LLIR | `src/ir/value_number.rs`, `value_number/tagging.rs:104-129` | Rewrites `Phys` names to `"{canon}#{version}"` strings; consumers parse them back with `rsplit_once('#')` (`value_number/coalesce.rs:43`, `parameter_slots.rs:56,66`). |
| Region tree | `src/ir/structure/region.rs:15-97` | `Block / Seq / IfThen / IfThenElse / While / DoWhile / RawLoop / Switch / Goto / Unstructured`. |
| AST (`ast::Function`, `Stmt`, `Expr`) | `src/ir/ast.rs` | The working representation for about 100 transforms. `Function { name, entry_va, body: Vec<Stmt> }` (`ast.rs:622-626`). `Expr::Reg(VReg)`; there is no `SsaValue` anywhere in `ast.rs` or `ast/*` (grep: 0 hits). |
| MIR (`MirFunction`, `DefinitionOracle`) | `src/ir/mir/` plus `memory_ssa.rs` and `memory_objects/mir.rs` | Built only inside the `GLAURUNG_DUMP_PASSES` dump (`src/python_bindings/ir/pipeline.rs:507`) and via `PreparedLlir::mir()`, which is `#[allow(dead_code)]` with no caller (`pipeline.rs:401-407`). `DefinitionOracle::new` has no caller outside `#[cfg(test)]` (`mir/mod.rs:121,266,294,335,505`). |

The consequence that matters most: **the dataflow passes operate on the flat
AST, not on SSA.** The public entry points of the passes take
`&mut ast::Function`:

- `copy_prop::propagate_copies(f: &mut Function)`
- `dce::prune_overwritten_flags` / `prune_dead_flags(f: &mut Function)`
- `dead_stores::eliminate_dead_stores` / `prune_callee_saved_spills` / `prune_unobserved_promoted_object_stores(f: &mut Function)`
- `const_fold::fold_constants` / `fold_typed_comparison_extensions` / `fold_typed_declared_views(f: &mut Function)`
- `expr_reconstruct::reconstruct(f: &mut Function)`
- `stack_locals::promote_stack_locals` / `promote_stack_locals_typed(f: &mut Function)`
- `call_args::reconstruct_args(f: &mut Function)`

Only `ssa.rs`, `value_number.rs`, `types_recover/valued.rs`, `definedness.rs`
and the structurer consume SSA. SSA is computed up to four times per function
(see 02-pipeline-map.md), and its identities are dropped at `ast::lower`.

## 3. Structuring

**Algorithm family.** A pattern-matching tree walk with a global `visited` set
(`src/ir/structure.rs:259-476`). It is not dominator-tree or SESE region
construction, and not DREAM, Phoenix or "No More Gotos". The module doc says so
itself (`structure.rs:1-20`: "walks the CFG from the entry block,
pattern-matching on successor counts and dominator info ... intentionally simple
and conservative").

`build` advances a cursor and tries recognisers in a fixed order:
`detect_raw_dispatch_loop` (`:278`), `detect_bottom_tested_loop` (`:293`),
`detect_raw_multi_latch_loop` (`:307`), `detect_natural_loop` (`:329`),
`detect_switch_shape` (`:346`), `detect_guarded_switch_shape` (`:389`),
`detect_if_shape` (`:399`), then a straight-line block. `Cfg::from`
(`structure/cfg.rs:109`) reads `ssa.idom`, computes post-dominators (`:410`) and
typed edges via `cfg_edges::classify`. `if_shape.rs` describes itself as "a
descending ladder of diamond shapes" (`:5-11`).

**The algebra cannot express split ownership.** `Region::While` and
`Region::DoWhile` carry exactly one `exit: Option<usize>`; `IfThen` and
`IfThenElse` carry exactly one `join: Option<usize>` (`region.rs:24-56`). A
loop with an early `return` on one path and a normal exit on another, or a
conditional whose arms meet beyond the loop, has no representation. There is no
`Return` node, no `Continue`, and `Break` exists only as an AST statement
recovered afterwards (`ast/lower_region.rs:38-43`).

**Whole-function fallback.** `build_full` (`structure.rs:204-257`) runs three
pre-build proofs from `structure/fallback.rs`
(`has_multi_latch_loop_with_distinct_exits`,
`has_loop_conditional_with_join_beyond_loop`,
`has_inner_loop_exit_that_reenters_via_outer_cycle`) and, after the build, a
typed-edge accounting check (`structure_accounting::account`). Any hard finding
returns `Region::Unstructured((0..lf.blocks.len()).collect())`: every block of
the function, not the offending one, goes to the labelled CFG. `fallback.rs`'s
own doc comment (`:17-19`): "A `true` from any of them costs the whole function
its structure."

**Short-circuit conditions.** There is no region shape for `&&`/`||`. The
region tree emits `Region::Goto` to the shared join (`lower_region.rs:173-177`),
and `guard_chain.rs` then pattern-matches the result at AST level.

**Switches.** From the LLIR side, a switch is an `IndirectJump` with N>=3
successors and `case_labels` (`cfg.rs:33-38`). `-O0` comparison ladders are
recovered later at AST level by `switch_ladder.rs`, which runs twice.

**The second layer.** `ast/prepare.rs` invokes about 62 transforms on the flat
AST (its doc comment at `:88-134` says "These nineteen steps"). The
control-flow subset, in invocation order:

```
guard_chain::collapse_shared_exit_guard_ladders
guard_chain::collapse_shared_assignment_guards
guard_chain::collapse_redundant_copy_nested_guards
guard_chain::collapse_nested_terminal_return_guards
switch_ladder::recover_switches                      (1 of 2)
select_fold::collapse_assignment_diamonds            (1 of 2)
guarded_call::materialize_false_edges
lazy_call_select::collapse_lazy_call_diamonds_with_pointer_width
select_fold::recover_guarded_select_returns
terminal_loop::recover_terminal_self_loops
label_prune::inline_terminal_goto_tails
label_prune::recover_forward_exit_regions            (2-round loop with the next)
loop_form::recover_linear_latched_do_whiles
select_fold::collapse_assignment_diamonds            (2 of 2)
label_prune::prune_unreachable_tails
loop_form::recover_head_tested_whiles
loop_form::recover_guarded_do_whiles                 (1 of 2; fired 0 times over 754 objects)
loop_form::recover_sentinel_search_loops             (fired 0 times over 754 objects)
guard_chain::collapse_adjacent_break_guards
guard_chain::collapse_nested_terminal_return_guards
switch_ladder::recover_switches                      (2 of 2)
guarded_switch::collapse_range_guards
loop_form::promote_for_loops
guard_chain::collapse_adjacent_break_guards
guard_chain::collapse_redundant_copy_nested_guards
guard_chain::collapse_matching_terminal_return_guard
loop_form::recover_guarded_do_whiles                 (2 of 2)
latch_predicate::fold_latched_predicates
```

Each of these matches the output of the previous heuristic rather than a CFG
property; `pass_stats.rs:5-7` describes them as "a long conjunction of shape
requirements". The 2026-08-27 reproduction document already named this: "Eight
AST passes now restructure control flow ... No document justifies two
structuring layers. It reads as accretion"
(`docs/design/decbench-defect-reproductions-2026-08-27.md:280-300`), and:
"Any redesign must grow the region algebra first. Patching the predicate is
what was tried twice and reverted twice."

**Goto emission.** `Region::Goto` lowers to `Stmt::Goto` with `Stmt::Label` on
referenced blocks (`lower_region.rs:173-197`). `Stmt::Break` is recovered by
`recover_direct_loop_breaks` (`:38`). `label_prune::inline_terminal_goto_tails`,
`recover_forward_exit_regions` and `terminal_loop` remove gotos afterwards on
the AST. Goto density is not measured anywhere in `src/`; only
`tools/extbench/analyze.py` computes it.

**Accounting.** `structure_accounting.rs` (1,405 LOC) is the typed-edge
implication check (`BlockDropped`, `BlockDuplicated`, `EdgeUnaccounted`,
`EdgeViaGoto`, `BackEdgeUnowned`, `ImpliedEdgeAbsent`, `GotoTargetMissing`,
`SwitchArmOutsideLoop`). It both gates fallback (`structure.rs:163`,
`fallback.rs:36-50`) and feeds `CfgHealth` counters.

## 4. Type recovery

- `types_recover.rs` (5,539 LOC). `TypeMap = HashMap<VReg, TypeHint>` (`:121`)
  with a flow-insensitive `upsert` join (pointer beats int, wider pointee wins,
  unsigned is sticky). `TypeHint` is
  `Pointer { pointee_width } / Int { signed, width } / Float { width } / BoolLike / CodePointer`
  (`:58-78`). There is no struct, array or typedef, and no constraint or
  solver. `TypeMapV = HashMap<SsaValue, TypeHint>` (`:304`) is built by
  `types_recover/valued.rs` with bounded 8- and 16-iteration propagation loops
  (`:88, :639, :705, :796`). Its only consumer is
  `recover_prototype_with_arm_vfp_args`.
- `decbench_type_maps` (`src/ir/type_maps.rs:483-627`) runs `recover_types_for`
  on both `lf_raw` and `lf_numbered`, remaps each by role name through
  `remap_type_map_impl` (`:65`), then builds `decl` and `width` maps through
  two eight-step refinement sequences duplicated verbatim (`:513-534` and
  `:548-604`).
- `stack_locals.rs` plus its directory (9,237 LOC) promotes `[rbp-k]` and
  `[sp+k]` to `local_N` / `stack_N` by `(base, disp)`; 17 `cc` gates in the top
  file alone.
- `high_variables.rs` propagates pointer-ness over copy and select edges at AST
  level into the legacy `TypeMap` (`:33`), using `memory_objects::infer_from_ast`.
- DWARF and PDB. `dwarf_type_env.rs` resolves typedef and tag relationships;
  `src/python_bindings/ir/dwarf_contracts.rs` turns DWARF prototypes into locked
  `TypeMap` facts (`apply_locked_fact`, `types_recover.rs:158`);
  `dwarf_fields.rs` and `pdb_fields.rs` annotate field accesses at render time.
  DWARF authority flows in as C type strings (`HashMap<String, String>`) that
  the renderer re-parses (`ast/decbench_render.rs:53-79`).
- **Declared prototype authority exists, but is still recovery-gated.**
  `ir.rs:451-468` selects analyst declarations first and then DWARF, and
  `python_bindings/ir/decbench_render.rs:442-474` prefers a supplied declaration
  over a recovered render prototype. But the final AST renderer filters that
  declaration on recovered `arg_count`, recovered void/non-void output, and
  type renderability (`src/ir/ast/decbench_render.rs:186-207`). The observed
  fixtures still omit an available source prototype and render `arg0`, `arg1`.
  Authority exists in the plumbing but does not yet hold end to end; parameter
  names from DWARF are not applied.

## 5. Verification

| verifier | where | when | effect |
|---|---|---|---|
| `structure::verify_region` | `structure/verify.rs` | at structuring | `tracing::debug!` only |
| `structure_accounting::account` | `structure_accounting.rs` | at structuring | hard findings force whole-function fallback |
| `health::trace_pass` | `health.rs:351` | after every named pass | only when `GLAURUNG_PASS_HEALTH` is set |
| `verify_defs::verify_before_render` | `verify_defs.rs:774` | just before render | records violations; never blocks; global never-defined/poison/frame checks still run, but path-sensitive `UsedBeforeDefinition` is skipped for functions containing goto or labels |
| `src/ir/verify.rs` (LLIR width / temp / memory-size invariants) | 357 LOC | never | not compiled: `pub mod verify;` left `src/ir/mod.rs` in `5e24383a` (2026-08-12); the only `mod verify;` remaining is `structure.rs:56`, a different module. `docs/test-inventory/index.json:20311` still lists its tests. |
| `mir/verify.rs` | | only if MIR is built | debug dump only |

The only fail-closed path in the whole pipeline is structure fallback.

## 6. Dormant subsystems

| subsystem | LOC (approx., with tests) | evidence of dormancy |
|---|---:|---|
| `mir/`, `memory_ssa.rs`, `memory_objects/`, `DefinitionOracle` | about 8,700 | no semantic production caller; `PreparedLlir::mir` is `#[allow(dead_code)]`; roadmap `docs/design/decompiler-roadmap.md:253` concedes "not yet the production authority" while ticking the items `[x]` at `:209-219, 411, 529` |
| `src/ir/verify.rs` | 357 | uncompiled since 2026-08-12 |
| `effect_census.rs` | | `mod.rs:50`; no non-test caller |
| `loop_form::recover_guarded_do_whiles` | | 0 fires over 5,580 attempts across 754 objects (`docs/design/dormant-transforms-2026-08-12.md`, re-measured 2026-08-15); still invoked twice per function (`prepare.rs:250, :279`) |
| `loop_form::recover_sentinel_search_loops` | | 0 fires over 2,790 attempts; fixture `192_pointer_chased_list` exists and does not trigger it; still invoked (`prepare.rs:252`) |

## 7. Entry points

Four PyO3 front doors in `src/python_bindings/ir.rs`: `decompile_at` (`:110`),
`decompile_range_at` (`:512`), `decompile_all` (`:944`), `decompile_many`
(`:1225`). The CLI calls `decompile_at`
(`python/glaurung/cli/commands/decompile.py:111`). Each front door assembles
the front half of the pipeline itself; `src/python_bindings/ir/pipeline.rs`
carries the middle.

`decompile_range_at` constructs `DirectCalleeFacts::default()` (`ir.rs:654`)
and never calls `recover_direct_callee_layouts`, so the same function
decompiled by VA and by range gets different callee prototypes.
`decompile_all` and `decompile_many` re-run discovery, naming and callee
analysis in their own loops (`ir.rs:1036-1076`, `:1373-1413`).
`docs/design/decompiler-middle-architecture.md` Phase 1 ("all four entry points
produce byte-identical output") is not met.

Only `style="decbench"` with `types=true` runs the full pipeline. `--style c`
is the low-level view and still shows `%zf`, `%sf`, `t10` and
`rsp = (rsp - 8)`; `decbench` is what is scored and the only fair thing to
compare (`docs/development/decompiler-parity-backlog.md`, "Reproducing it").

## 8. Smells, with citations

1. **Pass ordering lives in prose.** "must run on raw LLIR before SSA"
   (`pipeline.rs:15-19`); "runs before register renaming so aliases cannot
   collide" (`:186-188`); "DSE runs after naming so it sees `ret`"
   (`:270-272`); "a general copy-prop rerun is unsound here"
   (`prepare.rs:263-266`); "Deliberately the LAST semantic pass"
   (`decbench_render.rs:414-418`). Nothing checks these.
2. **The same pass runs repeatedly because earlier runs cannot see later
   shapes.** `fold_constants` four times, `recognise_machine_frame` three,
   `resolve_names` two, `recover_switches` two, `recognise_canary` two,
   `compute_ssa` up to four, `value_number` two (one whose result is discarded).
3. **Presentation names carry semantics.** `dead_stores.rs:39-43` lists
   `"ret"` and `"arg0"` beside `"rax"` as return aliases; `naming.rs:142-149`
   mints `"ret"`; `types::is_promoted_local_name` (`starts_with("local_")`,
   `types.rs:114`) has 18 product callers; `VReg::phys("ret")` and
   `format!("arg{slot}")` keys appear in 12 product files (`types_recover.rs`
   21 sites, `dwarf_fields.rs` 13, `type_maps.rs` 12, `call_contracts.rs` 10).
   The middle-architecture doc's stop condition, "a semantic value must be
   identified by parsing a display name", is the normal case.
4. **Render-time semantics and thread-locals.** `decbench_text` installs
   `symbol_env` and `dec_global_names` thread-locals around the render
   (`decbench_render.rs:116-136`); `DEC_PLAN` and `DEC_SOURCE_LOCALS`
   (`ast.rs:1348-1371`); `symbol_env.rs:190` adds another;
   `named_constants::symbolic_name` is called from inside `dec_render.rs:1682`.
5. **Lifters share no abstraction.** There is no lifter trait. Each ISA has
   its own width-narrowing helpers with different names:
   `signed_cmp_value` / `unsigned_cmp_value` (`lift_x86/flags.rs:33,51`),
   `arm_signed32` / `arm_unsigned32` (`lift_arm32/flags.rs:204,220`),
   `signed_view` / `unsigned_view` (`lift_arm64/flags.rs:78,95`).
   `cmp_flag_ops` exists in both x86 and arm32. Shared passes then re-encode
   ISA behaviour as `cc` gates: 17 in `stack_locals.rs`, 8 in
   `types_recover/float_bank.rs`, 6 in `dead_stores.rs`, 5 in `naming.rs`;
   `recognise_machine_frame` is a `match cc` (`pipeline.rs:310-322`).
   `Op::Unknown` construction sites: 83 (x86), 59 (arm32), 128 (arm64).
   `regview::Arch` is still `{ X86_64, AArch64 }`; ARM32 has no register view
   descriptor.
6. **`Stmt::If` is matched by hand in 558 places** across `src/ir` (grep,
   2026-09-02). There is no visitor or rewriter trait.
7. **Two type maps reconciled by string.** See section 4.
8. **Verification is advisory, and skipped where it matters.** See section 5.
