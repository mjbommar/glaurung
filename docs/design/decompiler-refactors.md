# Decompiler foundational refactors (roadmap)

Status tracking for the "big" refactors that keep surfacing as workarounds in the
DecBench parity work. Current metrics on the local 14-program corpus (gcc -O0,
`/tmp/claude-1000/local_eval.py`): **type_match 0.873** (angr 0.819),
**GED 8.65** (angr 7.59), **byte_match ~0.17** (angr 0.586). type is beaten, GED
is near; byte is the gap, and it needs the value-model refactor below.

## Top 5 projects (by leverage)

1. **SSA value model** — name & type by SSA value, not physical register. The
   keystone: a reused register becomes distinct typed variables; a parameter is
   the arg register's SSA entry-def; spill slots unify with their source value.
   Unblocks byte_match (register-reuse codegen), O2 register args, and deletes
   most of the naming/typing glue (`remap_type_map`, the `DEC_PTR_ARGS` cast).
2. **Constraint-based type inference (Retypd/TIE-lite)** on top of #1 — type
   variables + constraints (copy=equality, deref=pointer, arith=width), solve by
   union-find, **split on conflict, never int↔ptr**.
3. **IR optimization passes** — copy-prop + dead-store (DONE, `ir/copy_prop.rs`);
   next: const-prop, redundant-load elimination, broader DCE.
4. **Unified structuring engine** (DREAM condition-based + SAILR de-opt) —
   replaces the pattern-by-pattern `structure.rs`; needed for `statemachine`
   (switch-in-loop, multi-exit) and real `switch` clustering.
5. **Structured variable / typed-IR output model** — emit `VariableInfo`
   (name/type/size/stack_offset/arg_index/kind), render from that; strictly
   better DecBench scoring + the evidence-retention/LLM-refine substrate.

Sequence: **#3 → #1 → #2 → #5**, with **#4** alongside.

## #1 SSA value model — staged plan (from design analysis)

Pipeline today (`python_bindings/ir.rs` `decompile_*`): `lower()` drops the
already-computed `SsaInfo`, so everything downstream (`naming::apply_role_names`,
`types_recover`) is keyed on the physical-register **string** — one register =
one name = one type. That is the register-reuse bug.

`SsaInfo` (`ir/ssa.rs`) already has `def_versions[InstrAddr]` and
`use_versions[(InstrAddr, use_idx)]` — value identity is `(base VReg, version)`.
Gap: `rename` starts versions at 0, so a live-in param (v0) and the first scratch
def (also v0) collide. Fix = seed an entry-def v0 and start the counter at 1.

- **Stage 0** (XS): SSA entry-defs (`ir/ssa.rs` `rename`/`new_version`). No metric
  change; prerequisite for later stages.
- **Stage 1** (S–M, the byte_match mover): `ir/value_split.rs` —
  `split_spilled_arg_reuse`, run before `apply_role_names`. Uses the -O0 spill
  invariant: once an arg register is spilled to its frame slot, every later use of
  the raw register is scratch, so rename post-spill occurrences to a fresh local
  (folds to `varN`). Gated on "is spilled" so -O2 register-resident params are
  untouched. type/GED unchanged (only scratch renamed); fixes `arg2 = ret`
  (int↔ptr lvalue) that the render-time cast can't. Supersedes `DEC_PTR_ARGS`.
- **Stage 2** (L): value-tagged lowering — thread `SsaInfo` into `lower`, rewrite
  version≥1 occurrences to value-tagged names; coalesce by default (only split
  versions with type-incompatible uses) so GED doesn't fragment.
- **Stage 3** (M): per-value naming replacing `apply_role_names`.
- **Stage 4** (L): per-value typing, **delete `remap_type_map`**; risk to
  type_match — do last, diff per-program.
- **Stage 5** (M): spill-slot home unification (bidirectional type flow).

Safest path: ship Stage 0 → Stage 1, measure, then 2–4 behind a per-program
type_match guard. Validation: `cargo test` + `/tmp/claude-1000/local_eval.py`.

## byte_match: empirical divergence analysis (2026-07-23)

Recompile our C at the original's `-O0` and diff assembly to find the drivers:
- **Parameter spill duplication** — FIXED (`coalesce_param_spills`): we emitted
  `local_X = argN` and used the slot, adding a param→slot copy the compiler never
  makes. `sum_to` now recompiles byte-IDENTICAL. byte 0.169→0.192.
- **Array-access idiom (the pointer-function class: arrays/matrix/sort/strops/
  linkedlist/structs, ~0.12–0.23).** `s += a[i]` lowers to
  `t0 = i*4; ret = (long)a + t0; *(int*)ret` across statements with `(long)`
  casts; the compiler emits `cltq; lea 0x0(,i,4),%rdx; add a; mov (%rax)`. To
  match, need: (a) expression propagation to fold the single-use address temps
  into one `*(int*)((long)a + i*4)`, then (b) render it as `a[i]` (typed pointer
  indexing) instead of the byte-offset form — which lets the compiler use its own
  scaled-addressing idiom and drops the `(long)` casts/`cltq`. This is the next
  concrete byte lever (medium effort: expr-prop pass + array-index render).
  NOTE (attempted): a *global* single-use guard for expression propagation does
  NOT fold this chain — the address flows through `ret`, which is reused every
  loop iteration (multi-use globally). Folding needs **local** single-use
  analysis (def to next redefinition within a run), i.e. inline `t = i*4` and
  `p = base + t` at their single next-statement use before `ret` is reassigned.
  That is the correct (more careful) implementation; the global version was
  insufficient and churned render goldens, so it was reverted.
  UPDATE: a local-single-use forward-substitution pass was prototyped and
  produced a CORRECTNESS BUG on the reused-register (`ret`) chain — it dropped
  the address computation, so `a[i]` decompiled as `a[0]` (caught only by
  diffing recompiled assembly). Reverted. Lesson: ad-hoc AST value-folding over a
  register reused across iterations is unsafe; the address-idiom / expr-prop work
  must be done on the **SSA value model** (Stage 2 value-tagged lowering), where
  each `ret` version is a distinct value, not by an AST rewrite that cannot tell
  the versions apart. byte parity therefore depends on Stage 2, not a render hack.
- Deeper: `cltq`/sign-extend and 64-bit ops from our `long`-typed intermediates;
  local→local redundant copies (`local_14 = local_10`) copy-prop doesn't fold
  (it only handles register copies, not promoted-local value numbering).

## Progress log
- IR opt passes (#3): copy-prop + dead-store `ir/copy_prop.rs` — DONE.
- Render width/casts (bridges to #1/#5): load-width casts + pointer-arg
  int/pointer reconcile — DONE (byte 0.130→0.17).
- #1 Stage 0: DONE (bb96f61). Stage 1 (value_split.rs): DONE — splits post-spill
  arg-register scratch reuse into varN. Metric-neutral now (the DEC_PTR_ARGS cast
  already made it compile); value is architectural (foundation for stages 2-5,
  which remove the cast + match codegen for the real byte_match gains).
