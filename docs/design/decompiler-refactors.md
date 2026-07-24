# Decompiler foundational refactors (roadmap)

Status tracking for the "big" refactors that keep surfacing as workarounds in the
DecBench parity work. Current metrics on the local 14-program corpus (gcc -O0,
`/tmp/claude-1000/local_eval.py`): **type_match 0.891** (angr 0.819),
**GED 7.16** (angr 7.59), **byte_match 0.366** (angr 0.586). type and GED both
beat angr; byte is the remaining gap.

Note (eval env): the harness shell now sets `FORCE_COLOR=3`, which makes rich
emit ANSI codes even in captured subprocesses, so `local_eval.py`'s metric regex
sees `\x1b[..m2.00` and scores everything nan. Run the eval with `NO_COLOR=1`
(and `unset FORCE_COLOR`) — not a decompiler bug.

Update (#2 array-index render, LANDED): a T-sized deref through
`base + i*sizeof(T)` where `base` is a declared `T*` now renders `base[i]`
(drops the `(long)` cast + explicit scale; gcc re-emits its own scaled
addressing). sum_array's loop recompiles instruction-identical to the original.
byte 0.349 -> 0.366 (arrays .39->.47, matrix .51->.58, sort .27->.37); type/GED
unchanged.

Update (value model #1, first wave): the address-chain fold now lands. Splitting
reused lifter temporaries by SSA version + keeping only the *returned* value's
return-register version bare makes the loop address scratch and single-def, and
folding a trivial `Lea` into its single-use deref reassembles `t=i*4; p=base+t; *p`
into `*(base+i*4)` — so gcc -O0 re-emits register-only scaled addressing instead
of spilling/reloading `t` and `p` (byte 0.277->0.349, verified by recompile diff).
Signature arity + return type are now value-keyed (recovered from the type map /
returned value, not surviving body text), which recovered args/returns that DCE
had dropped (type 0.879->0.891). Strict improvement on all three metrics.

Update (value-model landing): SSA value-numbering is now wired into the decbench
lowering path (each reused register becomes a distinct SSA value). That unblocked
a **safe single-use expression fold** (copy_prop) — distinct values are single-def,
so folding `t = i*4; p = base + t; *p` into `*(base + i*4)` duplicates no work and
lets the compiler re-emit its own scaled-addressing idiom: byte_match 0.192 -> 0.277,
GED 8.65 -> 7.25. The fold carries a store/push aliasing barrier so a load is never
moved across a write. Value-numbering initially cost type_match (0.861 -> 0.794)
because a spilled pointer arg, used only as `*(param + i*scale)`, lost its pointer
type; recovered (and pushed past baseline to 0.879) by back-propagating pointer-ness
through the address `add`, identifying the base by frame-slot-reload / scaled-index
structure rather than by (default) type. See the three `ir:` commits on this branch.

## Top 5 projects (re-prioritized 2026-07-23, after the value-model landing)

The re-ranking is grounded in the walls hit while landing value-numbering: every
one was the *same* wall — name, type, return-ness, and render are each decided by
a separate heuristic pass that string-matches physical-register / role names, and
those passes collide (the int→long return regression from `ctype_for("ret")`, the
`max_ret`/KeepBare thrash, the `DEC_PTR_ARGS`/`remap_type_map` casts, the four
heuristic pointer passes in `types_recover.rs`, the fold not firing on `var5`).

**Already landed** (was old #1/#3): SSA value model stages 0–2 (`ssa.rs` entry-def,
`value_split.rs`, `value_number.rs`) + IR opt passes (copy-prop, dead-store,
single-use fold with aliasing barrier) + partial per-value pointer typing.

1. **Value-keyed variable model** (keystone; = old #1 naming/typing half + old #5).
   One `VariableInfo { name, type, width, storage, role }` per SSA value, decided
   *once*; naming, typing, return-detection, and render all read from it. Deletes
   the collision-prone string passes: `remap_type_map`, `DEC_PTR_ARGS`,
   `apply_role_names` string-matching, the `max_ret`/KeepBare heuristic,
   `ctype_for("ret")`'s default-long, `find_written_return_reg`. "Is this the
   return value / a pointer / scratch" becomes a value property, not a name lookup.
2. **Expression re-materialization + typed-pointer render** (the byte closer). Sink
   single-use value-expressions into their use site and render
   `*(T*)(base + i*sizeof(T))` as `base[i]`. Replaces the ad-hoc `copy_prop` fold;
   kills the measured byte driver (temps materialized as `long` locals that gcc
   -O0 spills+reloads, ~4 extra insns/iter). Needs #1's value identity to be safe.
3. **Constraint-based type inference (Retypd/TIE-lite)** on #1 — type variables +
   constraints (copy=equality, deref=pointer, arith=width), union-find, **split on
   conflict, never int↔ptr**. Subsumes the four heuristic pointer passes in
   `types_recover.rs` (ends the special-case treadmill).
4. **Lifter correctness for aggregate/struct access** (NEW; upstream of the value
   model). `dist2`/`rect_area` lower `a->x - b->x` as `arg0 - arg1` and read stack
   locals before defining them — caps `structs` at type 0.25 / byte 0.36 no matter
   what runs downstream. A correctness smell, isolated + testable, orthogonal to #1.
5. **Unified structuring engine** (DREAM condition-based + SAILR de-opt) — replaces
   pattern-by-pattern `structure.rs`; the GED outliers `statemachine` (35) and
   `switch_jt` (42) dominate the mean. Lower priority now (GED already beats angr)
   but it is the robustness story for real, non-toy binaries.

Sequence: **#1 first** (multiplier — 2/3/beyond get simpler + safer on top of it),
with **#4 in parallel** (independent, unblocks `structs`). Then **#2** (byte jump),
**#3** (retire pointer heuristics), **#5** (real-binary robustness).

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
- #1 Stage 2 (value-tagged lowering): DONE — `value_number` wired into the decbench
  render path, keeping structural + return regs bare. Enabled the single-use fold
  (copy_prop) that reassembles split address chains: byte 0.192→0.277, GED 8.65→7.25.
- #1 Stage 4 (per-value pointer typing, partial): DONE — `types_recover`
  back-propagates pointer-ness through address `add`s (frame-slot-reload / scaled-index
  base identification), recovering spilled pointer args used only as `*(param + i*scale)`.
  type 0.861→0.879 (beats angr). Still ad-hoc, not yet the full Retypd/union-find (#2).
- Remaining byte gap drivers (byte 0.277 vs angr 0.586): struct-field access idiom
  (`dist2`/`rect_area` still mis-lift `a->x` vs `arg0-arg1`; pre-existing, not value-model),
  and residual `long`-typed 64-bit intermediates forcing `cltq`/sign-extend the compiler
  wouldn't. Next: array-index render (`a[i]`) + struct-field recovery.
