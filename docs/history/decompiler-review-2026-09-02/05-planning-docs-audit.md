# 05. Planning documents audit

> **Kind:** record · **Date:** 2026-09-02

What the 24 planning documents under `docs/design/` and `docs/development/`
have already decided, tried and abandoned, so that the recommendations in
06-recommendations.md neither repeat a dead end nor re-propose something that
is already scheduled. Read on 2026-09-02; symbol claims were checked with a
grep of `src/`.

## 1. Per-document gist

**`docs/design/README.md`.** The index. Two live documents (the roadmap and
the newest diary); everything else is evidence. Phase blocks are views of EPIC
blocks (193 checkboxes, about 70 items); `[x]` requires a production caller;
do a capability census before a modelling theory.

**`docs/design/decompiler-roadmap.md`** (3,301 lines; header 2026-08-13, last
git touch 2026-08-19; baseline `fb4ee6b`). The single tracker. Thesis: one
semantic spine, `ProgramSession` -> lifted IR -> verified MIR / MemorySSA ->
HIR -> pure renderers. Five EPICs, Phases 0-8, fitness program, performance
plan, Appendix A (DecBench). Counted: 66 `[x]`, 49 `[~]`, 78 `[ ]`, 3 `[r]`.
Facts inside: MIR built on zero production decompiles; 0 of 7 consumers
migrated; no HIR exists; renderer has 9-16 `DEC_*` thread-locals; object
parses per session 58 -> 19; per-binary median 0.022 s, p95 2.15 s; ARM32
worst lane at 24.8% failure vs x86-64 12.9%; fitness moved `ast.rs` 11,582 ->
1,650 product LOC, 7 of 9 measures met. DecBench PRs #56 / #61 / #62 merged
upstream 2026-08-14.

**`decompiler-next-implementation-directive.md`.** Pre-August task list: CI
`maturin` provisioning, copy-chain folding out of the renderer, def-before-use
verification, register-view descriptor, classify `mul_widen` / deposit /
`sum_argN`. Baseline then 117 pass / 284 fail. Largely done.

**`decompiler-rearchitecture-2026-08-06.md`.** "Do not rewrite." P0-P6:
fail-closed evidence, composition seams, `ProgramEnvironment` /
`MachineModel`, typed MIR + `DefinitionOracle`, `StorageGraph`, total region
recovery, then perf and deletion. Proposed module map `src/decompile, program,
machine, mir, recovery, control, hir, render`. P1 seams and the MIR verifier
landed; P3-P5 consumers did not. `src/decompile/` today holds only
`profile.rs`.

**`glaurung-architecture-redesign-2026-08-05.md`.** The founding review. Same
spine, ten design rules, `AnalysisArtifact<T>` with `Completeness` as a set of
reasons, `TargetSpec`, three IR layers, `ProgramEnv` `Fact<T>` with provenance
and authority, contextual `ReferenceInterpretation`, aggregate constraint
solver, pass manager, ownership map, size targets. Absorbed into the roadmap.

**`decompiler-refactors.md`** (2026-07-25). Early metrics on a 14-program
corpus: gcc/O0 GED 5.99 vs angr 7.59, type 0.873 vs 0.819, byte 0.323 vs
0.586. Top-5 projects: value-keyed variable model, expression
rematerialisation + `base[i]` render, Retypd / TIE-lite constraint typing,
struct-access lifter, **unified DREAM / SAILR structurer**. Two reverted
expression-propagation attempts. Projects 3 and 5 were never built.

**`dormant-transforms-2026-08-12.md`.** The original attempt / fire table was
never produced by any run. Re-measured 2026-08-15 over 754 objects:
`recover_owned_pretested_do_while` 21 fires; `recover_guarded_do_whiles`
0 / 5,580; `recover_sentinel_search_loops` 0 / 2,790. Open decision: retire or
repoint.

**`value-model-root-cause-and-plan.md`** (2026-07-26). `VReg` is five things
at once (identity, storage, width, role, kind). A ~25-cell GED regression was
bisected to the loop `while(1){pre; if(!cond) break}` fallback. "Do not
attempt a fourth predicate." Phases: gate visibility, one pipeline,
`ValueId` + `MachineSort` with phis as instructions, typed predicates, region
ownership as a computed partition, delete the compat layer. Phases 0-1
substantially done; 2-5 open.

**`typed-ssa-hlir.md`.** Confirms four critiques (SSA is a sidecar; types
keyed on register strings; `remap_type_map` cannot map `varN`; AST lowering
drops SSA identity). Phases 1-2 landed (`TypeMapV`, multi-return join).
Phases 3-4 (delete `value_number` string mangling, delete `remap_type_map`)
not done: `remap_type_map` has three production callers in
`src/python_bindings/ir.rs`; `tag_phys` remains in
`src/ir/value_number/tagging.rs`.

**`semantics-preserving-structuring.md`.** Root causes: edges not first-class,
tree-matcher structurer with a `visited` set, under-typed widths, no stage
contracts, four entry points. Prescribes typed `EdgeKind`, a **total**
structurer (block and edge coverage, shared join once, honest goto fallback),
verifier-first, and **the new structurer behind a flag with shadow mode**.
Typed edges, accounting and the verifier landed; the structurer and shadow
mode never started.

**`register-views-and-the-verifier-boundary.md`.** Landed: `regview.rs` as the
single descriptor, `prepare_for_decbench` split from rendering,
`verify_defs`, `partial_alu_ops`, `slot_stores_to_assigns`,
`stack_arg_layout`, `Stmt::Call { dst }`. Open: `Op::Call` destination at
LLIR level (about 60 references, 19 files, touches `src/symbolic/`).

**`decompiler-roadmap-diary-2026-08-31.md`.** Full pinned run: 803 binaries,
94,575 functions, 217 missing bodies fully classified. Size curve: compile
84.6% at 25-49 lines to 36.2% at 500-999. Structural baseline is GCC -O0 only.
`perf_gate.py` had no baseline and failed open. "Adding an LLM is not a
response to this evidence."

**`ged-recovery-measured-trade.md`.** Always-hoist recovers 50.32 GED points
(46%) and returns wrong answers in 4 functions / 6 cells. Strictly
experimental, do not merge.

**`decompiler-ux-competitive-ranking.md`** (2026-08-28). 18-row scorecard vs
IDA / Ghidra / angr. Leading: rename reaching call sites, prototype-driven
signature, enforced 7-value provenance, cross-table undo. Missing:
line-to-address map (the number-one gap, needs `Stmt::Origin` across 182 match
sites), struct-apply, split / merge, per-call-site prototype override, code
labels, equates, lock bits.

**`docs/development/decompiler-roadmap-package-2026-08-31.md`.** Entry point
for R0-R8. R8 (test integrity) status 2026-09-01: silent gates fixed, canary
corpus in `cargo test`, never-executed 271 -> 0, perf gate fails closed, 1,162
xfails.

**`large-function-plan-2026-08-31.md`.** L0 telemetry, L1 `@large` ladder, L2
production shapes, L3 eight terminal failure classes, L4 ratchets, L5 fix
order. All open.

**`optimized-structural-quality-plan-2026-08-31.md`.** Structural baseline
2,253 rows / 751 functions / 37 predicates, GCC -O0 only. Sequence A-F.
Readability census done (3,580 rows, 85 switches, 4,604 gotos, 545 breaks);
dispatch relaxation reverted (+162 gotos / -37 breaks); lane-keyed closure
open.

**`performance-determinism-ratchet-plan-2026-08-31.md`.** The plan originally
listed fail-open gaps P1-P10. `bench/perf_baseline.json` exists (3 references),
and commit `4f4f88e3` plus `test_perf_gate_fails_closed.py` closed the missing-
baseline, unit-mismatch, and partial-measurement exit-status gaps. Provenance,
RSS, output identity, body completeness, tail behaviour, and unified release
reporting remain open.

**`real-binary-decompiler-roadmap-2026-08-31.md`.** Product order R0 inventory
-> R1 missing bodies -> R2 large -> R3 O2 structure -> R4 PE / PDB / Mach-O ->
R5 hostile assets -> R6 perf -> R7 breadth. Non-goals: no LLM for benchmark
columns, no DecBench bodies as fixtures, no byte-match at fidelity's expense.

**`decompiler-parity-backlog.md`** (2026-08-31). Three-way diagnostic vs angr
9.3.3 / Ghidra 12.1.3: Glaurung leads on types and fidelity, trails on
readability and naming. Landed: #1 symtab OBJECT names, #2 `cmp_fusion`, #5
`named_constants`, #7 `compare_decompilers.py`. Open: #3 variadic arity, #4
(re-ranked after both candidate fixes were rejected), #6 `char **`, #8 O2
structural baseline, #9 page-align guard, #10 pinned oracles.

**`decompiler-test-strategy.md`.** Items 1-5 built (C++ runtime 56% fail,
systems / ABI 43%, metamorphic lane live). Open: producer matrix (-O1 / -O3 /
-Os / LTO / hardening), csmith, `llvm-cov`. Out of scope: RISC-V, big-endian,
Rust, Go, adversarial.

**`decompiler-testing.md`.** The command ladder. Key finding: the published
leaderboard row (11th of 13 at 0.09%) is a coverage artefact, the same 82
perfect functions over 94,267.

**`decbench-full-score-audit-2026-08-30.md`, `decbench-submission-readiness.md`.**
Scores are in 04-defect-inventory.md section 4. The readiness doc (2026-08-02)
still says "not merged, do not submit"; the roadmap records the merges.

## 2. Proposals made and never implemented

| proposal | source |
|---|---|
| Semantic HIR (`src/ir/hir/`), pure renderers, `&RenderCtx` replacing `DEC_*` thread-locals, one visitor / rewriter trait (now 558 `Stmt::If` match sites) | redesign 08-05, rearchitecture 08-06, roadmap Phase 7 |
| MIR as production authority: `DefinitionOracle` consumer migration (0 of 7), target-owned clobber sets, transactional graph editing, memoised `value_at` | roadmap EPIC 5 / Phase 3 |
| Opaque `ValueId` + `MachineSort`, phis as instructions, delete `value_number` string mangling and `remap_type_map` | value-model Phase 2, typed-ssa-hlir Phases 3-4 |
| Typed predicates (`FlagEffect` total, `BoolId`, provenance rendering); `cmp_fusion` is an AST-level partial substitute | value-model Phase 3 |
| Region ownership as a computed partition; **total structurer behind a flag with shadow mode**; `Return` region node; exceptional edges reaching the structurer | semantics-preserving section 6, value-model Phase 4, roadmap Phase 4 |
| Retypd / TIE constraint type inference; recursive pointee in `TypeHint` | refactors #3, parity #6; roadmap: "no constraint type, no solver" |
| Unified DREAM / SAILR structuring engine | refactors #5 |
| Exact-width constants (`Value::Const` width, 579 sites); operand provenance | roadmap Phase 2 |
| `enum PipelineStage` + pipeline fingerprint; persisted artefacts with dependency fingerprints; function-parallel scheduling; `invalidate_function(va)`; cancellation and memory budget on the decompile path | roadmap Phases 1 / 8; grep: 0 hits |
| ARM32 completeness: VFP s/d/q overlap in `regview::Arch::Arm32`, `d0..d7` slots, 64-bit pairing, NEON, LDM / STM writeback, LDREX / DMB / SVC | roadmap Phase 2; `regview::Arch` is still `{ X86_64, AArch64 }` |
| PDB into `TypeStore`; FLIRT through evidence policy; `TypeStore` reader; xrefs / call graph / UI on `ReferenceResolver`; vtable / RTTI as objects; delete 14 legacy recognisers | EPIC 1 / 2, Phase 5 |
| Aggregate parameter side, `HiddenReturn` consumer, pointee classification, HIR `Index` / `Field`, array element count | EPIC 3 / Phase 6 |
| `Op::Call` destination at LLIR level | register-views section 4 |
| Line-to-address map (`Stmt::Origin`), struct-apply, split / merge, call-site prototype override, code labels, lock bits | UX ranking section 4; `Stmt::Origin` 0 hits |
| Parity #3, #4, #6, #8, #9, #10 | parity backlog |
| F1b scoring disposition, F1c validator, F1d trace, `@large` ladder + L0 telemetry, structural schema v2 lane keys, perf-gate P2-P8, PE32 / PE32+ / Mach-O semantic lanes, inventory `--check`, R8.4 / R8.5 | the 2026-08-31 plans |
| Producer matrix, csmith, `llvm-cov`; linked-structure argument kind for the harness; a readability metric defined before goto trades | test strategy, dormant transforms, roadmap `[ ]` |

## 3. Tried and rolled back, or judged a bad trade

| what | result | source |
|---|---|---|
| Always-hoist loop recovery | +50.32 GED, 4 functions wrong in 6 cells; `[r]` | `ged-recovery-measured-trade.md` |
| Goto sinking | -11% gotos, `statemachine:gcc:O0` GED 10 -> 35, -5 byte-match cells; `[r]` | roadmap "Measured cautions", `goto-density-measurement-2026-08-12.md` |
| Late table-layout patch for indirect calls | plausible, well-typed, wrong arguments; `[r]` | roadmap "Function contracts" |
| Global single-use expression propagation; local forward substitution | first churned goldens without folding; second turned `a[i]` into `a[0]`; both reverted | `decompiler-refactors.md` |
| Pointer-dominant return-type join | changed 20 of 223, regressed correct `int`, invented pointers for `void`; replaced by an exact-compat rule | `typed-ssa-hlir.md` |
| Hoist predicates (invariance, use-count) | each broke `find_first_set` or the `loops` family; keep `3ef32ae`, no fourth predicate | `value-model-root-cause-and-plan.md` |
| "Both arms must forward-reach the join" structuring fix | findings 3 -> 9 | value-model section 1.3 |
| Patching `has_loop_conditional_with_join_beyond_loop` | tried twice, reverted twice; "any redesign must grow the region algebra first" | `decbench-defect-reproductions-2026-08-27.md` section 3.4 |
| `flags-architecture` branch `06579df` | rehearsal only | value-model Phase 3 |
| `agent/stack-bias` affine-index branch | deleted 2026-08-19: capability already on master; 0 of 79 divergences show the pathology | roadmap Phase 6 |
| `NESTED_CALLEE_DEPTH=2` | 1,457 functions byte-identical; reverted | roadmap perf plan |
| MIR frame-extent join as the first aggregate consumer | 3,803 of 3,823 identical, 20 weaker, +10.4% cost; "not a migration" | roadmap Phase 6 |
| Separating AArch64 `x0` from `v0` / `d0` / `s0` | regressed `175:aarch64:O0:dot_product_f32`; collapse kept | roadmap EPIC 3 |
| Dispatch-loop relaxation (`detect_raw_dispatch_loop`) | +162 gotos / -37 breaks; reverted | optimised plan, package |
| `fold_one_call` `read_between` relaxation (parity #4) | differential +2 / 0, but undefined reads about 4x (gcc:O0 124 -> 536); reverted | parity backlog |
| `cmp_fusion` v1 (cast peeling) | changed a 64-bit condition to 32-bit; 11 lanes red; fixed with an equal-width rule | parity #2 |
| Block-scope `static` global definition | byte match 0.192 vs 0.266 for in-body `extern`; rejected | readiness (2026-08-02) |
| Raising fixture parallelism | recorded a fake regression (`561e08f`) | roadmap |
| AArch64 `fmadd` as an intrinsic | broke `217_complex_arithmetic:aarch64:O2`; reverted | `test_macho_lane.py:145` |
| Adding an LLM to improve a deterministic benchmark column | explicit non-goal | real-binary roadmap, diary Entry 1 |

## 4. Current stated priorities

R0 inventory authority -> R1 missing-body identity -> R2 large functions ->
R3 O2 structural quality -> R4 PE / PDB / Mach-O -> R5 hostile assets -> R6
fail-closed perf and determinism -> R7 breadth; R8 test integrity underneath
(`decompiler-roadmap-package-2026-08-31.md`). CLAUDE.md's active frontier:
control-flow structuring, type-aware re-render, Windows port, analyst
ergonomics, LLM vuln substrate. The roadmap's own top of queue (2026-08-17/19):
the all-SSE parameter class, `SILENT_REGISTER_WRITERS` (28 mnemonics / 1,130
occurrences: `syscall` 310, `movsb` 242, `aesenc` 222, `movsq` 134), and
float-bits reinterpretation.

## 5. Contradictions and stale claims

1. **Two live plans.** `docs/design/README.md` names the roadmap as the
   tracker; it has not been edited since 2026-08-19 and its "Current state" is
   `fb4ee6b`. The 2026-08-31 package says the product order lives in
   `real-binary-decompiler-roadmap-2026-08-31.md`. The EPIC / Phase queue (MIR
   migration, HIR) and the R0-R8 queue (identity, large, PE) are different
   work lists and neither references the other's ranking.
2. **Readiness is stale on submission state.** `decbench-submission-readiness.md`
   (2026-08-02) says "not merged, do not submit"; PRs #56 / #61 / #62 merged
   2026-08-14.
3. **`typed-ssa-hlir.md` Phase 4 claims deletions that did not happen.**
   `DEC_PTR_ARGS` / `DEC_PTRS` are gone (absorbed by `declaration_plan.rs`),
   but `remap_type_map` and `tag_phys` remain.
4. **Memory SSA.** `typed-ssa-hlir.md` section 2.3 declares it a non-goal; the
   roadmap ticks region-aware MemorySSA `[x]` as a sidecar with no consumer.
5. **`semantics-preserving-structuring.md` section 5 says to extend
   `src/ir/verify.rs`**; that file has been uncompiled since 2026-08-12.
6. **`decompiler-middle-architecture.md` section 2.6** says there is no
   indirect-jump terminator; `Op::IndirectJump` and `cfg_edges::EdgeKind` now
   exist. Section 2.1 ("arithmetic lacks explicit width") is still true.
7. **`decompiler-testing.md`'s "What it currently measures" table** (i386 59%,
   AArch64 34%, ARMv7 39%, "30-fixture corpus") is a very old snapshot;
   `arch_baseline.json` has 2,472 lanes.
8. **Bare `cargo test`** appears in `glaurung-architecture-redesign-2026-08-05.md`
   and `typed-ssa-hlir.md`; CLAUDE.md corrects this to `--features
   python-ext`. `large-function-plan` uses `-m ""` for the census, which
   CLAUDE.md (2026-08-31) says is unnecessary.
9. **Size numbers in older docs are all stale**: `ast.rs` 15,739 (08-06) vs
   9,710 physical lines today.
10. **F2a Cortex-M `MRS` / `MSR`** is listed as "next" in every 2026-09-01
    update and landed in `0031c3ee` and `b84ed29b`.
11. **`HiddenReturn`**: the roadmap says producer and no consumer;
    `types_recover.rs:1037-1043` now constructs and matches it. Whether a real
    consumer exists is not verifiable from the docs.
12. **`prepare.rs`'s doc comment says "These nineteen steps"**; the body
    invokes about 62.
