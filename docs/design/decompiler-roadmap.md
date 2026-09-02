# Glaurung decompiler and binary-analysis roadmap

**Status:** canonical consolidated roadmap

**Last updated:** 2026-09-02

**Planning baseline:** Glaurung `fb4ee6ba5966e0e4a7fe001b523231fc5fcd43f4`

This file consolidates the architecture review, DecBench gap analysis, repair
campaign, branch audit, IR redesign, ARM work, type and aggregate work, code-size
goals, performance plan, and benchmark-submission checklist into one ordered
plan. The dated diaries remain the evidence log; this is the place to decide
what comes next.

The central conclusion is unchanged:

> Glaurung does not primarily need more isolated AST heuristics. It needs one
> semantic spine connecting program-wide evidence to verified per-function
> values, memory effects, objects, types, control flow, and source rendering.

The migration must remain incremental. Each phase must deliver a usable,
tested improvement; “architecture work” is not permission to stop fixing real
decompiler defects.

## How to use this roadmap

Status markers:

- `[x]` is implemented, CONNECTED TO A PRODUCTION CALLER, and has specific
  evidence. "Implemented" and "connected" are different claims and this document
  has conflated them at real cost: `SymbolStore` was ticked while every caller
  lived in `session_tests.rs`, `RecoveredOutputKind::HiddenReturn` was matched in
  three places and constructed in none, and a whole width-propagation cluster in
  `ast.rs` was reachable only from its own tests. A box does not tick until
  something in the shipping pipeline asks it a question.
- `[~]` is partially implemented or implemented only as a diagnostic sidecar.
- `[ ]` is open.
- `[!]` is blocked by a prerequisite or known unsafe approach.
- `[r]` is a measured, rejected approach that must not be revived unchanged.

When an old score or revision appears in an evidence document, treat it as
historical unless this file calls it current. Product correctness, local metric
results, the PR branch, and the public leaderboard are separate states.

### Two tracks, judged differently

Work here divides into two kinds that were previously interleaved, competing for
the same slots. They are not equally urgent and they cannot be measured the same
way, so mixing them made the correctness work look like progress and the
architecture work look stalled, when in fact the second was simply losing every
scheduling contest to the first.

**CORRECTNESS.** Success is fixture cells moving from `fail` to `pass`, or a
census of a defect class going down. Fast feedback, days not weeks. A change here
that moves no cells needs an argument.

**ARCHITECTURE.** Success is a boundary that holds — a narrower API, one reason
to change, a capability something else can now be built on. A change here is
*expected* to move zero cells, and must be justified by what it unblocks rather
than by output quality. A change here that moves cells is a pleasant surprise,
not the reason it was done.

Judge each by its own standard. An architecture item that has to promise cell
movement to get scheduled will be over-sold, and a correctness item asked to
justify itself architecturally will be blocked on a refactor it does not need.

**The evidence for taking this seriously.** Across 2026-08-13..16 the changes
that moved fixture cells were, almost without exception, MISSING CAPABILITIES
rather than migrations: AArch64 had no scalar floating-point lifting at all,
i386 had no x87 at all, ARM32 dropped an entire modified-immediate family, and
`call *(mem)` lifted to a fabricated call to address zero. None of those four
appeared anywhere in this document. Meanwhile two migrations that this plan
treats as central were built and measured and returned nothing — the aggregate
MIR consumer join reproduces what `stack_locals` already computes, and the alias
barrier needed no MIR at all because 72% of its cases were provable from data the
AST already carried.

That is not an argument against the architecture track. It is an argument for
stating plainly that the two are different bets, so that neither one is judged by
the other's yardstick.

### Capability census: check for whole missing categories first

Before attributing a cluster of failures to a deep modelling gap, check whether
the capability exists at all. Three whole missing categories were found in three
days by one cheap technique: grep the lifters for an ISA's mnemonic families and
diff that against what the corpus actually emits.

    grep -c "fadd\|fmul\|fdiv\|scvtf\|fcvtz" src/ir/lift_*.rs
    objdump -d <fixture object> | grep -oE "\bf[a-z]+\b" | sort | uniq -c

`039c7d6`, `f1a6e4c` and `dcc62aa` were each found this way, and each looked like
scattered unrelated fixture failures beforehand. This belongs in a standing test,
not in institutional memory.


### The plan double-counts itself — read the Phases as views, not as work

Audited 2026-08-15. The document has 193 checkboxes, of which 118 were open. That
is NOT 118 distinct pieces of work: **the Phase blocks are largely a second view
of the EPIC and topic blocks**, sequenced by delivery order rather than by
subject. The same item is routinely open in two or three places:

| item | appears as |
|---|---|
| `FunctionFacts`/`CallFactStore` + SCC propagation | EPIC 1, Phase 4, Phase 5 (and the Performance-plan SCC box) — all four moved together 2026-08-15 |
| Aggregate classification (arrays/structs/unions/bitfields) | EPIC 3, Phase 6 |
| Semantic HIR + pure renderers | HIR block, Phase 7, Foundations |
| ARM32 A32/Thumb/PC/VFP/ABI completeness | EPIC 4 (twice), Phase 2, Foundations |
| One object parse per session | Performance plan, Phase 1 |
| Terminal/indirect/switch/exception edges | CFG block, Phase 4 |
| PDB import into the canonical store | EPIC 1, EPIC 3, Phase 5, Foundations |
| Delete legacy recognizers after parity | EPIC 2, Phase 5, Phase 7 |
| Performance targets | Performance plan, Phase 8 |

Roughly 70 distinct items, not 118. Two consequences worth stating, because both
have already caused mistakes here:

**Progress must be recorded in every view.** Landing a thing and ticking one box
leaves the plan claiming it is undone, and a reader who trusts the count
concludes less has happened than has. Several boxes were found already satisfied
by work committed days earlier and never ticked.

**A percentage-complete figure over these boxes is not a measure of progress.**
Closing one real item can move zero, one, two or three boxes depending only on
how many views happen to mention it. Cite what was closed and what it was
measured against; the ratio is bookkeeping, not evidence.


## Current state

### Active 2026-09-02 review execution package

The detailed implementation specification is
[`docs/review/decompiler-2026-09-02/PLAN.md`](../review/decompiler-2026-09-02/PLAN.md).
This roadmap remains the single status authority; the package supplies exact
files, tests, dependencies, effort bands, and stop conditions. Capability work
(shadow structuring, typed indirect targets, and two narrow render idioms) is
scheduled independently of the longer pipeline/SSA migrations.

- [x] **WP0 minimal inventory and gate integrity.** From the pinned baseline
  `e55576bc4612` through implementation revision `7aec4e842fa1`, the
  strict-xfail inventory has gained raw C/Rust totals and provenance-normalized
  totals derived from its measured rows. The normalized primary denominator is
  218 type, 473 structure, 67 return, 30 unrecovered, and 4,635 goto statements;
  exact byte identity remains a separate stripped-divergence fact. The
  gcc-O2 Duff's-device constant-false live latch now has its own strict xfail,
  separate from the unresolved-indirect-jump row. The three-profile gate now
  prints its evidence denominator and fails closed when required lanes are
  missing. Focused WP0 tests, the Rust fast lane (2,792 passed), and the Python
  core lane (2,376 passed, 22 skipped, 44 expected failures) are green. The
  standalone `ty` retry could not acquire or install its executable under the
  restricted runner, so that environment-limited tail check is not claimed as
  fresh evidence.
- [ ] **WP1 bounded MIR trial.** Two-day hard cap; no competing goto-aware
  definedness implementation until the trial records a keep/delete verdict.
- [~] **WP4 total structurer in shadow mode.** The bounded `structure_v2/`
  boundary and `structure-v2-shadow` feature now observe the exact typed CFG
  used by production v1. The first condition-DAG slice is deterministic,
  truth-table checked, and runs with total block/edge coverage on the real
  `01_conditional_polarity-gcc-O0.so::sc_mixed` fixture; cyclic graphs decline
  explicitly. Natural-loop facts and an independently verified typed region
  candidate now cover the real gcc-O0 `dowhile_atleastonce` and
  `loop_return_on_neg` fixtures, including post-test, `Break`, `Continue`, and
  singly owned shared-terminal facts. A deterministic, independently verified
  `Sequence`/`If`/`Block`/`Return` tree now covers acyclic single-entry graphs
  and the real gcc-O0 `early_return` fixture. Reducible trees now add explicit
  `Loop`/`Break`/`Continue` control and exit-specific regions; both
  `dowhile_atleastonce` and the multi-exit `loop_return_on_neg` fixture pass
  independent ownership, loop-identity, and control-transfer verification.
  Irreducible SCCs now become separately owned local-labelled definitions with
  explicit entry gotos and structured exit paths. The real two-entry and
  nested-irreducible fixtures pass independent ownership, evidence,
  local-exit, and local-goto verification, while the nested case retains its
  surrounding natural loop. Bounded shared-return cleanup is also materialized
  in the tree as independently verified `DuplicatedReturn` nodes; the real
  `loop_return_on_neg` fixture contains every planned clone. Production remains
  on v1. Verified acyclic v2 trees now pass through a conservative adapter into
  the existing AST/printer: the real `early_return` fixture emits deterministic
  raw pre-pass pseudocode with a structured `if/else` and no goto. The real
  single-exit `dowhile_atleastonce` fixture now emits a proved `do`/`while` with
  its early exit rendered as `break` and no goto. The real top-level
  `two_entry_loop` irreducible fixture now emits labelled CFG for only its
  verified local region; every honest goto resolves to an emitted label and
  its structured prefix and exit paths remain present. A RED adapter experiment
  established that the old one-exit `While` could not faithfully spell
  `loop_return_on_neg`'s two exit-specific paths. An explicit `MultiExitLoop`
  region/AST node now retains those typed transfers and materializes each
  independently verified exit region at its exact branch; the real fixture
  emits deterministic `while (1)` pseudocode with both returns and no goto.
  The nested `irreducible_inside_reducible` fixture now renders its verified
  pre-tested outer loop while retaining closed, honest labelled transfers for
  the inner multi-entry SCC. This adapter path requires at least one typed
  break and proves that every break reaches the lexical continuation before
  lowering it to C `break`; otherwise it declines. The five currently
  renderable real WP4 fixtures now also record deterministic
  parseable C after the shared source-level preparation pass, all from the same
  adapted AST; each passes a real host `cc -fsyntax-only` test. The optional
  production bridge now reaches the normal typed render and verifier via
  `decompile_many(..., shadow_v2=True)` without changing the v1 default. On the
  real clang-O2 `154::wide154_dense_effects`, the guarded-switch adapter no
  longer lowers its owner block twice, verified-shadow-only recursive
  machine-frame cleanup removes nested spills, pre-render definedness is clean,
  and the exact generated C matches the original on all 34 deterministic
  differential cases. The guarded def-use baseline now also records the
  separately attributed default-v1 coverage exposed by `c7473267`'s two sound
  miniz dispatch tables and by the newly required wide-switch cell; the six
  census assertions pass without claiming that debt as a v2 win. The census
  then caught and prevented a refactor from deleting top-level spills whose
  uses were nested under control flow; a focused v1 regression now preserves
  that historical liveness contract. The independently verified host matrix
  also moves clang-O2 `rpn_evaluate` from fail to pass and removes its two
  debug/stripped unrecovered rows, while the inventory records its honest
  readability cost (3 to 12 gotos in each form). Corpus-wide
  execution/GED/runtime comparison, output measurement, and promotion remain
  open.
- [~] **WP5 typed indirect targets.** The current discovery pipeline already
  implements bounded comparison, memory/stack, power-of-two-mask, PIC-relative,
  absolute, Thumb table-branch, and ARM word-table recovery across
  `analysis/dispatch.rs`, `analysis/cfg/dispatch_resolution.rs`, and
  `analysis/jump_table.rs`; `ir/indirect_targets.rs` remains the separate
  relocation-backed single-slot resolver. The first discovery-to-shadow
  vertical slice is now explicit: the real gcc-O2 `duff_copy` mask resolves
  exactly eight ordered targets, lifting retains its normalized index, and the
  verified WP4 candidate records case values `0..7` plus the linked bypass
  edge. The independent verifier rejects forged case labels. Production v1
  still falls back honestly on Duff's shared suffix-entry loop, and the strict
  constant-false-latch xfail remains open. The clang-O2 154 wide switch now
  carries all 256 typed cases through the optional production pipeline and its
  first exact 34-case execution differential; the other named fixture lanes
  and a fresh corpus census remain.
- [ ] **WP7A immediate render idioms.** Destination-typed literals and one
  width-proved range-check fusion are independent of the SSA-native idiom lane.

### Product and submission snapshot

- Glaurung `master` and `origin/master` are at `fb4ee6b`.
- The fresh deterministic DecBench package was produced from that exact commit:
  224/224 binaries, 250/250 requested functions, zero extraction failures.
- The package SHA-256 is
  `dac9d8382828a43f918739e79be61f98935f200287886b4e5548b3ae594cd69b`.
- DecBench PR #56 points its default Docker build at the exact evaluated commit.
  The image was built with Python 3.12 and Rust 1.97.1, reports Glaurung 0.1.0,
  and records `fb4ee6ba` in `/opt/glaurung.rev`.
- **All three submitted DecBench PRs are now MERGED upstream** into
  `Noelo-Lab/decbench` (verified 2026-08-14 via `gh pr view`):

  | PR | title | merge commit |
  |---|---|---|
  | #56 | Add Glaurung deterministic decompiler backend | `08f891581e6b` |
  | #61 | fix(metrics): honor ARM function encoding in byte_match | `af02672db6dd` |
  | #62 | build(corpus): make persistent rebuild reproducible | `3db5d557a6ae` |

  This supersedes the earlier "PR #56 is open and merge-clean at branch commit
  `f4fbd607`" state. Glaurung is now an upstream backend rather than a pending
  submission, which changes what "obtain a fresh official score" requires.
- No public result or leaderboard update is implied by the artifact or the
  merges. Merging a backend is not a published score, and publication still
  requires explicit authorization.
- The current package differs from the preceding `60271f2` package in one
  generated C file, so its score must be evaluated rather than copied forward.

### Local product state ahead of the planning baseline

Committed to `master` after `fb4ee6b` (see
[the 2026-08-13 execution diary](decompiler-roadmap-diary-2026-08-13.md)):

- `4549aee` DWARF type import retains conflicting cross-unit layouts instead of
  a first-wins dedup that destroyed them, and stops inventing alignment.
- `c4a6c9d` the local gate runs the fixture lanes by default; DecBench and Joern
  are opt-in behind `--decbench`.
- `558a012` the CLI loads only the invoked subcommand, cutting ~2.9 s of
  `pydantic_ai` import off every `glaurung decompile`.
- `4caa607` function lowering runs on its own 256 MB stack. A 442-deep region
  ladder from a 256-case switch built by gcc 15 for aarch64 overflowed the
  default stack and killed the process with a silent SIGSEGV, which had made
  `arch_roundtrip.py --write-baseline` unrunnable on this host for any change.
- `8f661ff`/`d3578ad` fixture `187_constant_bias_index` plus its three
  regenerated baselines, closing the roadmap's required constant-bias lane.
- `561e08f` fixture parallelism stays at the harness default; raising it
  recorded a fake regression in a baseline.

**2026-08-16 — a day of ABI classes, renderer splits, and three gates that were
not gating.** Diary Entries 55-62.

- `7105e26` x86-64 result banks get distinct identities; `SplitBanks` gets its
  first consumer. 12 cells. An ordinary `xor %eax,%eax` had been deleting a
  `double` call result.
- `205dcfc` fixture `197_homogeneous_float_aggregates` — the all-SSE return class
  `195` left out — plus `fdbcf58` `ReturnClass::SsePair` modelling it. 11 cells
  and −15 undefined reads.
- `9cfa912` a conversion's operand is spelled at the type it HAD, not the type it
  printed as. 12 cells across host and cross lanes.
- `3b437b1` a bounded CFG walk now says so, on the function it truncated, and
  cannot mark the clean function beside it.
- `c7bd847` one logical query counted once — and `master` had been red on two
  ordinary tests for nineteen hours.
- `a792b9a`, `3c1bb91` the dec and ctx renderers out of `ast.rs`: 19,269 ->
  16,449 lines, `product_max_loc` 11,582 -> 8,762.
- `c3e92a9`, `3c4df2e` three gates that did not gate — a `cargo test` without
  `--features python-ext` in the pre-push script itself, a gate that ran only
  `-m slow` so no ordinary test could fail it, and an unconfigured `ruff` whose
  verdict could change with no commit in this repository.
- `ae36fc9` a false failure the arch gate recorded under load, discarded rather
  than committed.

### Architecture already landed

- [x] Reusable `ProgramImage` and `ProgramSession` seams exist.
- [x] All four public decompilation entry shapes share session-owned image and
  environment data.
- [x] Canonical target identity exists and is shared with the newer analysis
  boundaries.
- [x] Stable typed MIR identities exist for blocks, instructions, storages,
  values, uses, memory values, effects, objects, accesses, and cursor lifetimes.
- [x] MIR represents inputs, phis, undef, opaque effects, and unreachable
  definitions explicitly.
- [x] A conservative, region-aware MemorySSA sidecar covers stack, known globals,
  readonly image data, heap/unknown, and fully unknown aliases.
- [x] MIR and MemorySSA have independent ownership, CFG, dominance, effect,
  region, phi, and cross-reference verification.
- [x] A canonical recursive `TypeStore` has stable `TypeId` identities,
  provenance, authority ordering, conflict retention, and object bindings.
- [x] Stable MIR objects can be joined to program types without source spelling.
- [x] A session-owned DWARF type graph has been implemented in the current
  working lane, including recursive nominal identities and referenced-member
  width resolution. It is not part of the `fb4ee6b` submission artifact until
  committed and verified.

### Foundations still incomplete

- [ ] Typed completeness and diagnostics do not yet travel through every stage.
  Still true, but no longer for want of typed signals — four now exist and none
  of them travels. See the same item under Phase 1 for the evidence; the sharp
  end is that `decompile_all`/`decompile_many` drop `LiftError` on the floor with
  a bare `continue`, so a function that failed to lift is indistinguishable from
  a function that does not exist.
- [~] `ProgramSession` is not yet the sole owner of every parse and cache.
  Substantially closed 2026-08-15: object parses per session went from
  `O(functions + branches + callees)` — 58 on a small C binary, 40,865 on
  `hello-rust-musl` at the default limit, and varying run to run on the SAME
  binary — to a constant 19. `ProgramImage` now indexes PLT stub ranges in its
  existing single parse and lazily owns `noreturn_import_targets`,
  `exception_call_sites` and `dwarf_functions`. The residue is 19 distinct
  one-shot analyses; reaching exactly one needs a relocation/symbol index on
  `ProgramImage`. Note two production sites had been bypassing the
  `profile::parse_object` adapter entirely, so the instrument was under-reporting
  its own subject. Re-measured at HEAD 2026-08-15: the 19 above is the
  `decompile_at` figure; whole-program `decompile_all` is 20, and both are now
  pinned as constants rather than bounds. See the Phase 1 view.
- [ ] The canonical target and ABI model is not ARM32-complete.
  Still true, and the Phase 2 view now says exactly which eight things remain
  (VFP s/d/q overlap, `d0`-`d7` argument slots, 64-bit integer argument pairing,
  shifter carry-out/V on logical `S` forms, NEON, register-shifted-register and
  RRX, LDM/STM writeback, and the synchronisation/system instructions). PC bias,
  literal pools, A32 condition decoding, IT blocks and hard-float ABI selection
  are done and should stop being listed as open.
- [ ] The verified MIR/MemorySSA boundary is not yet the production authority
  for all definition-sensitive transformations.
  Audited 2026-08-15: 0 of the 7 named consumers are migrated, and the reason is
  upstream of all of them — MIR is not BUILT on a production decompile.
  `lower_verified_with_image` has two non-test call sites: one inside
  `if std::env::var("GLAURUNG_DUMP_PASSES").is_ok()` whose result is `eprintln!`'d
  and dropped, and `PreparedLlir::mir`, which is `#[allow(dead_code)]` with a
  single `#[test]` caller. `DefinitionOracle` and its query surface appear in four
  files, all under `src/ir/mir/`, with zero production callers. Meanwhile four
  AST-level substitutes are live and say so in their own doc comments —
  `copy_prop` ("sound without dataflow analysis"), `expr_reconstruct` ("without a
  proper alias analysis"), `stack_locals`, and `structured_reaching.rs`, which
  return-type recovery and spill coalescing both call. `73bdca3` did not move
  this: `verify_defs.rs` is a string-keyed AST walk downstream of every transform
  that bails on flow it cannot linearize. First step: build MIR unconditionally
  in `prepare_llir_for_lowering` and carry it on `PreparedLlir` — no consumer can
  migrate to an artifact that is never computed. The measured cost of doing so is
  +13% on a whole-binary decompile, which is the real decision.
- [ ] The production aggregate/type consumers still depend on AST-era adapters.
  Audited 2026-08-15: 7 consumers on the adapter, 0 on MIR.
  `memory_objects/ast.rs` describes itself as "Prepared-AST compatibility
  adapter", and its `infer_from_ast` is the only object-model producer with a
  production caller (`high_variables.rs`). The one live query,
  `has_conflict_free_extent`, looks up `ObjectIdentity::LegacyRegister`. `554dbb4`
  added the MIR-side `memory_objects/shape.rs` but its own message says nothing in
  the production render path reads shapes yet, and the deletion of
  `memory_objects/llir.rs` was dead-code removal, not a migration. First step is
  the one this file already names at the rank-ordered plan's item 2: partition the
  MIR frame object into per-variable extents so `ObjectIdentity::MirValue` can be
  joined to `stack_locals`' promoted-local names.
- [ ] PDB and inferred type facts do not yet populate the same canonical store.
  Audited 2026-08-15: 1 of 3 sources populates it, and the store has no reader.
  `TypeStore` has exactly one production insert site — `program/types/dwarf.rs`
  under `TypeAuthority::Debug` — reached from `ProgramSession`. PDB facts go to a
  Python SQLite table and to AST string hints in `ir/pdb_fields.rs`. Inferred
  types live in their own lattice, `types_recover.rs`'s `TypeMap`/`TypeMapV`; that
  7,274-line file contains zero occurrences of `TypeStore`. And
  `ProgramEnvironment::types()` has only test callers, so today the canonical
  store is write-only. First step: a reader path, not another writer — a producer
  with no consumer is what made the DWARF slice easy to land and impossible to
  validate.
- [ ] Semantic HIR and pure renderers are not complete.
  Audited 2026-08-15: there is no HIR at all. `find src -iname "*hir*"` returns
  nothing; the `src/ir/hir/` directory this file's own ownership map names does
  not exist, and the only "HIR" token in the tree is a comment. The renderers are
  demonstrably not pure: the production entry
  `render_decbench_typed_with_output_and_prototype_and_dwarf_types_and_local_types`
  is 581 lines, writes 28 times into 15 `DEC_*` thread-local cells, and calls
  `recover_named_call_prototypes` (prototype INFERENCE, with conflict removal and
  a symbol lookup) and `infer_return_ctype` from inside rendering. Two of those
  analyses also run AFTER `verify_before_render`, so the thing verified is not the
  thing rendered. First step, and the cheapest cut at purity before any HIR
  exists: hoist `infer_return_ctype` and `refine_opaque_parameter_types_from_calls`
  into named `pass!` steps ahead of the verification boundary.
- [ ] File-size and ownership targets remain substantially open.
  Audited 2026-08-15 with `tools/fitness_report.py`: 5 of 7 targets missed, and
  every one of the top five files grew in the last 30 commits. 314 product files,
  166,455 LOC. Mean 530.1 against a target of 450; median 276 against 250; 13
  files over 2,000 LOC against a target of 5; 44.5% of LOC in files over 1,000
  against 25%; `src/ir` has 14 files over 1,000 against 5. Only "files over 1,000"
  (28 <= 35) and `src/ir` median (479 < 500) pass. `ir/ast.rs` is 11,628 product
  lines. Of the ownership map's directories, `src/lift/`, `src/ir/lifted/`,
  `src/ir/hir/` and `src/render/` do not exist. The measurement and the ratchet
  test both exist and pass — but `tools/fitness_baseline.json` has been rewritten
  in three of the last six commits, so the ratchet only ever records where the
  numbers went. First step: stop refreshing the baseline as part of unrelated
  work; the ratchet is only a ratchet if failing it is a decision.

## Non-negotiable design rules

1. Machine value, source interpretation, and rendered spelling are distinct.
2. Stable typed IDs identify every program, function, block, instruction, value,
   memory version, object, symbol, type, call site, reference, and target.
3. Evidence is retained with provenance, authority, confidence, scope, and
   revision. Selection policy never destroys conflicts.
4. Completeness and confidence are different. Incompleteness is monotone:
   downstream stages may add reasons, never erase them.
5. Unknown calls and instructions clobber conservatively. Unknown never means
   “no effect.”
6. Every reachable use resolves to a precise definition state: input,
   instruction, phi, undef, poison, unknown effect, unreachable, or a proved set.
7. Graph-changing passes prove preconditions, update through a controlled editor,
   invalidate dependent analyses, and verify postconditions.
8. A failed proof keeps a lower-level expression, explicit unknown, or honest
   goto. It does not guess.
9. One session parses and indexes one image. Passes consume session APIs and do
   not reopen the object independently.
10. Renderers are pure formatting projections over verified semantic artifacts.
11. ARM32 is a conformance architecture, not an optional afterthought.
12. Serial and parallel analysis must produce identical facts and output.
13. Metric gains do not override execution, verifier, completeness, regression,
    and canary evidence.
14. A file split counts only if it creates a narrower API and one reason to
    change; arbitrary fragmentation is not architecture.

## Target architecture

```text
                              ProgramSession
                   image / target / revision / budgets
                                    |
          +-------------------------+-------------------------+
          |                         |                         |
     ProgramImage                TargetSpec                ProgramEnv
 bytes/segments/relocs     ISA/mode/registers/ABI     symbols/types/objects/
 debug/imports/strings       and effect contracts      references/call facts
          |                         |                         |
          +-------------------------+-------------------------+
                                    |
                         function analysis pipeline
                                    |
                 complete lifted IR with exact effects
                                    |
                    verified typed MIR + MemorySSA
                                    |
             calls / types / objects / references / regions
                                    |
                         verified semantic HIR
                                    |
                  pure faithful / C / DecBench renderers
```

### Stage contracts

Every stage declares:

- typed input and output artifact versions;
- exact target and program revision;
- dependencies and required analyses;
- facts preserved and invalidated;
- budgets and cancellation behavior;
- verifier and failure policy;
- completeness reasons and diagnostics; and
- timing, allocation, graph-size, iteration, and change metrics.

The intended stage graph is:

```text
discover -> lift -> verify-lifted -> build-MIR -> verify-MIR
         -> recover calls/types/objects/references
         -> complete CFG -> recover verified regions
         -> build-HIR -> verify-HIR -> source cleanup -> render(profile)
```

## The five primary epics

### EPIC 1 — Program-level symbol and type environment

**Goal:** one revisioned evidence store for all cross-function knowledge.

The environment owns `SymbolStore`, `TypeStore`, `ObjectStore`,
`ReferenceIndex`, `FunctionFacts`, and `CallFactStore`. It imports object symbols,
relocations, imports/exports, DWARF, PDB, FLIRT, strings, readonly objects,
function tables, analyst knowledge, and inference without collapsing them into
lossy `HashMap<u64, String>` or C type strings.

- [x] Establish `ProgramEnvironment` behind the reusable session.
- [x] Add stable recursive `TypeStore` identities and conflict-preserving facts.
- [x] Bind stable MIR objects to type facts.
- [~] Import DWARF once per session into the canonical store; finish, commit, and
  verify the current working slice.
- [x] Implement a canonical `SymbolStore`: aliases, ranges, imports, exports,
  thunks, bindings, demangled names, and contextual address queries.
  **Built, and until 2026-08-15 it had ZERO production consumers** — every caller
  of `ProgramSession::symbol_store()` lived in `session_tests.rs`. It retained
  alternatives, conflicts, incompleteness and relocation sites by place the whole
  time; nothing asked. `program/references.rs` is now the first production
  consumer. "Implemented" and "connected" are different claims and this box only
  ever justified the first.
- [ ] Import PDB facts into `TypeStore` and `ObjectStore`; remove the separate
  PDB-only field-map authority.
- [ ] Import FLIRT/library catalog facts with explicit provenance.
- [~] Add `FunctionFacts` and `CallFactStore` keyed by stable function/call IDs.
  **The identity and the graph landed; the fact store deliberately did not.**
  `src/program/call_graph.rs` ships `FunctionId` (the normalized entry VA that
  `ProgramImage::normalize_function_entry` already canonicalizes for three
  existing keys) and `ProgramCallGraph` with a deterministic Tarjan
  condensation, owned by `ProgramSession::call_graph()` on the same
  `DiscoveryKey` as `discover_functions`. `CallSiteId` is NOT shipped: it has no
  producer, because `Function::callees` is a `HashSet` of targets that records
  no call-site VAs, so `CallFactStore` — keyed by call site — needs an
  `analysis/cfg.rs` change first. `FunctionFacts` is not shipped either, and the
  reason is in `docs/design/function-facts-and-call-facts-2026-08-15.md` §6:
  of the three candidate facts, only "does it return" has consumers, it is
  currently a 21-name list rather than an inferred property, and its main
  consumer is CFG discovery itself (`cfg.rs:1499`) — so a body-derived version
  is circular with the boundaries it would be derived from. Building the store
  before that decision would repeat the `SymbolStore` shape: implemented,
  unconnected, counted as done.
- [ ] Solve interprocedural prototypes and type constraints monotonically over
  call-graph SCCs.
  The SCC input now exists (box above); the monotone solver does not. Note the
  edge set is a LOWER BOUND — an unresolved indirect call contributes no edge at
  all (`cfg.rs:1488`) — so any fixed point over it must fail closed, and
  `ProgramCallGraph` deliberately offers no `is_leaf()`.
- [ ] Expose selected facts, alternatives, conflicts, and provenance through
  Python and the project database.
- [ ] Delete legacy string-keyed and per-entry-point fact exchange after parity.

#### Name-based knowledge: permitted, bounded, and never silent

Names are useful evidence, not proof of behavior. Carefully integrating them is
moderate work once the program environment is the owner; sprinkling name checks
through decompiler passes is cheap but creates an unsafe maintenance trap.

Allowed uses:

- exact imported/dynamic symbol plus a versioned known-library prototype;
- demangled C++/Rust names as candidate signature or type evidence;
- standard allocator/string/memory APIs as declared call-effect summaries;
- suffix/prefix conventions only as low-authority hints; and
- analyst-approved names as highest-authority local facts.

Required safeguards:

- preserve symbol source, binding, version, module, and demangling provenance;
- distinguish exact catalog match from heuristic name resemblance;
- validate candidate contracts against ABI, call sites, value widths, and
  observed uses;
- retain conflicting alternatives instead of forcing a signature;
- never key a product fix to a DecBench project or target-function name;
- include stripped, renamed, misleading-name, and same-name/different-signature
  negative controls; and
- use the selected contract before liveness/DCE so argument evidence is not
  deleted and reconstructed later from stale register names.

### EPIC 2 — Symbolize constant operands, not only call targets

**Goal:** attach contextual interpretations to operand uses while preserving raw
machine bits.

A constant may represent an integer, relocation, address, string, function,
symbol plus addend, enum member, field offset, RTTI/typeinfo record, or vtable.
The same bits may validly mean different things at different use sites.

- [x] Recover direct and address-taken function symbols in several existing
  paths without emitting conflicting `extern void name(void)` declarations.
- [x] Add an operand/use-site `ReferenceInterpretation` with source instruction,
  exact width, provenance, alternatives, and confidence.
- [~] Resolve evidence in order: relocation/loader semantics, decoded operand
  role and PC calculation, mapped region, MIR provenance, call/type constraints,
  xref consistency, then conservative heuristics.
  **Tiers 1-3 resolved; 4-6 cannot be queried from this layer.** A resolver that
  reached MIR provenance, call/type constraints or xref consistency would have to
  live downstream of MIR construction, and `readonly_fold` calls this from
  upstream. They are accepted as validated caller input instead, and a caller
  claiming a tier the resolver owns is dropped rather than outranked. The
  implementation is also two RULES rather than a priority list — role admission
  (a relocation is admitted everywhere, anything weaker needs the role to already
  say "reference") and fail-closed supply.
- [~] Index references once for decompilation, xrefs, call graph, readonly
  folding, function tables, and UI consumers. Three of six as of 2026-08-15:
  decompilation and readonly folding through `ReferenceResolver` (`4af32f1`), and
  function-table/indirect-branch targets through `ir/indirect_targets.rs`
  (`f1a6e4c`), which resolves a jump's destination from a relocation at
  `Confidence::Proved`. NOT xrefs — `analysis/xrefs.rs` has zero references to the
  module and still treats any immediate landing in a mapped range as a data
  reference — nor the call graph, nor UI consumers. The xrefs migration has a
  named blocker: no operand ROLE exists at that layer, so the disassembler must
  first distinguish a branch displacement from a memory displacement from an ALU
  immediate.
- [ ] Project selected interpretations as semantic HIR operations.
- [ ] Render `symbol + addend`, strings, enum members, globals, field offsets,
  and function pointers with an exact-literal fallback.
- [ ] Migrate and delete separate name, string, readonly, and function-table
  constant recognizers.
- [x] Prove with negative controls that a mapped numeric value used in arithmetic
  remains numeric.

### EPIC 3 — Aggregate and memory-object recovery

**Goal:** recover stack/global/TLS/parameter-pointee objects and solve structures,
arrays, unions, bitfields, and ABI aggregate transfers from proven accesses.

- [x] Add source-spelling-independent `MemoryObject`, affine access paths,
  extent, alignment, role, stride, lifetime, provenance, and conflicts.
- [x] Carry stable objects/accesses and cursor lifetimes into typed MIR.
- [x] Join MIR objects to canonical program types.
- [~] Retain the AST compatibility adapter as production authority while the MIR
  model is diagnostic; do not create a second production heuristic path.
- [ ] Migrate the first production aggregate consumer to verified MIR evidence.
  **Measured 2026-08-15 and the answer is not "not yet" but "there is nothing to
  move": the two models are at parity where MIR speaks, and MIR is silent
  exactly where the AST guesses.** See Phase 6 below for the full measurement;
  the one-line version is that verified MIR refuses to bound a frame the moment
  it sees a scaled index or an escaping frame pointer, and those two events are
  the trigger for every frame extent `stack_locals` recovers by guessing.
- [ ] Import authoritative DWARF/PDB/manual layouts into the same constraint
  system. Nothing is imported into the MIR constraint system yet. Worth knowing
  before that work starts: the AST-side import was silently COORDINATE-wrong on
  x86-64 until Entry 53. `dwarf_stack_object_hints` mapped SysV
  `DW_OP_call_frame_cfa` to `("rbp", +16)` — a frame-pointer displacement that a
  frame-pointer-omitted body never forms — so every proven aggregate extent in a
  `-O2` x86-64 function landed on a key nothing addressed, and promotion fell
  back to guessing beside it. Importing a layout is not enough; the coordinate
  has to be the one the body actually addresses.
- [~] Collect exact load/store, affine-offset, repeated-stride, overlap, pointer,
  and call-boundary constraints. Load/store footprints, affine offsets and
  overlap were already carried by `MemoryObject` and its partition. Scaled-index
  addresses are now retained as `MemoryObject::indexed_accesses` instead of
  being discarded at the point of refusal — the refusal itself is unchanged.
  Pointer and call-boundary constraints are still only refusals
  (`EscapedRoot`), not facts.
- [~] Classify struct versus array versus union versus bitfield conservatively.
  `src/ir/memory_objects/shape.rs`, reached through
  `MirFunction::object_shapes`. **Two of those four are not decidable from
  access evidence and the module says so rather than guessing.** Arrays are
  claimed only from a scaled-index address, which is the one signal no
  aggregate spelling imitates; their element COUNT is never claimed. Struct
  versus array is not claimed at all — `int32_t[4]`, a four-field homogeneous
  struct, and four packed locals are the same bytes and the same instructions,
  so the model reports the proven cells and declines the noun. Union versus
  punned struct is refused with a measured justification: a real union, a real
  byte array read through a wider load, and a real bitfield container all
  produce the identical verdict on real fixtures (diary entry 38). Bitfields
  carry no evidence here at all, because their field edges live in value
  arithmetic and never appear as a memory footprint. The ignored `shape_census`
  test measures the whole corpus: 40 arrays recovered across 32 of the 173 C
  fixtures, 910 cell decompositions, 14 overlapping cells, and zero index
  refusals. Diagnostic only; no production consumer, per the `[~]` item above.
- [ ] Propagate pointee and object constraints across calls.
- [~] Model by-value aggregates, split register/stack values, hidden structure
  returns, and aggregate result storage for each ABI.
  **The return CLASS is modelled and four of its five contracts are connected.**
  `abi::ReturnClass` (`Single` / `IntegerPair` / `SplitBanks` / `SsePair` /
  `Memory`) plus `abi::sysv_amd64_return_class` and the DWARF-driven
  `ir::return_class::declared_return_class` land the classifier; the register
  pair is wired end to end and MEMORY is now `RecoveredOutputKind::HiddenReturn`'s
  first and only producer (Entry 51, `tools/dectest.py 195_by_value_aggregates
  --full`, 4 improvements, 0 regressions). `SplitBanks` got its first consumer in
  Entry 54 (`tools/dectest.py 195_by_value_aggregates --full`, 4 improvements,
  0 regressions; `@o0` +2, `@o2` +3, both with 0 regressions).

  **`SsePair` landed 2026-08-16 (`fdbcf58`, Entry 62)** — the all-SSE class, 2-4
  floats or doubles returned in `xmm0:xmm1`, two registers holding one value.
  `195` had no lane for it, so `197_homogeneous_float_aggregates` was added
  (`205dcfc`) and found it immediately. 5 gate cells and 6 arch cells
  `fail -> pass`, 0 regressions, and the def-use census — the better measure here
  — moved `clang:O0 136->134`, `clang:O2 250->246`, `gcc:O0 98->94`,
  `gcc:O2 116->111`, **-15 undefined reads with no lane worse**.

  Two things it established that generalise beyond this class:

  - **A destination-first check asks the wrong question.** `SplitBanks` is
    consulted AFTER `result_storage`; `SsePair` had to be consulted BEFORE it,
    because at `gcc:O2` the attributed destination of a pair-returning call is
    `Phys("xmm0_d0#1")` — a dword LANE, which `is_return_register` correctly
    declines — so the scalar gate rejects the call before any class is reached.
    The destination is an artifact of register allocation; the class is a
    property of the ABI, and only the class knows where the value is.
  - **The vector bank needs lane identities, not just register identities.**
    `regview::ssa_parent` declines the vector bank, so a definition spelled
    `xmm0` never reaches a use spelled `xmm0_d0` — and callers unpacking a
    returned float aggregate read almost exclusively through lanes. Modelling the
    two whole registers moved ONE cell; adding `xmm0_d0/_d1/xmm1_d0/_d1` took it
    to seven. Expect the same asymmetry on the parameter side.

  Occupancy is derived from the object SIZE rather than the class list, which is
  what makes the 12-byte `{float x3}` case sound: `xmm1` carries four defined
  bytes, the lane table is filtered so `xmm1_d1` is *not defined at all*, and the
  fourth member cannot be manufactured because no identity exists to read it
  from. Sizes 9/10/11/13/14/15 classify `None` rather than rounding up.

  **Fixture `195_by_value_aggregates` maps the boundary exactly** (added
  2026-08-15, after an audit found the corpus had NO lane returning a struct by
  value). Verdicts after Entry 54:

      8-byte struct  -> rax             INTEGER      pass on all 4 lanes
      scalar control                                 pass on all 4 lanes
      16-byte struct -> rax:rdx         INTEGER      pass on all 4  (Entry 51)
      int + double   -> rax + xmm0      split banks  pass on all 4  (Entry 54)
      32-byte struct -> hidden pointer  MEMORY       FAIL on all 4

  What remains here is the MEMORY lane, and it is not ABI work:

  - **Split banks is closed (Entry 54).** It needed a C type the renderer could
    not spell, and now synthesises one: `abi::split_bank_return_tag` /
    `split_bank_return_definition` emit `struct __glaurung_split_is { unsigned
    long __integer; double __sse; }` (and its `_si` mirror) at block scope above
    the callee declaration, chosen for their EIGHTBYTE CLASSES so no field
    recovery is needed. The call's destination becomes a 16-byte frame object and
    each bank is read back out at its ABI offset — the decomposition goes through
    memory because `Expr` still has no value-base member node (see the "project
    solved access paths" item, which this does not close).

    The same entry fixed the soundness defect underneath it:
    `call_result_split::result_storage` used to map `xmm0` onto the SAME storage
    key as `rax`, so an ordinary `xor %eax,%eax` between a `double`-returning
    call and the read of its result EVICTED that result —
    `181_compensated_summation:gcc:O2:summation_disagrees` compared against a
    literal zero. The x86 conventions now key on the result BANK, which also
    moved the i386/x87 form of the same bug
    (`181_compensated_summation:i386:O2`). **AArch64 deliberately keeps its
    collapse**: separating `x0` from `v0`/`d0`/`s0` regressed
    `175_float_matrix_kernel:aarch64:O0:dot_product_f32`, because AAPCS64 has no
    modelled aggregate return class to re-attribute the other bank from.
  - **The MEMORY lane does NOT fail for an ABI reason.** The recovered call is
    positionally correct against the machine — `bv195_make_big(<buffer>, seed)`,
    the hidden pointer in `rdi` and `seed` in `rsi` — because the callee's
    storage layout is recovered from liveness and never claims a source arity, so
    the "every argument shifts one register right" hazard never materialises. It
    fails because `mov %rsp,%rdi` at `1331` hands out the frame base while the
    subsequent `0x8(%rsp)` reads are promoted to `local_38`: the address escaping
    into a call is not connected to the stack object the reads name, so the
    callee writes to an undefined `rsp` and the caller reads a buffer nothing
    wrote. ~~That is the same promotion-meets-a-borrowed-address shape as Entry
    50 and `111_self_referential_struct`~~ — **it is not (Entry 53).** Those two
    were a DWARF coordinate bug and are fixed; this lane has no DWARF stack
    object at all, because `b` is recorded as four register `DW_OP_piece`s. Its
    buffer is formed heuristically by `stack_assignment_object_address` from the
    epilogue's dead `%t147 = %rsp`, after the call argument was visited. Entry 53
    prototyped and reverted the connect: admitting a bare `%rsp` as an escaping
    address in argument position does hand out `&local_38[0]`, and the recovered
    callee prototype then truncates it — `extern long *bv195_make_big(int)`
    renders `(int)(&local_38[0])`. **The blocker is the parameter side:
    `RecoveredOutputKind::HiddenReturn` has a producer and no consumer**, so the
    callee never declares the MEMORY-class hidden pointer this box proved it has.
    It belongs here, with the ABI work, not with EPIC 3's stack work.

  Consequently returns and parameters were **separable** here, contrary to the
  earlier note in this box. The eightbyte classifier is shared machinery — the
  parameter side can call `sysv_amd64_return_class`'s `Eightbyte` join unchanged —
  but the consumers are independent and nothing forced them to land together.
- [ ] Project proven accesses as HIR `Field`, `Index`, `AddressOf`, and typed
  dereference nodes.
- [ ] Model vtables and RTTI as global objects connected to relocations, types,
  and method contracts.
- [ ] Remove PDB-only AST operations and debug-specific late walkers.

Near-term retained work:

- Port only the version-stable affine-index analysis from the retired
  `agent/stack-bias` snapshot against current master.
- Keep the guards that reject self-rooted read-modify-write facts and unstable
  definition endpoints.
- Add a real end-to-end fixture for an array indexed with a constant bias before
  integrating it.
- Do not merge the retired branch or restore its pervasive `StackAddressDefs`
  threading wholesale.

### EPIC 4 — Architecture-parametric machine model

**Goal:** one validated model for target identity, register views, instruction
mode, ABI classification, call effects, stack/frame rules, and exact widths.

- [x] Introduce canonical target identity at the program and MIR boundaries.
- [x] Centralize substantial x86-64/AArch64 register-view behavior.
- [x] Finish `TargetSpec`: ISA, mode, endian, address width, pointer width,
  object format, OS ABI, default calling convention, and register bank.
  Audited 2026-08-15: `src/target/spec.rs` carries exactly those nine —
  `architecture`, `default_code_mode`, `endianness`, `address_bits`,
  `pointer_bits`, `format`, `os_abi`, `calling_convention`, `registers` — and it
  is production, not a declaration: 29 references outside `src/target/`, 24 of
  them reading a specific field. The struct is finished; what remains is
  consumers still deciding without asking it, which is the NEXT bullet, not this
  one.
- [~] Remove remaining register-name inference from SSA, widths, execution,
  lifting, and recovery. Substantially advanced by the register-view model
  (`5724717`), which moved vector-lane facts out of string surgery into one
  descriptor table with generated conformance tests. Still parsing names:
  `types::phys_reg_width` matches against literal name lists and
  `types.rs:621,627` parse a numeric suffix, as does `regview.rs:379`. The
  blocker on `phys_reg_width` is recorded and real — it is arch-blind, so `sp`
  would resolve to a 16-bit view on x86 and a 64-bit one on AArch64, and fixing it
  means threading the target through every caller.
- [ ] Represent constants as exact-width bitvectors with operand provenance.
- [ ] Make all call and intrinsic read/write/clobber effects target-owned.
- [ ] Unify ABI argument/result/aggregate classification behind the target.
- [ ] Generate conformance tests for every register view and partial-write rule.

ARM32 acceptance work:

- [x] Preserve the real armv7 fixes recovered during branch integration.
- [x] Reject ARM alignment saves as parameter evidence when balanced and unused.
- [x] Widen the dual current-SP/CFA entry-stack coordinate machinery from its
  AArch64 gate to ARM32, with real A32/Thumb controls. **The gate was not what
  this item described.** The coordinate re-expression machinery was already
  widened to ARM32 at `401ac4f`; the gate actually remaining was an
  A32-versus-Thumb split *inside* ARM32. `STACK_BASES` carried AArch64's `x29`
  and A32's `fp`, but not Thumb-2's `r7` — which GCC anchors Thumb frames on
  because 16-bit encodings cannot reach high registers — and the
  `is_arm_frame_pointer` guard that already listed `"r7"` was nested inside the
  `is_active_stack_base` branch, so that arm was unreachable. Thumb frames
  therefore promoted NOTHING: `07_packet_parser` recovered 1 distinct local
  against A32's 25, `163_wire_header_parser` 1 against 12. Seven of eight Thumb
  lanes now match their A32 control exactly, with every A32 number unchanged.
- [ ] Cover A32 versus Thumb, PC bias, literal pools, condition execution,
  r0-r15/CPSR, instruction alignment, and endian behavior.
- [ ] Cover VFP s/d/q overlap and hard-float versus soft-float ABI selection.
- [x] Add a real `-marm` A32 fixture lane; Thumb-only ARM coverage is inadequate.
  `tools/arch_roundtrip.py` lists `armv7_a32` in `REQUIRED_ARCHES` and
  `tests/decompiler_fixtures/arch_baseline.json` carries 350 ratcheted
  `armv7_a32` lanes.
- [ ] Verify ARM32 frame promotion, stack aggregate extents, and argument homes
  through the shared coordinate model.
- [ ] Treat unsupported architecture/ABI combinations as typed incompleteness,
  not a silent fallback to x86/AArch64 assumptions.

### EPIC 5 — Sound definedness and reaching definitions

**Goal:** make verified MIR the single answer to “what value reaches this use?”
for registers and memory.

Minimum query surface:

```text
definition(value)
uses(value)
dominates(definition, use)
value_at(storage, point)
all_paths_defined(value, point)
clobbers_between(value, from, to)
memory_version(region, point)
```

- [x] Add stable MIR values, definitions, uses, phis, and dominance verification.
- [x] Add all-paths-defined fixed-point queries that preserve valid loop cycles
  and fail closed through poisoned dependencies.
- [x] Add conservative region-aware MemorySSA with explicit call/unknown clobbers.
- [x] Verify memory ownership, region consistency, phi predecessors, effects,
  backreferences, and dominance independently.
- [~] `value_at`, `clobbers_between`, the reaching-definition set, and
  `memory_version` are implemented and tested in `src/ir/mir/query.rs`; the whole
  EPIC 5 minimum surface now exists. No production consumer has been migrated to
  it yet, and every call still poisons every unnamed machine storage because no
  target-owned clobber contract exists (EPIC 4). See diary entry 10.
- [ ] Add transactional graph editing and precise analysis invalidation.
  Audited 2026-08-15: not started. `src/ir/mir/` exports `lower_verified`,
  `lower_verified_with_image`, `verify` and the query/model types — no `&mut`
  editing surface leaves the module, and the only `invalidat|transaction|commit`
  hit in the whole tree is an unrelated `.expect()` string at `mir/mod.rs:385`.
  First step: it is not the editor. `DefinitionOracle` has no caching — `value_at`
  runs a fresh fixed point per call and `clobbers_between` rebuilds a `PointGraph`
  — so the first per-instruction consumer needs a memoized per-storage solve
  before an invalidation protocol has anything to invalidate (diary entry 10).
- [ ] Port call argument recovery, copy propagation, DCE, stack promotion,
  return recovery, expression reconstruction, and aggregate recovery to oracle
  proofs.
  Audited 2026-08-15: **zero of the seven have moved.** `DefinitionOracle::new`
  has no non-test caller anywhere in `src/`, and none of `call_args.rs`,
  `copy_prop.rs`, `dce.rs`, `stack_locals.rs`, `direct_output.rs`,
  `expr_reconstruct.rs`, `high_variables.rs` mentions `mir` at all. Two findings
  that change the plan rather than the score:
  * The listed ORDER looks wrong. Aggregate recovery is last, but it is the only
    consumer whose verified MIR model is already built and independently verified
    (`memory_objects/mir.rs`, `mir/verify_objects.rs`) and sitting unused beside
    the AST version production actually calls (`high_variables.rs:36` ->
    `memory_objects/ast.rs`). It is the cheapest migration, not the dearest.
    **Retracted 2026-08-15 — measured, and it is not a migration at all.** The
    join was wired through the real pipeline over the whole corpus and MIR
    agrees with the pass it would replace on 3803 of 3823 bounded frame
    coordinates, is a weaker bound on the other 20, and is silent on every
    extent `stack_locals` actually guesses. Cheap to plumb, yes; it returns
    nothing. See Phase 6's "Migrate the first production aggregate consumer"
    box for the numbers and for the three model changes that would make it
    return something.
  * The "instruction identity blocks four of the seven" claim (diary entry 44)
    is **retracted 2026-08-16 — measured, and it was wrong twice over.** First,
    only `copy_prop` actually bails on aliasing: `dead_stores::is_dead_from`
    contains no memory barrier at all (it eliminates *register* writes, and its
    two `Stmt::Store` matches are a callee-save idiom and a storage-based
    proof), and `readonly_fold` reads read-only image data that nothing writes,
    its `Stmt::Store` arm folding subexpressions and clearing nothing. Second,
    `copy_prop`'s bail does not need a `MemoryAccessId`. Instrumented over the
    corpus, 1,989 dropped loads had a waiting reader, and **1,438 of them
    (72.3%) are provable from evidence already in the AST** — `Expr::StackAddr
    { object }` plus a literal displacement plus the widths `Stmt::Store
    { size }` and `Expr::Deref { size }` already carry. Shipped as
    `copy_prop::invalidate_loads_for_store`; see diary entry 46. The 27.3%
    remainder needs a real pointer proof, which the five-region MemorySSA also
    cannot give: `primary_region_for_memop` maps any non-sp/fp base to
    `HeapUnknown` and a `HeapUnknown` write clobbers every region, so verified
    MIR would buy 121 of the 1,989 cases for Entry 44's measured +10.4%.
  * Call-argument recovery has since grown its OWN reaching-definition machinery
    (`call_args::EnclosingSlots::reaching`, `9952fc0`) rather than migrating. It
    is fail-closed and it works, but it is an eighth approximation, and its two
    remaining corpus failures are precisely the shape `value_at` answers and it
    cannot — see "Function contracts and indirect calls" below.
  Blocked on the box above it in Phase 3: until call clobbers are target-owned,
  every post-call `value_at` on a real body answers
  `Unknown(OpaqueInstruction)`, so migrating first would trade a confident wrong
  answer for a universal refusal.
- [ ] Delete local backward scans and AST reaching-definition approximations as
  each consumer reaches parity.
  Audited 2026-08-15: nothing deleted, and the count went UP. `73bdca3` promoted
  `ir/verify_defs.rs` — an AST-only def-before-use walk — from a discarded debug
  check to the pipeline's render-time authority, and ratcheted it across six
  lanes. That was the right call for the defect it fixed and it is movement away
  from this box. The live set is `call_args::EnclosingSlots`, `copy_prop`'s
  `copies.clear()` invalidation, `dce::prune_body`'s reverse walk,
  `structured_reaching.rs`, `use_def.rs` (intra-block only, by its own docstring)
  and `verify_defs.rs`.
- [x] Diamonds, loops, irreducible flow, conditional definitions, multi-output
  intrinsics, undef/poison, calls, memory aliases, and **exceptional flow** are
  covered by `src/ir/mir/query_tests.rs`, including a real x86-64/ARM32 property
  test that a query may refuse to answer but may never contradict the verified
  SSA edge.
  The exception gap is closed as of 2026-08-15. The old note — "LLIR has no
  exceptional-edge representation yet" — was already false for MIR when it was
  written: `analysis::exception::with_exceptional_successors` builds the
  LSDA-proven augmented graph and `python_bindings::ir` hands *that* graph to
  SSA. `value_at_a_landing_pad_join_merges_the_lsda_proven_edge` lowers both
  graphs and pins the difference: without the proven edge the pad has no
  predecessor, so its operand is a `Definition::Unreachable` root — the oracle
  would be telling a consumer the handler is dead code — and with it the same
  operand is a real `InstructionOutput` in the reaching set. What still has no
  exceptional edges is the STRUCTURER, which is Phase 4's box, not this one.

## Cross-cutting decompiler workstreams

### Function contracts and indirect calls

- [x] Recover several direct, address-taken, format-sink, callback, and library
  contracts from reusable evidence.
- [~] Recover function-pointer-table entry contracts before liveness/DCE.
  Done for LAYOUTS, not for contracts. `callee_contracts::recover_table_entry_layouts`
  (`9952fc0`) recovers each entry's parameter storage through the same
  demand-driven cached callee analysis the direct path uses, bounded by the
  fail-closed `function_tables::tables_referenced_by` scan. Ordering is proved:
  it runs in `recover_direct_callee_layouts` before the AST pipeline, and its one
  consumer runs in the `reconstruct_args` pass, ~80 lines of pass ordering ahead
  of `eliminate_dead_stores` and well ahead of `copy_prop::remove_dead` inside
  `prepare_for_decbench`. What is NOT done: the recovered `CallPrototype` is
  discarded at `callee_contracts.rs:765` — only the storage list is kept, in a
  separate `DirectCalleeFacts::table_entry_layouts` no other consumer can reach.
  Per-entry return and parameter TYPES are still unrecovered, so the emitted cast
  on a table call is inferred, not proven.
- [x] Preserve ABI may-use argument registers for proven indirect-table calls in
  the safe over-approximation direction.
  `call_args::table_call_may_use_layout` (`9952fc0`) unions the entry layouts
  over a callee set proven by relocations — `collect_function_pointer_tables`
  builds a table only when a defined data symbol has pointer-sized storage, EVERY
  slot carries an exact dynamic relocation, and EVERY relocation resolves to a
  defined function symbol. It fails closed three ways: a missing entry layout,
  layouts that do not nest, or a union that is not a valid ABI allocation prefix.
  Note what "preserve" had to mean: the union is MATERIALISED as real `Call.args`
  (`call_args.rs:1528`), not recorded as a side set. `abi::call_effects` is
  deliberately unchanged. At the AST/C boundary a may-use set that does not
  become arguments is cosmetic — the emitted call passes nothing regardless of
  which local assignments survive above it — so the design doc's cheaper "teach
  DSE about may-uses" option was correctly not taken. See diary entry 25.
- [~] Reconstruct actual reaching values at the call site, not architectural
  register names that may now denote different caller arguments.
  Implemented and load-bearing: `EnclosingSlots::reaching` records a slot's
  reaching definition only from a top-level unconditional `Stmt::Assign` with a
  VERSIONED destination (`call_args.rs:1012`). That versioning requirement is the
  whole difference from the reverted patch below, which named architectural
  `rdi`/`rsi` and let the naming pass render them as this caller's own `arg0`.
  The residue is exact and measured. `fold_one_table_call` is all-or-nothing over
  the union, and the one shape it cannot name is a LOOP-CARRIED argument. For
  `191_indirect_table_args:gcc:O2:t191_fold` the union is recovered correctly —
  all four entries yield `[rdi, rsi, rdx]`, dumped under `GLAURUNG_DUMP_PASSES` —
  but the accumulator lives in `rsi`, defined at the loop head and rewritten
  inside the guarded arm, so `reaching_value` refuses slot 1, the fold declines,
  and the ordinary backward scan emits the single adjacent `rdi`. The recovered
  call is `T191_OPS[i](witness)` for a callee that reads three. Same cause for
  `95_function_pointer_table:gcc:O2:fold_operations`; both are recorded `fail`.
  This is the exact query `mir::query::value_at` answers and the AST scan cannot,
  and it is the strongest concrete argument for EPIC 5's consumer migration.
- [x] Re-test the `dispatch_operation` table-call fixture and the full corpus.
  Re-run 2026-08-15 at `dcc62aa`: `tools/dectest.py 95_function_pointer_table`
  and `191_indirect_table_args 08_indirect_dispatch` — 12 lanes, no regressions;
  `95:gcc:O2:dispatch_operation` is `pass` in the committed `baseline.json`.
  The corpus half was done by `2c2bf68`, which ratcheted the 26 cells the
  indirect-call work repaired after `874fe33` stopped the lifter fabricating
  `call @0x0` for `call *(%rcx,%rax,8)`; that single lifter repair moved twelve
  cells including six `191` lanes and five unpredicted obfuscation cells. Two
  cells remain `fail`, both the loop shape, both attributed above.
- [r] Do not restore the reverted late table-layout patch: it emitted plausible,
  well-typed, but wrong arguments.

### Complete CFG and semantic structuring

- [~] Carry unresolved transfers, skipped bytes, clipped blocks, budgets, and
  edge completeness through every artifact.
  **Done: unresolved transfers, clipped blocks, clipped targets, edge
  completeness.** Undecodable blocks survive as an explicit `undecoded_bytes`
  intrinsic instead of vanishing (`38d6591`); terminal edges are typed and the
  unexplained ones counted (`01f0b23`). **Not carried: budgets, and skipped bytes
  on the discovery side.**
- [x] Represent direct, conditional, switch, indirect, exceptional, call,
  return, tail-call, and unknown terminal edges explicitly.
- [~] Build graph-complete region recovery with total edge accounting.
  **Measured 2026-08-15 and the successor-edge half already holds.** Census over
  60 gcc-O2 fixture objects (15576 health events; the absolute sums double-count
  because health is emitted at several pipeline points per function, but the
  zeros and the ratios do not depend on that):

      terminal_edges             24046
      unresolved_indirect_edges   2706     11% of terminals
      undefined_uses               761
      structure_fallbacks          594
      uncovered_cfg_edges            0
      invented_cfg_edges             0
      unknown_cfg_edges              0
      unknown_terminal_edges         0

  Zero uncovered and zero invented edges means the region tree already expresses
  exactly the successor graph — `structure_accounting::account` is not merely a
  diagnostic, it gates region selection through `structure_accounting_is_unsound`.
  What is NOT total is terminal ownership: there is no `Return` region node, so
  terminals are classified and counted but not owned by the tree.

  **The 2706 turned out to be ~99% mis-attribution, not unknown control flow.**
  Classified against `objdump`/`readelf` ground truth over 182 objects: 43.2%
  `crtstuff` `jmp *%rax` after a GOT load, 34.0% `.plt.got`/`.plt.sec` stubs,
  21.6% the `.plt[0]` lazy-binding header — 98.8% boilerplate whose destination a
  relocation states outright — and 1.2% real table dispatch. Resolving them from
  the relocation rather than the stored bytes took the corpus from 32838 to 351
  unresolved (23.2% to 0.25%), re-attributing every one and inventing none.

  Two things that census exposed are worth more than the number. The count is
  taken at the WRONG POINT: `cfg_health` is frozen at LLIR structure time, before
  `function_tables` runs, then re-stamped at ~39 later boundaries, so five of the
  nine residual functions already decompile perfectly — the honest floor is four,
  all fixtures written to be unresolvable. And "why the decoder declined" is
  already computed and thrown away: `analysis::dispatch::Unresolved` records
  `UnknownBase`/`NoTableAt`/`NoBound` and nothing serializes it, while ~14
  distinct decline points in `jump_table.rs` collapse to a bare `None`.

  What remains to chase here is the 594 structure fallbacks.
- [ ] Preserve irreducible and unresolved flow with explicit goto/indirect
  fallback rather than inventing structure.
- [ ] Separate dominance/loop discovery, region selection, verification, and HIR
  projection from the current large structuring owner.
- [x] Diagnose the 43 historically AArch64-only DecBench failures by first wrong
  semantic stage, not verdict alone.
- [ ] Attack large O2-noinline GED failures directly after CFG completeness and
  definition ownership are trustworthy.

Measured cautions:

- [r] Do not restore always-hoist loop recovery. It recovered substantial GED
  but produced wrong answers in four functions across six cells.
- [r] Do not restore goto sinking merely to reduce goto count. It removed 11%
  of gotos but regressed `statemachine:gcc:O0` GED from 10 to 35 and lost five
  ByteMatch cells.
- [ ] Define a readability metric before trading source-like structure or
  execution safety for lower goto density.
- [ ] Add a linked-structure argument kind to the differential harness before
  changing the nearly dormant sentinel-list recovery pass.
- [ ] Keep pass-fire instrumentation and either add standing real coverage for
  extremely rare transforms or retire them deliberately.

### Semantic HIR and pure rendering

- [ ] Complete semantic HIR with stable variables, object paths, calls, casts,
  predicates, regions, and preserved CFG provenance.
- [ ] Generate or centralize one visitor/rewriter surface.
- [~] Move copy-chain folding and every semantic renderer rewrite into named,
  verified pre-render passes. Copy-chain folding was already out. 17 anonymous
  passes between `prepare_for_decbench` and `ready_to_render` now have names,
  which matters because `pass_health_report.py` blames the FIRST pass at which a
  counter moves — every new undefined read in that tail was being attributed to
  `ready_to_render`, the boundary that observes the damage rather than the pass
  that caused it. Still at render time, with blockers named:
  `renderable_dwarf_structs` (no blocker), `recover_named_call_prototypes`,
  `infer_return_ctype` (runs both pre-render AND in the renderer), and the
  `DEC_DECLARED_CTYPES` keystone — which is NOT circular, so the declaration plan
  is extractable. `DEC_SEMANTIC_WIDE_CAST` is genuinely unmovable and wants a
  parameter, not a pass.
- [x] Verify def-before-use after the final semantic transform, before rendering.
  The check already RAN at that boundary — `decbench_text` called
  `verify_defs::check` right after `ready_to_render` — but the answer was
  computed, found non-empty, logged at debug level and dropped. It now returns a
  `#[must_use] RenderVerification`, so discarding the proof is a compile error,
  and the verdict leaves by a channel that is not the C: stderr on every
  `glaurung decompile`, plus `take_render_verification()` programmatically. It is
  deliberately NOT a comment in the rendered output — that output is scored by an
  external benchmark, and a note announcing our own bug does not belong inside
  the code being scored.
- [ ] Make faithful, C, and DecBench output profiles pure projections of the same
  verified HIR.
- [ ] Remove renderer thread-local type/name state. (The bullet also said
  "renderer-time fixed points"; measured 2026-08-15, there are none — every
  bounded-iteration loop reachable from a DecBench render is inside
  `prepare_for_decbench` or `refine_decbench_abi_widths_with_value_widths`, both
  pre-render. The 16 `DEC_*` thread-local cells are real and remain.)
- [ ] Require deterministic pipeline fingerprints for every entry point/profile.

## Code quality, composition, and file-size program

### The targets are moving the wrong way — decide, do not drift

Measured 2026-08-16, and the direction matters more than the gap:

| measure | target | 2026-08-13 | now |
|---|---:|---:|---:|
| product mean LOC | 450 | 515.9 | **530.2** |
| files over 2,000 LOC | 5 | 13 | **14** |
| product LOC in files over 1,000 | 25% | 44.5% | 44.5% |

The mean rose while the ratchet stayed green, because the baseline was
regenerated ten times in one day — each movement individually defensible, the
trend visible to nobody. `tools/fitness_report.py --write-baseline` now records
accepted regressions inside the baseline and prints cumulative drift, and it
earned that on its first use by catching `copy_prop.rs` crossing 2,000 lines.

This is an ARCHITECTURE-track item and should be judged as one: splits that do
not move fixture cells are the expected outcome, not a failure. But an
aspirational target nobody is working toward reads as failure at every
measurement, which is corrosive. Either schedule the splits below as real work,
or restate the numbers as a direction rather than a target. Do not leave them
sitting as a gap that grows.

**Decided 2026-08-16, and the table above was measuring the wrong thing.** The
first real cut — lifting the typed C renderer out of `ir/ast.rs` into
`ir/ast/dec_render.rs` (`a792b9a`) — took the largest owner from 11,582 to 9,461
product LOC, an 18% reduction, and made **four of the seven measures worse**.
Not through any fault of the split: dividing a 19,269-line file into 17,148 +
2,170 necessarily adds a file to both "above N" buckets and moves both medians.
Every measure in the set was a count or an average, so the program's own ratchet
argued against the program.

`product_max_loc` — the single largest product file, target 1,000, the same line
the ownership map already enforces for *new* modules — joined the set in that
commit. It is the only measure that moves in the direction this work moves:

| measure | target | 2026-08-13 | before the cut | after |
|---|---:|---:|---:|---:|
| **largest product file** | 1,000 | — | 11,582 | **9,461** |
| product mean LOC | 450 | 515.9 | 530.6 | 528.3 |
| files over 2,000 LOC | 5 | 13 | 14 | 15 |
| product LOC in files over 1,000 | 25% | 44.5% | 44.9% | 44.9% |

The four regressions are recorded as accepted, with drift, rather than
regenerated away — and the drift record is now saying something uncomfortable
that the per-change view hid: since it was first written,
`product_files_above_1000` has gone 28 -> 30 and `files_above_2000` 13 -> 15. We
keep buying mean improvements with file-count regressions. **`product_max_loc` is
how that trade gets judged from here, and it has to come down.** Judge the
program by it; treat the count measures as secondary, because a decomposition
that is working will always push them the wrong way for a while.

The constraint that governs any split has not changed and is not negotiable: a
split counts only if it creates a narrower API and one reason to change.
Arbitrary fragmentation is not architecture, and a split that leaves the same
responsibilities coupled by private mutation is a stop condition.

**2026-08-17 — the measure that was chosen to judge this program no longer
points at a decompiler file.** Twenty-five cuts in, `product_max_loc` is
`symbolic/solver/axeyum_backend.rs` at 3,357, a file this program has never
touched and which is not part of the decompiler at all. That is the intended
terminal state for the decompiler owners, reached: no file this work is
responsible for is the largest in the tree.

```
uv run python tools/fitness_report.py
```

| measure | target | 2026-08-13 | 2026-08-17 |
|---|---:|---:|---:|
| measure | target | 2026-08-13 | 2026-08-18 |
|---|---:|---:|---:|
| product mean LOC | 450 | 515.9 | **430.3 — MET** |
| files over 2,000 LOC | 5 | 13 | **3 — MET** |
| product LOC in files over 1,000 | 25% | 44.5% | **22.6% — MET** |
| product LOC in files over 1,000 | 42,000 | — | **39,264 — MET** |
| files over 1,000 LOC | 35 | — | **26 — MET** |
| src/ir median | 500 | — | **429.5 — MET** |
| product median LOC | 250 | — | 311.5 |
| src/ir files over 1,000 | 5 | — | 15 |
| **largest product file** | 1,000 | 11,582 | **2,466** (`analysis/cfg.rs`) |

**Seven of the nine measures pass (measured 2026-08-19).** Three files remain over 2,000 lines against a target of five, and the tree carries 39,264 LOC in files over 1,000 against a 42,000 ceiling. The two that do not are the two that
cannot be satisfied by moving code between files: `product_median_loc` and
`src/ir files above 1,000`, both of which ask for a tree with many more, much
smaller modules than this one has. They are worth restating as directions rather
than targets, or re-derived from what a decompiler of this shape should look
like — the mean, the file-count buckets and the largest-file measure have all
done their job and should now be held rather than pushed.

`fitness ratchet: no regressions` throughout, across every one of the ~65 cuts.
`files_above_2000` went 15 -> 4. **Not one decompiler file remains above
2,000**: the four are `analysis/java_class.rs` (2,644, a `.class` parser),
`python_bindings/analysis.rs` (1,901 — below the line, listed for context),
`ir/value_number.rs` and `ir/lift_arm64.rs`. The largest decompiler file is
`analysis/cfg.rs` at 2,466, down from 6,248.

The measure this program was judged by, `product_max_loc`, has moved
11,582 -> 2,644 and now points at a file the decompiler work never touches. That
is the honest end state for it: it stopped measuring this program some time ago,
which is itself the argument for holding the met measures rather than chasing
the two that remain.

Per owner, product LOC, `#[cfg(test)]` excluded:

| owner | start | now | cuts |
|---|---:|---:|---:|
| `ir/ast.rs` | 11,582 | 1,650 | 8 |
| `analysis/cfg.rs` | 6,248 | 2,414 | 8 |
| `ir/lift_x86.rs` | 4,998 | 2,163 | 9 |
| `ir/call_args.rs` | 3,920 | 1,327 | 7 |
| `symbolic/solver/axeyum_backend.rs` | 3,357 | 925 | 6 |
| `ir/stack_locals.rs` | 3,241 | 767 | 4 |
| `ir/types_recover.rs` | 3,058 | 1,893 | 3 |
| `ir/lift_arm32.rs` | 2,998 | 1,941 | 3 |
| `ir/structure.rs` | 2,607 | 1,671 | 3 |
| `ir/lift_arm64.rs` | 2,516 | 2,038 | 2 |
| `ir/copy_prop.rs` | 2,068 | 1,630 | 2 |

Fifty-one cuts. `symbolic/solver/axeyum_backend.rs` is in the table because it
was the file `product_max_loc` pointed at once every decompiler owner came down
— it is not a decompiler file, and splitting it is what found that **all three
SMT solver backends had not compiled for seventeen days** and that no workflow
builds any solver feature.

Two findings that change how the remaining cuts get planned:

- **A sibling's `use super::X` does not pin `X` to the parent.** Moving `X` into
  a different child and adding `use child::X;` to the parent re-binds the name
  in the parent's namespace, so `use super::X` in a sibling — and a rustdoc
  `[`super::X`]` link — keeps resolving with no edit. Proven by compiled probe
  on 2026-08-17. The opposite rule had been treated as fact and had already
  blocked one real ~215-line cut. The caveat that survives: a re-export whose
  only consumer is a `#[cfg(test)]` module is unused in the shipped lib build
  and *adds* a warning.
- **The purity standard is a token diff, not a claim.** Every cut is now checked
  by extracting the moved region from `git show HEAD:<parent>` and comparing
  token streams against the new file; three of this round's four cuts came back
  at ratio 1.000000, and the fourth — the first non-pure cut in the program —
  came back token-identical modulo five named substitutions. A cut that cannot
  produce that diff gets its behaviour argued line by line instead.

The next targets are `ir/types_recover.rs` (3,057) and `ir/lift_arm32.rs`
(2,999), which are now the two largest decompiler files.

### Ownership map

```text
src/program/       image, session, artifacts, environment, provenance, stores
src/target/        target identity, register banks, ABI and effect contracts
src/lift/          shared lift context/builders plus ISA instruction families
src/ir/lifted/     exact machine effects and verifier
src/ir/mir/        values, memory, graph editor, analyses and verifier
src/ir/hir/        semantic source model, builder, visitors and verifier
src/analysis/      dataflow, calls, types, objects, references and structure
src/render/        faithful, C and DecBench formatting-only projections
src/decompile/     pipeline, profiles, orchestration and result boundary
```

**Current sizes, measured 2026-08-18 (`uv run python tools/fitness_report.py`).**
This table is here because the list below names targets without sizes, and that
is how `analysis/cfg.rs` stayed invisible: it was never in the priority list, and
while `ast.rs` was at 11,582 nobody looked past it.

| product LOC | file | status |
|---:|---|---|
| 2,466 | `analysis/cfg.rs` | 8 cuts; 6,248 -> 2,466. **Largest decompiler file.** `discover_function` is still ~596 lines of it |
| 2,163 | `ir/lift_x86.rs` | 9 cuts; 4,998 -> 2,163. `lift_one_inner` is ~74% of what remains and is a by-mnemonic match, not a lift-and-shift |
| 2,038 | `ir/lift_arm64.rs` | 2 cuts; 2,516 -> 2,038. `arith` family measured as the next cut |
| 1,941 | `ir/lift_arm32.rs` | 3 cuts; 2,998 -> 1,941. `lift_one_decoded` is 76% and needs a `return`->`Some` rewrite, so not pure |
| 1,888 | `ir/types_recover.rs` | 3 cuts; 3,058 -> 1,888 |
| 2,013 | `ir/ast/dec_render.rs` | Created at 2,195, cut to 1,727, **now 2,013 — it crossed 2,000 on 2026-08-19** and took `product_files_above_2000` 3 → 4. The growth is four commits of decompiler-correctness work in one day (1,797 → 1,839 → 1,946 → 2,013). `check_ratchet` said "no regressions" throughout, because `product_loc_above_1000` is a SUM with thousands of lines of slack; the per-owner trend line is what caught it. **Re-reviewed 2026-08-19 at 2,013 LOC: verdict RENEWED, not split** — the strongly-connected component grew in step (11 fns/903 lines → 12/1,029, 53.7% → 54.1% of item lines), 57% of the growth landed inside it, and the float candidate the re-review most expected to have become separable got *worse* (co-change 25% → 20%). Two previously unenumerated seams turned out genuinely acyclic and scored 25% and 15.4% against the accepted `stmt` cut's 33–36% — structural closure without change locality. **A review is now a licence that expires**: `test_no_review_licence_outlives_the_file_it_was_written_for` fails when a reviewed file drifts more than 150 LOC past its last blessed size, and the re-review happened BEFORE the baseline was refreshed |
| 1,668 | `ir/structure.rs` | 3 cuts; 2,607 -> 1,668. `detect_if_shape` (353 lines) measured as the next cut |
| 1,650 | `ir/ast.rs` | 8 cuts; 11,582 -> 1,650, **-86%**. The file this program started on |
| 1,422 | `python_bindings/ir.rs` | 3 cuts; 2,738 -> 1,422. Seven of its eight PyO3 items would be mis-cut by a keyword scan — the attributes sit between doc and item |
| 1,327 | `ir/call_args.rs` | 7 cuts; 3,920 -> 1,327 |
| 767 | `ir/stack_locals.rs` | 4 layers out; 3,241 -> 767. **First file taken below 1,000**, review entry deleted |

Not decompiler files, but they are what `product_max_loc` now points at:
`analysis/java_class.rs` 2,644 (untouched), `symbolic/solver/mod.rs` 1,710,
`python_bindings/analysis.rs` 1,901, `ir/value_number.rs` 1,965.
`symbolic/explore.rs` (2,742 -> 901) and `symbolic/solver/axeyum_backend.rs`
(3,357 -> 925) were cut on 2026-08-18 and are off the list.

Two things this table has already earned. It is **measured, not remembered** — a
priority list without sizes ranks by when someone wrote the list rather than by
where the mass is. And it is measured with a tool that was itself wrong until
`afbabb4c`: `strip_test_items` matched only the literal `#[cfg(test)]`, so 1,053
lines of test code counted as product, 877 of them in `analysis/cfg.rs`, which
was reported at 6,248 and is really 5,371. **A number in this file is only as
good as the last time someone checked the instrument.**

That sentence earned itself again on 2026-08-18: **nine of the ten rows in the
previous version of this table were stale**, by as much as 5,159 LOC, and one of
them — `ir/ast/dec_render.rs` — was presented as a shrink while the file had
actually grown. A table that exists to stop people ranking by memory had itself
gone back to being remembered. It is now regenerated from
`tools/fitness_report.py:product_loc` rather than edited row by row.

Regenerating it by hand is still a manual act, and on 2026-08-18 three rows
had gone stale again within a day (`lift_x86.rs` +43, `ast.rs` +11,
`java_class.rs` listed at 2,644 "untouched" when it had been split to 509).
So the growth case no longer depends on anyone rebuilding this table:
`tools/fitness_report.py --check-ratchet` now prints a **per-owner trend**
line for every oversized file that grew since the committed baseline. The
aggregate measures could not do this — `product_loc_above_1000` is a SUM, and
with 15,978 lines of slack against the baseline any single file could grow by
that much while the ratchet printed "no regressions", which is exactly what
happened to `dec_render.rs`. It is reported, not enforced: an oversized file
grows when a defect inside it is fixed, and a gate that fails on that teaches
people to stop fixing them.

Priority splits, performed only as ownership migrates:

- `ast.rs`: HIR model, projection, visitors, verifier, declaration planning,
  cleanup, and renderers.
  **In progress — the renderers came out first.** 19,269 -> 15,934 lines,
  11,582 -> 8,247 PRODUCT LOC, **down 29%** in three cuts across 2026-08-16/17:
  `ast/dec_render.rs` (2,170 lines, `a792b9a`), `ast/ctx_render.rs` (746 lines,
  `3c1bb91`), `ast/c_render.rs` (562 lines, `63a2a42`), after
  `ast/declaration_plan.rs` and `ast/width_semantics.rs` earlier. All three
  verified pure — `@o0`/`@o2` at 370 lanes with **zero regressions AND zero
  improvements**, an improvement being as suspicious as a regression for a move —
  and dead code checked in both configurations each time (0 with
  `--features python-ext`, 97 without).

  Three things learned that apply to every remaining split here:

  - **Derive the boundary from the call graph, never from line numbers.** A
    stated range was wrong at an edge **all three times**, in both directions.
    The dec cut: `render_with_types` was physically inside the dec block while
    calling `write_stmt_ctx` — it is the ctx renderer's front door and is
    production-used from `python_bindings/ir.rs` at three sites. The ctx cut: two
    listed items stayed as shared vocabulary and eight unlisted ones moved. The c
    cut: the shared-vocabulary list named `binop_sym`/`cmpop_sym` and omitted
    their `_c`-suffixed siblings, which sit at the END of the named range and are
    called from `dec_render.rs` at four sites.
  - **A descendant module already sees its ancestor's private items**, so leaving
    a shared helper behind is FREE and moving one costs a `pub(super)` plus a
    re-export to buy nothing. Visibility cost across the three cuts: one
    `pub(super)`, then **zero**, then **zero**.
  - **"Lowering" is not a mechanical move and must not be attempted as one.**
    Measured three times independently — ~2,570 lines across four tangled
    concerns, then 3,208 physical lines by section boundary, then 3,208 again. It
    needs its own call-graph boundary pass. One tangled sub-concern is already
    identified: the loop-hoisting-safety helpers have a unit test inside
    `ast.rs`'s own `mod tests`, so a cut there forces a decision about whether
    tests move with them.

  Next cut, recommended over lowering: the **ABI-width refinement block**
  (`ast.rs` ~3926-5103, roughly 1,100-1,180 lines). It has a single `pub(crate)`
  production front door, `refine_decbench_abi_widths_with_value_widths`, called
  from exactly two sites in `python_bindings/ir.rs`, and reads as one coherent
  concern — recovering and propagating integer widths for the declaration plan —
  with `declaration_plan.rs` already a sibling for exactly that. **Not yet
  caller-verified**; that verification is the prerequisite, and unlike the three
  renderer cuts it would land over 1,000 LOC and need a `REVIEWED_LARGE_MODULES`
  entry. `dec_render.rs`'s expression/statement seam is **done** (2026-08-17):
  the seam is real and the call graph made it exact — `write_stmt_dec` plus
  seven helpers, no caller outside that set, against an expression side that is
  a *closed* sub-graph never calling a statement printer. It left as the
  `dec_render::stmt` **child** module (526 lines), which is why it cost zero
  widenings: a descendant already sees its parent's privates. 2,195 -> 1,727,
  and `product_files_above_2000` 13 -> 12. **That was the last acyclic seam in
  the file, and the expression side is now closed to further splitting
  (reviewed 2026-08-18).** Four candidates were derived from the items and
  measured: a `dec_render/float.rs`, the call-argument family, the
  destination/representation cluster, and the six pure pattern-recognisers.
  All four cut through a single 11-function, 903-line strongly-connected
  component that is 54% of the file's item lines, and none reaches the
  co-change cohesion the `stmt` cut scored (36% of its commits touch nothing
  else in the file; the best remaining candidate is 24%). The float
  hypothesis in particular fails on its own evidence: one function renders
  floats, the scalar-float intrinsic tables are already `ast/float_gate.rs`,
  and the union type-punning predates this file. The one candidate that is
  structurally closed — zero outbound references — has the WORST co-change
  score of the five, at 11%, which is the reason to measure change and not
  just the call graph.
- `lift_x86.rs`, `lift_arm32.rs`, `lift_arm64.rs`: shared builder plus
  instruction-family modules.
- `call_args.rs`: ABI classification, evidence, solver, and HIR projection.
  **Two of those four names do not describe this file (measured 2026-08-17).**
  "HIR projection" has NO CODE: the file's input and output are both `ir::ast` —
  every function rewrites `Function`/`Stmt`/`Expr` in place, so there is no
  lowering stage to cut. "ABI classification" is not a cluster but the
  shared-helper trap: six helpers totalling ~100 LOC, most of them one-line
  delegations to `crate::ir::abi`, every one called from `fold_one_call`. The
  "solver" is real and enormous — `fold_body`'s exclusive subtree is 2,056 LOC
  behind a single entry point. "evidence" is real but is four disjoint clusters.
  The seams that exist, with the cost of each: tail-call recovery 249 LOC / 0
  widenings, 32-bit cdecl outgoing args 394 / 1 (taken, `90e791e5`), return-value
  attribution 246 / 3, incoming-slot evidence 503 / 4, ARM-AAPCS layout 390 / 7,
  arg read-write marking 402 / 7.
- `types_recover.rs`: constraints, collection, solving, prototypes, and language
  spelling.
  **Two of those five do not exist in the file, and a third is two things
  (measured 2026-08-17).** `grep -ci constraint` returns **1**, in prose: there is
  no constraint type, no constraint list, no worklist. There is no **solver** —
  every fixpoint is an inline bounded loop inside the pass that needs it,
  `for _ in 0..8` at six sites. **"collection" is two independent passes** with
  different keys and different outputs, `recover_types` -> `TypeMap` (669 LOC)
  and `recover_types_valued` -> `TypeMapV` (954, taken in `90e791e5`), and naming
  them as one hid that they are the two largest cuttable units after prototypes.
  **"prototypes" is 1,927 LOC — half the file** — and needs its own boundary
  pass. **"language spelling" is 43 LOC across two functions**, not a module.
  The honest shape is: spelling 43, fact stores 365, prototypes 1,927, raw
  collection 669, value-keyed collection 954.

  This entry was written from an idea of what type recovery looks like rather
  than from the file. Treat every other line in this list as unverified until
  someone measures it the same way.
- `stack_locals.rs`: frame analysis, object construction, access recovery,
  promotion, and naming. **Measured 2026-08-17 — four of the five are real,
  one is not.** Of 3,241 product LOC: **promotion 1,076** (five public entry
  points, the 162-line driver, `rewrite_body`, `rewrite_expr`,
  `promote_address_taken_stack_object`, `reconcile_late_address_taken_objects`),
  **frame analysis 752** (the anchor predicates and `StackContext` at 252, plus
  500 in the two bounded monotone analyses `collect_label_stack_deltas` and
  `collect_stack_address_defs`), **access recovery 720**, **object construction
  362** (one function, `seed_indexed_stack_objects`), the **data model 97** —
  and **"naming" is 141**: a 121-line `alloc_name`, a nine-line reservation
  helper, and an eleven-line counter struct. That is a function, not a module,
  and it is the same mistake as `types_recover`'s "language spelling". The
  entry also inherited the size table's "untouched", which was wrong in a
  second way: the file was already three, with `address_aliases` (697) and
  `bounded_overlap` (62) as descendants, so its real footprint was 4,000 LOC
  over four files. Four layers are now out — `address_recovery` (750),
  `coordinate_flow` (526), `indexed_objects` (378) and `rewrite` (912) — a
  textually pure move costing 15 `pub(super)` on moved privates and **zero**
  `pub(crate)`/`pub`. The fourth cut took the file to **767**, the first time
  this program has moved a file from above 1,000 to below it, which is also the
  only way `product_loc_above_1000` sheds a whole remainder rather than a
  difference (61,896 -> 60,201, of which 1,695 is this file leaving the set).
  What is left is one thing: five public entry points, the driver, the
  frame-anchor predicates, `StackContext`, the data model, naming, and
  `stack_arg_layout`. Its `REVIEWED_LARGE_MODULES` licence has been deleted.
- `structure.rs`: graph algorithms, regions, selection, verification, and HIR.
- `python_bindings/ir.rs`: the LLIR dict encoder and lift entry points, the
  shared LLIR/AST stage pipeline, and the DecBench renderer — leaving the PyO3
  adapters.
  **Done in three cuts, 2026-08-18. 2,738 -> 1,422 PRODUCT LOC, down 48%**, and
  the file stopped being the tree's largest (`product_max_loc` 2,738 -> 2,644,
  now `analysis/java_class.rs`). `ir/lift.rs` (396) took `encode_op` and its
  seven helpers plus `lift_for_arch`/`lift_bytes`/`lift_window_at` — the dict
  shape the module header documents, and its producers, in one owner.
  `ir/pipeline.rs` (504) took `run_ast_passes`, `prepare_llir_for_lowering`,
  `PreparedLlir` and the four stage helpers that the four Python entry points
  share. `ir/decbench_render.rs` (461) took prepare/verify/render of the
  DecBench C artifact. `@o0`/`@o2` at 376 lanes and `@returns`/`@aggregates`
  (i386/armv7/aarch64) with **zero regressions AND zero improvements**; dead
  code unchanged in both configurations (0 with `--features python-ext`, 98
  without); `MISSING: 0` on both the code-token and the comment-word multiset.

  Two things this split adds to the three learned from `ast.rs` above:

  - **The named destination was fiction and the "thin adapters" premise was
    false.** This entry used to read "thin adapters over session, engine, and
    typed results". `session` existed; `engine` and `typed results` named
    nothing that was ever built. And the four largest items in the file were not
    adapters at all — `decbench_text_with_installed_environment` (349),
    `encode_op` (212), `run_ast_passes` (188) and `prepare_llir_for_lowering`
    (123) are the pipeline itself, which is why the real seams came out as
    lift/pipeline/render rather than as the three the entry promised.
  - **Moving a `#[pyfunction]` needs a check no Rust test performs.**
    `register_ir_bindings` is the only thing that puts an adapter on the module,
    and it is a plain function body: drop a `wrap_pyfunction!` line and the crate
    still compiles, `cargo test --features python-ext` still reports 2,613
    passing, and the dead-code count stays at 0 — the API just quietly loses a
    function. Keeping the registration list byte-identical is necessary but not
    sufficient evidence, so the module surface was enumerated after the move: 8
    attributes on `glaurung._native.ir` (`DecompilerSession` plus the seven
    functions, unchanged), and `lift_bytes` was then called on real x86-64 bytes
    to prove the moved adapter and the moved encoder still meet.

End-state fitness targets:

| Measure | Target |
|---|---:|
| Product-code mean | below 450 LOC |
| Product-code median | below 250 LOC |
| Product files above 1,000 LOC | at most 35 |
| Product files above 2,000 LOC | at most 5 |
| Product LOC in files above 1,000 | below 25% |
| `src/ir` median | below 500 LOC |
| `src/ir` files above 1,000 LOC | at most 5 |
| **Largest product file** | **below 1,000 LOC** |

The last row was added 2026-08-16 (`a792b9a`) and is the one to judge this
program by. Every other measure is a count or an average, and a decomposition
that is *working* pushes several of them the wrong way: splitting a 19,269-line
file into 17,148 + 2,170 necessarily adds a file to both "above N" buckets and
moves both medians. `product_max_loc` went **11,582 -> 8,247** across the three
`ast.rs` renderer cuts — down 29% — and it is the only measure that saw the
work.

- [x] Add a reporting and ratchet check for these measurements. `tools/fitness_report.py`
  measures them over `src/` (test files/modules and generated tables excluded) and
  prints each current value against its target; `tools/fitness_baseline.json` is
  the committed baseline and `python/tests/test_fitness_report.py` fails the
  suite if a fresh measurement is worse than that baseline. The targets
  themselves are not met yet (see Entry 19 in the diary for current numbers) --
  this box is only the measurement and ratchet infrastructure, not the fitness.
- [x] Reject new production modules over 1,000 LOC without a documented review.
  `python/tests/test_large_module_review.py` ratchets the SET, not the count.
  `product_files_above_1000` above is a count, and a count cannot see a swap: a
  change that splits one owner below the line while pushing a new one over it
  leaves the count unchanged and the baseline ratchet silent. The new module
  holds `REVIEWED_LARGE_MODULES`, one entry per file currently over 1,000
  product LOC (28 today), each carrying the review that admits it — "scheduled
  split" for the nine named in the priority-split list above, "accepted" for the
  rest. An unlisted file over the line fails the suite; a listed file that drops
  below it also fails, so a landed split takes its licence with it instead of
  leaving a standing permission to re-cross. Proven by adding a real 1,400-line
  `src/ir/audit_probe_blockb.rs` (the gate failed naming it, and passed again on
  removal) and by a `tmp_path` case showing test-only and `@generated` files are
  correctly not counted. `ir/x87.rs` (`dcc62aa`) is the worked example the gate
  formalises: it crossed 1,000 LOC, the count ratchet fired, and the reasoning
  went into a commit message with nowhere permanent to live.
- [x] Exempt generated tables/data only; mixed-responsibility logic is not an
  exemption. `tools/fitness_report.py::is_generated` exempts a file only for an
  `@generated`/`DO NOT EDIT` marker in its first 20 lines, and
  `python/tests/test_fitness_report.py::test_a_marker_past_the_header_window_does_not_exempt_the_file`
  pins the window so a generated-looking table buried inside a hand-written file
  cannot buy an exemption for the logic around it. Measured 2026-08-15: **zero**
  files in `src/` are currently exempt under this rule, so the exemption is a
  closed door rather than an unmeasured one.
- [x] Add dependency checks: renderers cannot import lifters, HIR cannot parse
  images, targets cannot import renderers, and correctness cannot depend on
  environment variables. All four are enforced by
  `python/tests/test_src_dependency_boundaries.py` as source-text checks over
  the checked-out `src/`, with `#[cfg(test)]` items and whole-line comments
  stripped first so a fixture or a rustdoc link cannot read as a dependency. The
  environment rule is the strictest of the four: every `std::env::var`/`var_os`/
  `vars()` read in production code must appear in `ENV_VAR_ALLOWLIST` with one
  of six reviewed categories, the list is two-sided (a stale entry fails too),
  and a separate tripwire fails if a category outside that six is ever
  introduced — the categories deliberately have no slot for "changes what counts
  as correct". Tightened 2026-08-15: the renderer/HIR rules now discover their
  file list (`ir/ast.rs` plus everything under `src/ir/ast/`) instead of naming
  one file, so each submodule Phase 7 carves out of `ast.rs` is covered on
  arrival rather than escaping the boundary until someone remembers to add it.
  The rules are stated against today's layout, where the renderer and HIR share
  one owner and `src/render/`, `src/lift/` do not exist yet; when the physical
  split lands the file lists get updated, not deleted.
- [~] Delete compatibility owners promptly after their consumers reach parity.
  Honoured once and not yet overdue anywhere, but there is no gate. Executed:
  `src/ir/memory_objects/llir.rs` was deleted in `34b17c2` together with its
  producer-less `AccessSource`/`MemoryStateIdentity` variants once `mir::attach`
  superseded it. Remaining: `src/ir/memory_objects/ast.rs`, the prepared-AST
  compatibility adapter, which EPIC 3 above deliberately retains as production
  authority precisely because its consumers have NOT reached parity — so nothing
  is currently overdue for deletion. What is missing is the enforcement: the
  closest proxy is the never-used-function count from
  `cargo build --features python-ext` (0 today, and it is what found
  `llir.rs`), but a superseded owner that still has one live caller is invisible
  to it. First step: record each compatibility owner with the parity condition
  that retires it, so "promptly" has a measurable trigger.

## Performance plan

Improve performance through avoided work first, then profile-led local tuning.

- [~] Parse object and debug data once per session; continue removing remaining
  independent parsers.
- [~] Cache artifacts by image revision/hash, target, function, pipeline version,
  configuration, and exact dependency revisions.
  Audited 2026-08-15. Three in-memory caches exist and none of them is keyed on
  the tuple this box names. `RenderKey` (`src/python_bindings/ir/session.rs:11`)
  is `{func_va, max_blocks, max_instructions, timeout_ms, types, style,
  max_functions}`; `DiscoveryKey` and `EnvironmentKey`
  (`src/program/session.rs:24`, `:34`) are budget scalars plus seeds/VAs. Of the
  six named key components: **function** is present (`func_va`, normalised);
  **target** is absent but sound by construction, since the target comes from
  the image and the image is fixed for the session's lifetime; **configuration**
  is present only as budgets, and there `EnvironmentKey` omits `total_timeout_ms`
  even though `recover_program_environment` inherits it into a `Deadline`
  (`src/program/environment.rs:842`) — two calls differing only in whole-run
  ceiling share one cached environment; **image revision/hash**, **pipeline
  version**, and **dependency revisions** are absent everywhere (there is no
  `pipeline_fingerprint` symbol in the tree at all, which is the still-open
  fingerprint box in the HIR section). Cache identity is therefore object
  identity — "the same `ProgramSession`" — which is safe only because nothing
  persists (see Phase 8). Note also that `diagnostics_are_disabled()`
  (`src/python_bindings/ir/session.rs:195`) bypasses the artifact cache entirely
  whenever any of five `GLAURUNG_*` diagnostic variables is set: correct, since
  those paths have side effects, but it means the cache vanishes under exactly
  the conditions you would measure it.
- [~] Analyze call-graph SCCs to fixed point instead of repeatedly relifting
  callees from each root.
  The condensation now exists — `src/program/call_graph.rs`, deterministic
  Tarjan over `FunctionId`, reached by `ProgramSession::call_graph()`. The fixed
  point does not; the callee path is still bounded re-lifting.
  **This box's stated first step was wrong and must not be followed.** It said
  to stop discarding the `CallGraph` at `session.rs:263`. That value is unfit
  for the purpose: its `nodes` are captured before the rename passes and its
  edges after, so it fails its own `CallGraph::validate()` on a hello-world
  (`Err("Edge references unknown caller function: _start")`); only callees are
  ever added as nodes, so every root is missing from `nodes`; and 41% of its
  nodes on that binary are `sub_<hex>` strings with no function behind them.
  The graph is instead built from `Function::callees`, which discovery already
  populates and the session already caches. `session.rs` now carries a comment
  saying why the return value stays dropped. Full measurements in
  `docs/design/function-facts-and-call-facts-2026-08-15.md` §6.
  On the truncation this box cites: it conflated two separate concerns into one
  boolean. `NESTED_CALLEE_DEPTH` is now the depth limit and the sole termination
  guarantee, and the SCC condensation is a separate guard that declines to spend
  a layer inside a call cycle. Census over all 762 built fixture objects: 29%
  (222) have a call chain deeper than the truncation reaches, while the mutual
  recursion the truncation was written to avoid occurs in 1% (8).
  **The depth increase that census suggests was tried and is inert.** At
  `NESTED_CALLEE_DEPTH = 2`, 1457 decompiled functions over 300 fixture objects
  are byte-identical to depth 1, and `dectest @o0` + `@o2` (728 lanes) show no
  verdict change. Reverted to 1, with the negative result recorded at the
  constant. Consequence to be honest about: at depth 1 the SCC guard cannot
  change an outcome, so this box has a landed condensation and no consumer whose
  behavior depends on it yet.
- [~] Use immutable environment snapshots for function-parallel work and
  deterministic phase-barrier merges.
  The snapshot half holds: `ProgramEnvironment` is handed out only as
  `Arc<ProgramEnvironment>` (`src/program/session.rs:281`), discovery results as
  `Arc<[Function]>`, and `ProgramImage` is `Arc`-of-everything behind
  `OnceLock` lazies. The function-parallel half does not exist — see the
  identical Phase 8 box.
- [ ] Replace whole-HIR clones used for fixed points with change sets/epochs.
  No epoch or change-set mechanism exists (`epoch`/`ChangeSet`/`dirty` match only
  page tables, register halves and VEX call kinds). Two whole-`Function`
  clone-and-compare fixed points are still live on the render path:
  `src/ir/ast.rs:7185` (bounded at 4 iterations, one deep clone plus one full
  structural `PartialEq` walk each) and `prune_unreachable_tails`
  (`src/ir/label_prune.rs:35`), which is an **unbounded** `loop` with the same
  clone-and-compare shape and is called twice from the `prepare_for_decbench`
  chain. The dataflow fixed points are already change-flag driven and are not
  what this box is about. First step is smaller than "epochs": make
  `propagate_copies`/`fold_constants`/`prune_*` return whether they changed
  anything, which deletes both the clone and the equality walk with no new
  machinery. Do it for correctness of shape, not for speed — the section's own
  ~100 ms-of-285 ms accounting gap means there is no evidence these clones cost
  anything measurable.
- [~] Make expensive type/object/reference passes demand-driven and cacheable.
  `DecompilerSession` already caches artifacts and discovery per image, and the
  warm-query row is met through it (3081x on `hello-gcc-O2`, 271180x on
  `hello-rust-musl`). What is NOT demand-driven is the cold path itself.
- [~] Record per-pass time, allocations, graph sizes, iterations, cache hits, and
  invalidations.
  **Per-pass time is recorded** (`GLAURUNG_PIPELINE_PROFILE`) and was used for the
  first time on 2026-08-15. Allocations, graph sizes, iterations, cache hits and
  invalidations are not. Caution recorded with the measurement: instrumented
  stages account for only ~100 ms of a 285 ms run, so the timings are not yet
  complete enough to choose optimisation targets from.
- [~] Enforce per-function and per-session budgets plus cooperative cancellation.
  Both halves exist; neither reaches the decompile path. `Budgets`
  (`src/analysis/cfg.rs:31`) bounds functions, blocks, instructions and two
  clocks, and its own doc comments are the best evidence against ticking this:
  `timeout_ms` "has never bounded an analysis" because `discover_function`
  restarts its clock per seed, and the session-level `total_timeout_ms` defaults
  to `0` (no ceiling) for a recorded reason — a ceiling changes what discovery
  finds, and every corpus number was measured without one. Every decompile entry
  point hardcodes `total_timeout_ms: 0` (`src/python_bindings/ir.rs:1032`,
  `:1373`, `:2727`, `:2984`, `:3340`), so there is no session budget on that path
  at all. Cooperative cancellation is real and well built — `Deadline` with an
  `Option<&AtomicBool>` (`src/analysis/cfg.rs:74`),
  `analyze_functions_bytes_cancellable` (`:4438`), the signal-driven
  `analyze_interruptible` (`src/python_bindings/analysis.rs:227`), test
  `a_cancelled_analysis_stops_and_reports_the_truncation` — but its only two
  callers are in `analysis.rs`. The decompiler calls `discover_functions` with no
  cancel flag and interrupts only *between* functions via `py.check_signals()`,
  so one pathological function is uninterruptible and `DecompilerSession
  .decompile_at` has no cancellation point at all. No memory or allocation budget
  exists anywhere. First step: thread an `AtomicBool` from `decompile_all_py`'s
  existing `check_signals` site into `discover_functions` via
  `Deadline::with_cancel`; the plumbing can be lifted verbatim from
  `analysis.rs`.
- [x] Profile before changing arenas, layouts, allocation, or parallel granularity.

Performance acceptance on the pinned host:

| Measure | End target |
|---|---:|
| 224-binary wall, 12 workers | below 45 s |
| Per-binary median | below 2.0 s |
| p95 | below 4.0 s |
| Slowest bounded case | below 15 s |
| Base object parses/session | exactly one |
| Warm identical-function query | at least 5x faster |

Coverage, completeness, errors, and tail latency must accompany every speed
claim. Timing out more work is not an optimization.

**Measured for the first time, 2026-08-15.** Over the 138 real binaries in
`samples/binaries` (of 400 files attempted; the other 262 are not object files
and fail with `Unknown file magic`), via `g.ir.decompile_all(..., limit=250)`:

| Measure | Target | Measured | |
|---|---:|---:|---|
| Per-binary median | below 2.0 s | **0.022 s** | met |
| p95 | below 4.0 s | **2.15 s** | met |
| Slowest bounded case | below 15 s | **5.19 s** (`hello-go-static`) | met |
| 224-binary wall, 12 workers | below 45 s | 41.7 s for 138, **sequential** | met |
| Base object parses/session | exactly one | 58 -> **19** | closer; see below |
| Warm identical-function query | at least 5x | **3081x** | met |

Restricted to the 50 binaries with 50 or more functions, the median is 0.192 s,
p95 2.65 s, and the median cost is 1.67 ms per function.

So speed is not the problem, and optimising it would be work aimed at targets
already met.

The warm-query row must be measured through `DecompilerSession` — "reusable
decompiler state for repeated queries against one immutable image" — which is
the API the row is about. Measuring repeated `decompile_many` calls instead
rebuilds the session every time and reports 1.98x, which is the cost of NOT
having a cache rather than the benefit of having one. Through the session it is a
straight cache hit: 2.524 ms cold to 0.001 ms warm on `hello-gcc-O2`, and 163 ms
to 0.001 ms on `hello-rust-musl`.

The remaining gap is architectural, and it is the one this section's own plan
predicts. `object_parse_count` was **58** for 49 functions on `hello-gcc-O2`, and
**40,865** for `hello-rust-musl` at the default limit — the count scaled as
`O(functions) + O(branches) + O(callees)` and varied run to run on the same
binary. It is now **19 and constant**, the same 19 for both binaries at any
limit. The residue is 19 distinct one-shot analyses; reaching exactly one needs a
relocation/symbol index on `ProgramImage`.

Worth recording for the next person who optimises here: re-parsing was NOT worth
the time it appeared to be. An ELF `File::parse` reads a header and a section
table, about 12 us, so removing 40,848 parses from the `hello-rust-musl` run
moved wall time not at all. The gap between instrumented stages (~100 ms) and the
285 ms run is still unexplained, and it is not this.

The accounting also does not close: instrumented stages sum to roughly 100 ms of
that 285 ms run, so most of the wall time is outside any named stage. Until that
gap is explained, per-stage timings should not be used to choose what to
optimise.

## Safety and reliability plan

- [~] Replace semantically ambiguous `Option` results with typed errors or
  partial artifacts carrying exact reasons and affected ranges. **The lifter
  boundary is done** (entry 35): `lift_function_from_bytes`/`_from_image` return
  `Result<LlirFunction, LiftError>` with three distinguishable reasons, and
  `LiftError::NoLiftableBlocks` carries the exact disowned VA ranges. Two
  analyst-visible Python messages that guessed at the reason were replaced with
  the real one. Other ambiguous `Option`s remain; the ranking is in entry 35.
- [ ] Attach address, instruction, operand, and source origin to every lifted
  instruction and value.
- [ ] Preserve skipped bytes and unresolved CFG edges to API diagnostics.
- [x] Validate target/mode/ABI combinations before lifting. `validate_code_mode`
  and `validate_target_mode` resolve one `CodeMode` before any byte is decoded,
  and `lift_window` now matches on that mode exhaustively instead of on
  `(arch, thumb)` with a silent `_ => Vec::new()` arm. A Thumb marker on a
  non-ARM target is a typed rejection naming the function (entry 35).
- [~] Require declared register and memory effects for every call/intrinsic.
  Censused, not asserted (entry 35): `ir::effect_census` measures the corpus, the
  last `Op::Unknown` escape into a public API is closed, and two invariant tests
  hold the line. `Op::Unknown` still exists as the per-arch lifters' internal
  marker, deliberately — entry 35 records why it cannot be deleted yet.
- [ ] Verify every IR boundary and every graph-changing pass.
- [ ] Keep manual/debug facts immutable by default; inference cannot overwrite
  them.
- [ ] Fuzz decoders, register contracts, lifters, importers, reference resolution,
  MIR editors/verifiers, project input, and persistence schemas.
- [ ] Add crash recovery and schema migration tests for persisted projects.
- [ ] Make cancellation prompt and return a typed partial artifact.

## DecBench and evaluation

Moved. See [Appendix A](#appendix-a--decbench-and-evaluation-on-demand-only) at
the end of this file.

It is an appendix rather than a section because it is not a work queue. The
project's correctness ground truth is `tests/decompiler_fixtures/`, which
compiles the corpus, executes the recompiled decompiler output, and diffs it
against the original. GED / TypeMatch / ByteMatch measure something else, on a
harness that costs tens of minutes per run and reports its own resource
contention as cell failures. Reach for the appendix when refreshing the paper or
preparing a submission artifact — not to decide what to work on next.

## Dependency-ordered execution phases

### Phase 0 — Evidence and attribution

**Outcome:** a change cannot hide behind stale caches, denominators, toolchains,
or aggregate scores.

- [x] Deterministic score ledger and exact function-key joins.
- [x] Stable metric/canary sets and output-health counters.
- [x] Pass-attributed output traces and pass-fire instrumentation.
- [x] Cold/warm/resource and pipeline baselines.
- [ ] Refresh the canonical ledger for each exact release artifact.
  Audited 2026-08-15: this is a standing process obligation, not an artifact, so
  it can only ever read "currently satisfied" — and it is not. The ledger is
  `tools/decbench_score_ledger.py` over
  `tests/decbench_scoreboard/baseline-ledger.json`, which pins
  `baseline_revision c1cfdc9` and `glaurung-c1cfdc98-results.zip`; it was last
  written by `d1bfd14` (2026-08-08) and has never described `fb4ee6b`. `c1cfdc9`
  is 171 commits behind HEAD, `fb4ee6b` 64. First step: it needs a DecBench
  evaluator run, which is out of scope here, and it folds into the two sibling
  items below it that also await one.
- [x] Add the A32 and GCC 15 control lanes.
  Done in `e2b76a4` (2026-08-06) and audited 2026-08-15 — this box is a stale
  duplicate of the two already-`[x]` items in the score-campaign list above
  ("Add and evaluate the A32 `-marm` lane", "Rebuild the x86-64 control with
  GCC 15"). Both lanes are real, not relabels: `tools/arch_roundtrip.py:194`
  compiles `armv7_a32` with `-marm` against `armv7`'s `-mthumb`, and
  `x86_64_gcc15` (line 162) is the unpinned host `gcc 15.2.0` against the
  control's pinned `gcc 11.4.0`. Both are in `REQUIRED_ARCHES`, asserted by
  `test_arm32_required_lanes_select_distinct_instruction_sets` and
  `test_gcc15_x86_64_shape_control_is_required_and_host_built`. Both are fully
  populated: 364 cells each in `arch_baseline.json`, no skips, no nulls, no
  empty cells. They are not copies of their siblings — 40 of 364 `armv7_a32`
  cells differ from `armv7`, and 33 of 364 `x86_64_gcc15` cells differ from
  `x86_64`. (The "350 ratcheted lanes" in the two older items is stale; it is
  364 now.)
- [~] Close the linked-list ByteMatch investigation and AArch64-only diagnosis.
  Audited 2026-08-15; both halves moved, neither closed.
  **ByteMatch:** root-caused, not re-measured. `defect-register-2026-08-05.md`
  lines 644-687 withdraw the "structurally closer" explanation this roadmap
  still objects to, bisect the drop to `b2003b5`, and record the recovery to
  0.31 through `199af22`/`9a6f627`/`1fc76ab`, attributing the residual to
  recompiling a Clang 21 binary's output with GCC 15. That argument has not been
  re-scored on the current artifact, which is the same blocker as the ledger
  item. First step: restate this bullet as "re-score `linkedlist:clang:O0` and
  confirm the residual is still cross-compiler", and run it with the ledger.
  **AArch64:** partially diagnosed. `039c7d6` lifted AArch64 scalar float and
  measurably moved 12 fixture functions fail->pass with 0 pass->fail, but diary
  Entry 23 splits the 94-strong set as 22 float-adjacent (diagnosed, fixed), 7
  `141_atomics` (diagnosed as missing `ldar`/`stlrb`, NOT fixed), and 65 with no
  float instruction and no cause identified. Recomputed from `arch_baseline.json`
  at HEAD the set is 93, still led by `141_atomics` at 7. First step: the 7
  `ldar`/`stlrb` cells, which are a named decoder gap rather than an
  investigation.

### Phase 1 — One session, image, pipeline, and artifact boundary

**Outcome:** remove repeated parsing and entry-point drift while preserving
behavior.

- [x] Land `ProgramImage` and `ProgramSession` foundations.
- [x] Route public entry-point shapes through shared session data.
- [~] Continue moving debug, symbol, relocation, string, unwind, and format data
  behind the session.
- [~] Carry typed diagnostics/completeness through discovery, lifting, recovery,
  HIR, and rendering.
  Audited 2026-08-15: four stage-local typed signals now exist, and none of them
  travels. Discovery has `dispatch::Unresolved`'s `UnknownBase`/`NoTableAt`/
  `NoBound` decline reason, serialized by `4ad8800`. Lifting has `LiftError`
  (`eed4b75`) with `UnsupportedArchitecture`/`IncoherentCodeMode`/
  `NoLiftableBlocks { disowned ranges }`. MIR has `EffectCompleteness`. Rendering
  has `verify_before_render` and `verify.rs`'s `ResidualUnknown`. There is no
  common carrier — a repo-wide grep for a `Diagnostic`/`Diagnostics` type returns
  nothing — and the typing dies at the artifact boundary: `decompile_at` flattens
  `LiftError` into a `PyValueError` string, losing the variant and the disowned
  ranges, while `decompile_all` and `decompile_many` discard it entirely with
  `let Ok(lf_raw) = lift_function_from_image(..) else { continue; }`. That is the
  same silent-`continue` shape `eed4b75` removed from `xrefs.rs`, still present on
  the two whole-program entry points. First step: give the whole-program entry
  points somewhere to put a `LiftError`, so a skipped function is a reported
  incompleteness rather than an absent row.

  **Re-audited 2026-08-16, and the discovery half now has a reproduction rather
  than an argument** (diary Entry 55). The 2026-08-15 audit found the *lifting*
  signal dying at the artifact boundary. The *discovery* signal dies one line
  earlier and more completely, at `src/analysis/cfg.rs:4351`:

  ```rust
  let (functions, cg, _stats) = analyze_functions_bytes_within(...);
  ```

  `analyze_functions_image_with_seeds` is the only discovery entry point the
  decompiler uses — `ProgramSession::discover_functions` (`src/program/session.rs:272`)
  calls it, and `decompile_at_session`, `decompile_many` and `list_functions` call
  that. All five truncation flags die on that underscore, including the one that
  fires in practice. The discarded struct documents the rule the discard breaks
  (`src/analysis/cfg.rs:203`): *"A consumer that treats this result as a complete
  function list is wrong, which is why it is reported rather than absorbed."*

  Reproduced on the shipping API against `0x1401fd8a0` in `NETwtw10.sys`
  (`uv run python $CLAUDE_JOB_DIR/tmp/measure_truncation_visible.py`):

  | `max_blocks` | CFG blocks | `truncated` | rendered chars | output says so |
  |---:|---:|---|---:|---|
  | 4096 | 643 | `False` | 153,068 | — |
  | 256 | 256 | `True` (`hit_block_limit`) | 61,942 | **no** |
  | 64 | 64 | `True` (`hit_block_limit`) | 17,833 | **no** |

  387 of 643 blocks vanish, 60% of the body disappears, and the pseudocode carries
  no marker. That is stop condition 1 verbatim.

  Two corrections to earlier text in this file. **The wall clock is not the
  problem.** This box's neighbour in the performance section already says
  `timeout_ms` "has never bounded an analysis"; measurement confirms it end to end
  — 5000/500/100 ms give identical function counts *and* identical runtimes on a
  4.9 MB driver (`measure_timeout.py`). The limit that bites is `max_blocks`.
  **And it is rare but biased**: 0.04%–0.10% of functions exceed the shipping
  budgets (`measure_instr.py`), about ten per large binary — but they are the
  largest and most complex ones, and `python/glaurung/llm/finding_verifier.py:139`
  decompiles every vulnerability candidate at `max_blocks=256,
  max_instructions=2_000`, below both thresholds. A verifier reasoning about 40%
  of a function while believing it holds all of it is the failure this box exists
  to prevent.

  **The discovery half is CLOSED as of `3b437b1`, and the box stays `[~]` because
  three of the five stages it names are still open.** Four bits in the existing
  `FunctionFlags` word record which budget cut a walk short, written in
  `discover_function` from that single walk's stats *before* the merge into the
  whole-run aggregate — that ordering is the correctness property, and it is what
  makes it impossible for one function's budget hit to mark a different function
  incomplete. `decompile_at` and `decompile_many` render an analyst-visible note
  naming the budget and its value, and refusing to state how much is missing,
  because a bounded walk stops without enumerating what it did not reach. Proven
  on a second binary: one discovery at `max_blocks=2` over 38 functions marks 9
  and leaves 29 clean, with zero disagreements against their true block counts; a
  design reading the whole-run aggregate would have marked all 38.

  Four design predictions were recorded in diary Entry 55 *before* the work and
  **three were wrong**, including one whose reasoning was exactly inverted:
  putting the fact on `Function` was assumed to have the largest blast radius
  because it is a core data model with PyO3 bindings and serialization, and it
  measured smallest of four designs — 0 forced compile breaks against 36 for
  threading stats through `discover_functions`.

  Still open on the discovery stage, and smaller than what closed: nothing *acts*
  on the marker (`finding_verifier.py` is handed a body that says it is partial
  and neither retries wider nor downgrades confidence — that is the obvious next
  box); `hit_function_limit` and the unattributable half of `hit_total_timeout`
  remain whole-run facts still written to `_` at `src/analysis/cfg.rs:4351`; and
  `decompile_range_at` synthesises its own `Function` without discovery, so it is
  partial by construction and can never be marked.
- [ ] Establish one explicit pipeline stage list and deterministic fingerprint.
  Audited 2026-08-15: open, though the raw material is all there. Stage names
  exist only as string literals at the ~38 `pass!`/`refine!` sites in
  `python_bindings/ir.rs` plus a handful of hardcoded `profiler.measure` calls;
  one `decompile_at` emits 40 stage events. There is no enumerated list, no
  ordering contract, and no fingerprint anywhere in the crate. First step: make
  the stage name an `enum PipelineStage` in `decompile::profile` so the list is
  the type, then hash the ordered sequence into the existing `run` event.
- [~] Prove exactly one base object parse per reusable session.
  Substantially closed by `2ed9b07`; see the `ProgramSession` entry under
  "Foundations still incomplete" for the ownership work. Re-measured at HEAD
  2026-08-15 with `GLAURUNG_PIPELINE_PROFILE=1`: a whole-program `decompile_all`
  costs **20** parses and a single-function `decompile_at` **19**. Not one — but
  the number is now genuinely a constant. It is identical across `hello-gcc-O0`,
  `hello-clang-O2`, `hello-go-static` and the 1146-function `hello-rust-musl`,
  identical at `limit=50` and `limit=30000`, and identical between repeated runs;
  before the ownership work the same measurement was 58, 80, 3517 and 40,865 and
  varied run to run on the SAME binary. Note the 19 quoted previously was the
  `decompile_at` figure; whole-program is 20, and the constant has crept 17 -> 20
  across the six commits since, unnoticed, because the only pin was a
  `object_parse_count < 100` bound. That is now
  `test_object_parse_count_is_a_session_constant_not_a_function_of_the_binary`,
  which asserts the four-binary/two-limit equality directly and ratchets the
  bound to 20. The residue is a fixed set of one-shot program analyses; reaching
  one needs a relocation and symbol index on `ProgramImage`.
- [~] Expose stable reusable Python session/result APIs.
  Audited 2026-08-15. The SESSION half is done and the RESULT half has not
  started. `glaurung.ir.DecompilerSession` exists with `path`,
  `discovery_cache_stats`, `artifact_cache_stats`, `clear_caches` and
  `decompile_at`; it is typed in `python/glaurung/_native/ir.pyi`, and
  `test_decompiler_session.py` pins on a real compiled binary that a session
  query is byte-identical to the module-level `decompile_at`. What is missing:
  `decompile_at` returns a bare `str`, so there is no result object to carry
  entry VA, prototype, diagnostics or completeness; there is no whole-program
  query on the session; and the class has **zero production consumers** — the CLI
  and every tool still call the module-level functions, so nothing in the repo
  actually reuses a session. First step: give the CLI's multi-function paths a
  session, which is the consumer that would show whether the API is the right
  shape before a result type is designed around it.

### Phase 2 — Canonical target and exact lifted semantics

**Outcome:** widths, register views, ABI, effects, and target mode have one owner.

- [~] Finish canonical `TargetSpec` and migrate all consumers.
- [ ] Finish exact-width constants and operand provenance.
  Audited 2026-08-15: not started, and neither half is partially built.
  `ir::types::Const(i64)` and `ast::Expr::Const(i64)` carry no width — a doc
  comment on the former disclaims it, `expression_width` returns `None` for
  `Expr::Const`, and `ast::FloatConst { bits, width }` is the only width-tagged
  constant in the IR. Operand provenance is discarded at the source: the x86
  lifter's `value_of_operand` receives the operand index and drops it, and no IR
  value carries an operand reference; only `MirInstruction::source_va` survives.
  The shape already exists in `symbolic::expr::Const { value: u128, width }` and
  was never carried into `src/ir/`. First step: add `width` to `Value::Const`,
  which turns the 579 construction sites into a compiler-enforced worklist.
- [~] Complete shared register banks and generated view/write conformance tests.
  Audited 2026-08-15. The generated conformance tests EXIST and are the strong
  half: `ir::regview`'s `every_view_conforms_to_the_partial_write_rule` iterates
  every row of the bank (~377 views) rather than a hand-listed sample, with four
  more generated suites beside it. The bank is not shared, though: `regview::Arch`
  has exactly two variants, `X86_64` and `AArch64`. ARM32 is absent — `lift_arm32.rs`
  never mentions `regview`, and `abi::result_view_arch` returns `None` for
  `Arm | ArmHardFloat | Cdecl32` with the comment "ARM32 has none". 32-bit x86 is
  gated off inside the x86-64 table (views apply only when `bits == 64`). A
  second, unrelated abstraction — `target::registers::RegisterRoles` — does cover
  Arm32, but it is a four-role name table (sp/fp/lr/pc), not widths or views.
  Execution-level partial-write checks remain hand-written spot tests
  (`tests/register_view_semantics.rs`). First step below, shared with ARM32.
- [ ] Complete ARM32 A32/Thumb/PC/condition/VFP/ABI semantics.
  Open, and much further along than this line implies — audited 2026-08-15
  against the code, because "ARM32 is incomplete" is not actionable. ARM32 is
  still the worst lane in the corpus at 320/1288 = 24.8% failures against
  x86-64's 173/1345 = 12.9%, and design rule 11 makes it a conformance target.
  **Already landed** (not open, despite the item-4 note further down still
  listing three of these): PC bias `+8` A32 / `+4` Thumb and literal-pool
  resolution restricted to executable sections (`lift_arm32.rs:135-190`); A32
  condition codes decoded from bits 31:28 of the word rather than guessed from a
  mnemonic suffix; Thumb-2 IT blocks lowered to conditional selects; full NZCV
  including C and V on ADD/SUB; the modified-immediate rotation fold (`f1a6e4c`),
  which took ARM32's opaque-intrinsic rate from 6.6% to 6 instances in 2349;
  hard-float ABI SELECTION from `EF_ARM_ABI_FLOAT_HARD`; and 64-bit `r0:r1`
  return pairing with an executed round-trip test.
  **Actually remaining, in value order:** (1) VFP s/d/q overlap is not modelled
  at all, so writing `s1` does not touch `d0`; (2) consequently
  `abi::arm_hard_float_argument_slots` lists only `s0`..`s15` and has no `d0`..`d7`,
  so a double-precision argument is unrepresentable; (3) 64-bit integer argument
  register pairing and even-register alignment — `call_args` returns `None` for
  `long long`/`int64_t`/`uint64_t` and nothing implements the even-register skip;
  (4) logical-op `S` flags set only Z and N, with shifter carry-out and V
  deliberately unmodelled; (5) NEON entirely absent, and VFP
  `vcmp/vcvt/vabs/vsqrt/vmrs/vmsr/vmla/vsel` absent; (6) register-shifted-register
  and RRX explicitly declined; (7) LDM/STM base writeback is a conservative
  no-op; (8) LDREX/STREX, DMB/DSB/ISB, SVC, MSR/MRS and BFC fall to the
  `Op::Unknown` catch-all. `test_decompiler_arm32_semantics.py`'s six QEMU
  round-trips cover none of (1)-(5). First step: (1) and (2) are the same fact —
  an s/d/q overlap table in `regview::Arch::Arm32` deletes the `None` arm in
  `abi::result_view_arch`, admits ARM32 to the existing generated conformance
  suite above, and makes `d0`..`d7` expressible.
- [x] Widen the entry-stack coordinate model to ARM32.
  Done, and this box duplicates two already-ticked homes: the rank-ordered plan's
  item 4 and EPIC 4's Thumb frame-promotion bullet. `stack_locals::entry_stack_base`
  returns `"entry_sp"` for `Arm | ArmHardFloat | Aarch64`;
  `aapcs_entry_stack_coordinate` re-expresses `sp`-relative accesses in that
  coordinate for the same three; `is_arm_frame_pointer` covers `fp`/`r11` plus a
  prologue-proven Thumb `r7` anchor; and `dwarf_contracts` maps ARM
  `DW_OP_breg11/breg7` to `fp` and `DW_AT_frame_base=CFA` to `entry_sp`. Proved
  in both modes by `stack_locals/arm32_tests.rs`:
  `thumb_frame_register_shares_the_a32_entry_stack_coordinates`,
  `a32_frame_pointer_address_rejoins_the_entry_cfa_object`, and the negative
  control `thumb_scratch_r7_is_not_a_frame_anchor`. Commits `401ac4f` and
  `152d240`; the measured effect was that Thumb had been promoting NOTHING
  (`07_packet_parser` recovered 1 distinct local against A32's 25) and seven of
  eight Thumb lanes now match their A32 control exactly. The remainder is EPIC
  4's separate bullet on frame promotion, aggregate extents and argument homes.
- [x] Add the real A32 lane and differential execution coverage.
  Done in `e2b76a4`; same lane as the Phase 0 box above, and also ticked twice in
  the score-campaign list. The lane is genuinely A32 (`-marm` against `armv7`'s
  `-mthumb`, pinned by `test_arm32_required_lanes_select_distinct_instruction_sets`)
  and fully populated: 364 cells, 1288 checks, no skips or nulls, and 40 cells
  whose verdict differs from the Thumb sibling. Differential EXECUTION is real,
  not a structural check: the recovered C is recompiled with the target driver
  and executed under `qemu-arm` against the original ARM object through a
  generated dependency-free ILP32 worker, judged by the same `diff_decompile.py`
  the x86-64 gate uses, and `arch_roundtrip.py --check` refuses a scoped matrix
  so gate lane 3 always includes `armv7_a32`. Honest caveat: signatures outside
  the worker's subset fall back to a host LP64 rebuild guarded by `incomparable`
  / `nonportable`; the 10 `incomparable` cells are a proven lower bound on that
  fallback and the exact split was not measured.

### Phase 3 — Verified MIR and definedness authority

**Outcome:** every definition-sensitive transform asks one verified service.

- [x] Land typed MIR identities and baseline verifier.
- [x] Land region-aware MemorySSA and object identities.
- [~] Value-at, clobber, reaching-set, and memory-version queries are complete;
  the transactional mutation/invalidation API is still open.
- [ ] Model complete call/intrinsic effects.
  Audited 2026-08-15: not started, and it gates the next box harder than this
  ordering suggests. `mir::builder::register_effects` returns `Opaque`
  unconditionally for `Op::Call` and `Op::Unknown` (`builder.rs:349`), so every
  call poisons every unnamed machine storage; `grep -rn clobber src/target/
  src/disasm/` returns zero hits and `ir::types::CallEffects` has no clobber
  field. `call_contracts::apply_known_llir_call_contracts` narrows a call's READS
  from a catalog but never states a write footprint, and `register_effects`
  short-circuits before it would be consulted anyway. First step: a clobber set
  on `TargetSpec`, since the calling convention already lives there.
- [ ] Migrate high-risk consumers in order: call arguments, copy propagation,
  DCE, stack promotion, return recovery, expression reconstruction, aggregates.
  Audited 2026-08-15: zero of seven migrated; the listed order is probably wrong
  (aggregates are the cheapest, not the dearest). Full evidence under the same
  box in EPIC 5 above — this is the duplicate, not a second workstream.
- [ ] Delete migrated local approximations.
  Audited 2026-08-15: nothing deleted; `73bdca3` added one. See EPIC 5 above.

### Phase 4 — Function contracts and graph completeness

**Outcome:** values survive calls correctly and the structurer accounts for all
machine control flow.

- [~] Implement stable `FunctionFacts`/`CallFactStore` and SCC propagation.
  Audited 2026-08-15, then partly implemented the same day. **Landed:**
  `FunctionId` and `ProgramCallGraph` with a deterministic Tarjan condensation
  (`src/program/call_graph.rs`), owned by `ProgramSession::call_graph()` on the
  same `DiscoveryKey` as discovery, and read by the nested callee analysis in
  `python_bindings/ir/callee_contracts.rs`. **Not landed, each for a stated
  reason** (see `docs/design/function-facts-and-call-facts-2026-08-15.md` §6):
  `CallSiteId`/`CallFactStore` have no producer — `Function::callees` records
  targets but no call-site VAs, so this needs an `analysis/cfg.rs` change first;
  `FunctionFacts` has no fact worth storing yet — the only candidate with
  consumers is noreturn, which is a 21-name list today and whose principal
  consumer is CFG discovery itself, making a body-derived version circular with
  the function boundaries it would be inferred from.
  Two corrections to this box's own premise. First, its "first step" —
  retaining the `CallGraph` that `session.rs:263` drops — is wrong: that graph
  fails its own `validate()`, omits all roots from `nodes`, and is name-keyed.
  Second, the box is one of three homes for this item (EPIC 1, here, Phase 5);
  all three moved together.
- [x] Repair indirect-table call arity before DCE using reaching values.
  Done by `9952fc0`, with a correction to this box's premise: DCE was never the
  first wrong stage. `GLAURUNG_DUMP_PASSES` put the boundary at
  `copy_prop::remove_dead` inside `prepare_for_decbench`, which drops the
  argument setup because the call reads nothing — the deletion is the consequence
  of the empty argument list, not its cause. The repair is a union over a
  relocation-proven callee set, materialised as arguments before naming; a
  may-use set that is not materialised as arguments is cosmetic at the AST/C
  boundary. Residue (two loop-shape cells) is recorded under "Function contracts
  and indirect calls".
- [~] Complete terminal/indirect/switch/exception edge representation.
  Represented; not all of it reaches a consumer. `01f0b23` added
  `EdgeKind::Exceptional`/`Unknown` and the nine-variant `TerminalKind`, with the
  invariant that no block has zero ways out; `f1a6e4c` and `4ad8800` then split
  indirect terminals into `Indirect`/`IndirectToSymbol`/`IndirectThroughSlot`.
  Three gaps, in descending size:
  * **Exceptional edges do not reach the structurer.** `prepare_llir_for_lowering`
    calls `analysis::exception::with_exceptional_successors`, feeds the augmented
    graph to SSA and the bit-demand oracle, and DROPS it — region recovery is
    handed the un-augmented `function` (`python_bindings/ir.rs:776-786` vs
    `:899-903`). `Cfg::from` then calls `cfg_edges::classify`, which is
    `classify_with_exceptions` with an EMPTY proof set, so `EdgeKind::Exceptional`
    cannot fire in production. `classify_with_exceptions` has no production
    caller at all. Representation was never the blocker; plumbing is, and the
    reason it was not plumbed is real: a landing pad is a second entry into the
    middle of a region.
  * Switch edges are DERIVED, not read. There is no `Op::Switch`; `SwitchDefault`
    is inferred, and `is_dispatch`'s `_ => succ_count > 2` still reads any
    non-branch terminator with three successors as a jump table.
  * `EdgeKind` has no `Call`/`Return`/`TailCall`; those live only on
    `TerminalKind`, which is why the box below can only be `[~]`.
- [~] Verify total region ownership and edge accounting. Successor-edge
  accounting is verified and enforced (0 uncovered, 0 invented across the
  measured corpus); terminal ownership is not, because the region algebra has no
  `Return` node.
- [~] Attack large-function GED and AArch64-only failures from the first wrong
  stage.
  Split verdict, and the two halves are not comparable.
  **AArch64: the method worked and is partly spent.** Diary entry 23 censused 94
  AArch64-only failures from `arch_baseline.json` and named the first wrong stage
  for 29 of them — 22 FP/FP-adjacent (LIFTING: `scvtf`/`fmov` arriving with no
  output, no input, no register footprint, behind two ABI holes) and 7
  `141_atomics` (`ldar`/`stlrb` unlifted). `039c7d6` fixed the FP cluster: 12
  functions fail->pass, 0 pass->fail. Each remaining blocker is named with an
  owner (`fcmp` needs a float NZCV model; `fcvtzu`/`ucvtf` need an unsigned
  `ScalarType`; `fmadd` is a rendering decision). **65 of the 94 are still
  undiagnosed** — no FP instruction, no single cause — which is what Phase 0's
  open "AArch64-only diagnosis" box refers to. The same method has since been
  applied to i386 instead (`dcc62aa`, x87 opaque rate 100% -> 0.35%).
  **Large-function GED: untouched.** `ged-recovery-measured-trade.md` is dated
  2026-07-26, is marked strictly experimental, and measures one rejected
  experiment (+50.32 GED points, 4 functions answered WRONG). No commit since
  addresses GED; every diary mention says "unmeasured" or "out of scope". The
  structural reason is in this plan's own ordering — GED is a DecBench metric,
  and DecBench is opt-in. First step for that half is a measurement, not a fix.

### Phase 5 — Canonical program environment and references

**Outcome:** program-wide names, types, objects, calls, and operand meanings share
identity and provenance.

- [~] Finish and commit the session-owned DWARF `TypeStore` producer.
- [~] Implement `SymbolStore`, PDB import, call facts, and analyst persistence.
  A four-way conjunction with one part done. **`SymbolStore`: built (`6783274`)
  and, since `4af32f1`, connected** — `python_bindings/ir.rs:447` builds a
  `ReferenceResolver` from `session.symbol_store()`, the first production caller
  after every earlier one lived in `session_tests.rs`. Its reach is one
  `InterpretationKind` (`StringLiteral`) over pointer-width slots in
  relocation-fixed sections; `ir/symbol_env.rs` and `ir/name_resolve.rs` are
  still the real symbol path. **PDB import: open** — `symbols/pdb.rs` and the
  Windows tooling exist and are real, but nothing in them touches
  `crate::program::symbols`; `SymbolSource::Debug` is declared and never emitted.
  **Call facts: started 2026-08-15, and the identity half is done** — the
  stable function identity (`FunctionId`) and the call structure it keys
  (`ProgramCallGraph`, with a deterministic SCC condensation) landed in
  `src/program/call_graph.rs`, session-owned and read by the nested callee
  analysis. Facts *about* calls did not land: `CallSiteId` has no producer
  (`Function::callees` records targets, not call-site VAs), and the one
  candidate function fact with real consumers — noreturn — is circular with CFG
  discovery, which consumes it to place function boundaries. Same box as
  EPIC 1 and Phase 4; all three moved together. Reasoning in
  `docs/design/function-facts-and-call-facts-2026-08-15.md` §6.
  **Analyst persistence:
  open** — `SymbolAuthority::Analyst` is constructed only in
  `symbols_tests.rs:109`; the `.glaurung` KB schema has no symbol projection.
- [~] Add contextual operand reference interpretations.
  `4af32f1` landed `program/references.rs`: a seven-tier `EvidenceSource`
  ordering, `OperandRole` admission (a mapped value consumed by arithmetic stays
  a number; only a relocation may promote it), and fail-closed supply — a caller
  may not hand in evidence claiming a tier the resolver could have proved itself,
  pinned by `a_caller_may_not_supply_a_tier_the_resolver_owns`. Nineteen tests,
  and `193_mapped_constant_roles` measures non-vacuity (12 positives fail with
  the consumer off, 12 controls pass either way).
  Tiers 4-6 — MIR provenance, call/type constraints, xref consistency — cannot be
  proved from this layer by construction, and are recorded as caller-supplied.
  The one production caller supplies nothing, so tiers 4-7 are dead in
  production. Known defect, unfixed: `references.rs:697` maps
  `memory_kind_at(..).is_none()` to `UnmappedReference`, but `ProgramImage`
  returns `None` for overlapping sections that DISAGREE, where the answer is
  `ConflictingEvidence` (diary entry 35).
- [ ] Migrate symbols, strings, globals, enums, function tables, RTTI, and vtables.
  Audited 2026-08-15: nothing migrated. Legacy owners, one per item:
  `ir/name_resolve.rs` + `ir/symbol_env.rs` (symbols, as `HashMap<u64, String>`),
  `ir/strings_fold.rs` and the threaded `str_pool` (strings), `ast.rs:9259`'s
  `format!("glaurung_global_{address:x}")` and `got_fold.rs` (globals),
  `core/data_type.rs` (enums — `TypeShape::Enum` exists in the canonical store
  and nothing reads it), `ir/function_tables.rs` (tables), nothing at all for
  RTTI beyond one integer-RTTI proof in `exception_recover.rs`, and
  `analysis/vtable.rs` (vtables). First step is not a migration but a layering
  fix: `vtable.rs` and `jump_table.rs` run during DISCOVERY, before a symbol
  store exists, so they cannot ask it no matter how good it gets.
- [ ] Integrate bounded name-based library knowledge through evidence policy.
  Audited 2026-08-15: open. FLIRT exists and is wired straight into discovery
  seeds and name overrides rather than through `SymbolEvidence`;
  `NameMatch::Resemblance` is defined in `symbols.rs` and never produced. The
  policy this box points at is written (see "Name-based knowledge: permitted,
  bounded, and never silent" above) and has no enforcement point yet.
- [ ] Delete legacy maps and scattered recognizers after parity.
  Audited 2026-08-15: open, and correctly last — all fourteen recognizers the
  entry-32 survey counted are still live, and none has reached parity. Nothing
  here is deletable yet.

### Phase 6 — Aggregate recovery

**Outcome:** verified memory accesses become source-level objects and layouts.

This block is a second view of EPIC 3; audited 2026-08-15 against the code, with
the detail kept there and only the delta recorded here.

- [x] Land the common object/access model and MIR identities.
- [ ] Port the safe affine-index slice with real end-to-end coverage.
  **An implementation of this exists, unlanded, on the branch `agent/stack-bias`**
  (commit `4ac7657`, 2026-08-12, +640/-80 in `src/ir/stack_locals.rs`). It was a
  snapshot taken to let a worktree be deleted, explicitly "not a reviewed
  change", and it is 236 commits behind master. It carries `affine_of_expr`,
  `collect_affine_index_defs` and `is_version_stable` — the exact three symbols
  the 2026-08-15 audit searched for and found absent from `src/`.

  **REVIEWED AND DELETED 2026-08-19, on its merits.** The capability had ALREADY
  LANDED, four days before that snapshot was taken, in `798daf60` "Fix ARM32 O0
  affine frame addresses" — under different names, in a file that did not exist
  at the branch point. `is_version_stable` is `is_versioned_local_value`
  (`stack_locals/address_aliases.rs:103`) VERBATIM; `scaled_index`
  (`address_recovery.rs:97`) already returns a bias and its caller adds it to the
  displacement; the self-rooted-definition guard is `address_aliases.rs:510`.
  Master's version is strictly stronger: it clears its maps at every
  stack-pointer write and control boundary rather than keeping one whole-function
  map, and it is bounded (`MAX_AFFINE_COMPONENTS`, `MAX_AFFINE_COMPONENT_NODES`)
  where the branch was not. The branch's own ARM32 unit test, ported verbatim
  onto master, PASSES.

  It also could not have been landed: `collect_stack_address_defs` gained a
  third parameter and an outer joint fixpoint that compares maps for equality,
  and the branch's `StackAddressDefs` does not derive `PartialEq`; `StackContext`
  gained a field its test does not construct; and the retype it needs now touches
  20 signatures across six files rather than one.

  And it would have bought nothing: **0 of 79** stripped-lane divergences show the
  pathology it targets, because x86-64 SIB has a `disp32` field so no compiler
  materialises the bias into a register — the shape is an ARM32 immediate-range
  artefact, and ARM32 is exactly where it already works. Its own recorded
  casualties (`20_graph_bfs:clang:O2`, `25_kmp_search:i386:O2`) are green today,
  so reintroducing it would risk two passing cells to fix zero.
  Step 3 of the four-step plan under EPIC 3's "Near-term retained work" landed
  and nothing else did. The fixture exists —
  `tests/decompiler_fixtures/src/187_constant_bias_index.c` (`8f661ff`), five
  functions including two deliberate controls, with the `[bias]` and
  `[aggregates]` sets in `sets.toml` — but all 20 of its lanes are already
  `pass` in `baseline.json`, because execution equivalence is green whether or
  not the analysis exists. So the coverage is not yet a test the port would flip.
  **CORRECTED 2026-08-19 — this paragraph was literally true and substantively
  wrong.** `affine_of`, `affine_of_expr`, `collect_affine_index_defs` and
  `is_version_stable` do match zero times. The CAPABILITY is present anyway,
  under other names (see the branch note above): a name-based search concluded a
  thing was absent when it had shipped. That is the same failure the duplicated-
  helper audit hit on 2026-08-19, where three of four identical function bodies
  carried DIFFERENT names in each location and no name search could find them.
  **Search for the behaviour, then confirm with the name — never the reverse.**
  Do not credit `resolve_affine_values`/`AffineFact`
  (`src/ir/memory_objects/mir.rs:338`) here — those resolve `root + constant` at
  scale 1, not `root*scale + bias` folded into a frame displacement.

  **AND THE PROPOSED FIRST STEP IS NOT POSSIBLE.** The instruction was to "add a
  failing slot-recognition assertion on `187_constant_bias_index`". That
  assertion cannot be written: all five of its functions take the array as a
  POINTER PARAMETER (`bias_forward_sum(const int32_t *values, int32_t count)`
  and alike) and none allocates a stack array, so the base is `arg0` and
  `src/ir/stack_locals/` is never on the path. It is a good lane for
  parameter-pointer bias and is 20/20 green on x86_64, armv7 and aarch64 — but it
  is not evidence about the frame path in either direction, and anyone gating a
  port on it would conclude the port is unnecessary for the wrong reason. The
  residual gap is x86-only (`address_aliases::expand` returns early unless the
  calling convention is `Arm | ArmHardFloat`) and is worth ZERO cells.
- [ ] Migrate the first production aggregate consumer from AST to MIR.
  **Blocked, and both halves of the blocker are now verified in code rather than
  suspected.** (1) There is no frame object left to migrate by the time a
  consumer could ask: `promote_stack_locals_with_facts` runs at
  `src/python_bindings/ir.rs:579`, inside `prepare_for_decbench`, and mints every
  `(base, disp)` slot into its own named local; the only production consumer of
  the object model, `refine_pointer_high_variables`, runs at `:1944`. The AST
  adapter forms an object only where `record_access`
  (`src/ir/memory_objects/ast.rs:265`) sees a `Deref` over an affine address —
  a pointer held in a local, never the frame — while the MIR adapter keys every
  stack access by the frame root, so "a whole frame arrives as one object"
  (`src/ir/memory_objects/partition.rs:3`). The two models have disjoint object
  populations. (2) The consumer's question is the one MIR refuses:
  `is_proven_promoted_object_cursor` requires `has_conflict_free_extent`, extent
  is derived only from `stride` (`src/ir/memory_objects.rs:394`), and
  `partition.rs:174` inserts `PartitionConflict::UnboundedCursor` **because**
  `stride.is_some()` — the single property the AST consumer treats as proof is
  the single property the MIR partition treats as disqualifying. Proven by
  `a_walking_frame_cursor_refuses_to_partition`
  (`src/ir/memory_objects/partition_tests.rs:664`). First step: migrate a
  different consumer. The frame-slot *extent* question is already answerable end
  to end — `StackLocalFacts::frame_coordinates` →
  `MemoryObjectModel::resolve_frame_coordinate` → `bounds_at`, test-proven by
  `every_promoted_frame_coordinate_resolves_to_its_own_extent`
  (`partition_tests.rs:252`) — and today has no non-test caller.

  **2026-08-15: that suggested first step was taken, wired through the real
  pipeline, and MEASURED. It is a no-op, and the reason generalises to the whole
  box.** The join was built in `decompile_at`/`decompile_range_at` after
  `run_ast_passes`, asking verified MIR for the extent of every promoted frame
  coordinate on all 173 fixture sources at `-O0` and `-O2` (1270 functions, 4703
  promoted coordinates). It resolves — `rbp`, `rsp` and `entry_rsp` spellings all
  land on the right byte — and then it agrees with the pass it was supposed to
  replace:

  * **Forward** (production coordinate -> MIR bounds): 3823 coordinates bounded,
    802 refused by a partition conflict, 78 unresolvable (`AmbiguousBase` 48,
    `UnknownBase` 30). Of the 3823 bounded, **3803 widths identical, 20 wider,
    0 narrower** — and all 20 "wider" are `sizes[name] == 1` byte-array
    aggregates, where MIR's `at_least` is a strictly WEAKER bound than the
    number production already has. `100_struct_layout:struct_assignment_copies`
    is the clean example: the source `struct Tight` is 12 bytes, production
    emits `unsigned char local_18[12]`, and MIR bounds the same storage only as
    `8 <= w <= 32`.
  * **Reverse** (MIR-proven unit -> did production name it?): 3657 of 3675 units
    already carry a promoted local. The 18 exceptions are interior cells of
    structs production names as ONE byte object, plus two spill slots in
    `call_into_spill` it deliberately does not promote. No frame variable is
    being lost.
  * `bounds_at(offset).at_least` started at the local's own coordinate for
    **3823 of 3823** — production never mints a local inside a proven storage
    unit. That is worth keeping as a fact; it is not a migration.

  The structural reason, which is the part that generalises: **`stack_locals`
  forms a frame OBJECT (as opposed to naming a scalar slot) in exactly three
  places, and all three are triggered by the frame's address being indexed or
  taken** — `seed_indexed_stack_objects` (`stack_locals.rs:1018`, extent = "to
  the next indexed start, else to the frame base"),
  `promote_address_taken_stack_object` (`:1921`, extent = "to the next known
  slot, else to the frame base") and `stack_assignment_object_address`
  (`:2608`). Verified MIR refuses to bound a frame on exactly those two events:
  `memory_objects/mir.rs:71-94` calls `refuse()` for any `memop.index`
  (`UnmodeledAccess`) and `:216` raises `EscapedRoot` for a frame pointer in an
  operand it does not interpret. **Production's guesses and MIR's refusals are
  the same set.** The corpus census `frame_partition_census`
  (`partition_tests.rs`) pins the invariant: 1179 stack-rooted objects, 1120
  with an empty conflict set, and **not one of those 1120 contains a single
  indexed access**.

  **Correction, Entry 53 (2026-08-16): part of that "guessing" was not a guess
  at all.** On x86-64 the DWARF extent was already exact and simply arrived in a
  coordinate the body never forms — `DW_OP_call_frame_cfa` was mapped to
  `("rbp", +16)`, which is only real when the body establishes a frame pointer.
  Repairing the coordinate replaced the heuristic partition with the declared one
  in every frame-pointer-omitted x86-64 function that has an aggregate: 51 of the
  748-lane corpus's `gcc:O2` bodies re-render, four `gcc:O2` cells go
  `fail -> pass`, and the def-before-use census drops 18 violations with none
  introduced. So the set of frame extents production genuinely guesses at is
  SMALLER than this measurement recorded, and the overlap with MIR's refusals is
  correspondingly weaker evidence than it looked. Re-measure before building on
  it.

  So this box does not need plumbing; it needs the model to change. The three
  things that would actually unblock it, in increasing order of cost:
  1. **Per-cursor conflict attribution.** One object per frame root means one
     escaping local poisons every other local in the frame, so MIR's escape
     verdict is frame-wide where production's is per-slot — strictly coarser,
     hence unusable as evidence about any individual variable.
  2. **An index-aware partition.** A scaled index whose stride and access width
     agree (the `ObjectShape::Array` case, which `shape.rs` already proves) is
     enough to bound the bytes BELOW the indexed region even though the indexed
     region itself stays open. Today one index refuses the entire object.
  3. **An element COUNT.** `ObjectShape::Array` deliberately reports `end: None`
     (`shape.rs:56-61`), so even a perfect array claim cannot answer the one
     question `seed_indexed_stack_objects` is guessing at.

  Cost note for whoever wires the next consumer: building verified MIR per
  function measured **+10.4%** on a 294-function decompile (28.76 s -> 31.75 s,
  release, gcc `-O0` fixtures), consistent with the +13% recorded on
  `PreparedLlir::mir`. That is the price of admission for any consumer, so the
  first one to pay it must return more than a restatement.
- [~] Solve arrays, structs, unions, bitfields, extents, and pointees.
  Four of the six are settled, two of them by proof of *undecidability* rather
  than by an answer; see the `[~]` "Classify struct versus array versus union
  versus bitfield" item under EPIC 3 for the detail, which is not repeated here.
  Extents are the sixth settled one: `ObjectPartition`/`ExtentBounds` gives
  two-sided bounds with five typed refusals (`partition.rs:82`, `:31`).
  **Pointees are the one noun with neither an answer nor a proof.**
  `ObjectOrigin::ParameterPointee` exists as an origin tag
  (`src/ir/memory_objects.rs:148`, set in `mir.rs:350`) but nothing classifies a
  pointee's shape, which is why EPIC 3's "Propagate pointee and object
  constraints across calls" is still open. The whole layer also remains
  diagnostic: `object_shapes` has no production consumer.
- [~] Implement aggregate ABI transfers and real execution fixtures.
  **Both halves started, the RETURN side only.** The execution lane exists:
  `tests/decompiler_fixtures/src/195_by_value_aggregates.c` (2026-08-15) covers
  all four System V return contracts plus a scalar control, and the older note
  that "no fixture anywhere returns a struct by value" is superseded — the corpus
  had dodged it on purpose in `129_struct_by_value.c`, which still keeps its
  struct-taking functions `static`.

  A SysV eightbyte classifier now exists (`abi::sysv_amd64_return_class` +
  `ir::return_class`, Entry 51) and `RecoveredOutputKind::HiddenReturn` is
  constructed for the first time, from a proven MEMORY-class declared return
  (`python_bindings/ir.rs`). It is deliberately behaviour-neutral: under System V
  a MEMORY callee returns the caller's buffer address in the ordinary result
  register, so the recorded contract changes no spelling.

  The first REAL aggregate transfer on the return side landed in Entry 54: a
  `SplitBanks` result is declared with a synthesised `rax + xmm0` tag and
  decomposed into one identity per bank through a frame object
  (`abi::split_bank_return_tag`, `call_result_split::split_bank_results`,
  `bv195_mixed_roundtrip` pass on all four host lanes). It goes through memory
  rather than through field access because `Expr` has no value-base member node —
  correct, and still a workaround.

  **The PARAMETER side is untouched.** The refusal is still pinned by
  `locked_sysv_parameters_decline_the_whole_signature_on_an_aggregate`
  (`src/ir/types_recover.rs`) — one aggregate poisons the whole signature — and
  the renderer still refuses by-value aggregates in as many words
  (`src/ir/ast.rs:7565`). The eightbyte join the parameter side needs is the one
  already written; what is missing is a consumer, not a classifier.
- [ ] Project solved access paths to semantic HIR.
  Zero, and it is gated on Phase 7 rather than on Phase 6: there is no HIR to
  project onto (no `src/ir/hir/`, no `Field`/`Index`/`Member`/`AddressOf` node in
  `Expr`). Nothing reads a solved access path — `object_shapes` has three call
  sites and all are definitions or tests. What ships today is two independent
  older stories: members come from debug info (`annotate_function_fields`,
  `src/ir/dwarf_fields.rs:18`, plus `pdb_fields.rs`), and arrays come from the
  `stack_locals` indexed-start heuristic (`src/ir/stack_locals.rs:1016`) rendered
  as `unsigned char {local}[{size}]` (`src/ir/ast.rs:8136`) — a *different*
  array story from the one `shape.rs` proves, and the one that reaches output.
  Even the shipping cursor projection says it is waiting: it emits `char *`
  because that is "the only portable C declaration that preserves those byte
  displacements until semantic Field/Index HIR can carry the recovered layout"
  (`src/ir/high_variables.rs:130`). First step: land the `Index` node and project
  `ObjectShape::Array { element }` into it — the one shape with a positive proof
  and an existing passing assertion (`20_graph_bfs`) to measure against.

### Phase 7 — Semantic HIR, pure rendering, and physical decomposition

**Outcome:** semantic ownership becomes visible in APIs and file structure.

This block is a second view of "Semantic HIR and pure rendering" above; audited
2026-08-15, with only the delta recorded here.

- [ ] Finish HIR and shared visitors/rewriters.
  Not started, and the second half is the larger problem. `src/ir/hir/` does not
  exist; the HIR is `Expr`/`Stmt`/`Function` in `src/ir/ast.rs`. There is no
  visitor or rewriter trait anywhere — 51 files under `src/ir` hand-match
  `Stmt::If` across **540** sites, each with its own descent
  (`visit_children`, `rewrite_body`, `walk_stmt`, `walk_stmt_rw`, all
  file-private and all different). The one generic helper,
  `for_each_expr_in_stmt` (`src/ir/expr_reconstruct.rs:261`), is private with one
  caller. First step: one descent trait plus a single well-bounded convert
  (`src/ir/canary.rs`, 13 sites) as proof of shape, before touching
  `guard_chain.rs` (55).
- [~] Move all semantic renderer behavior into declared verified passes.
  The pipeline half is real and the registry half is not. 19 steps are named
  between `trace_pass("prepare_for_decbench")` and `trace_pass("ready_to_render")`
  via the `pass!`/`refine!` macros at `src/python_bindings/ir.rs:1904`, def-use
  is verified (`src/ir/verify_defs.rs`, `#[must_use] RenderVerification` in
  `73bdca3`), and `symbol_env::clear()` was removed from the renderer tail in the
  same commit so the renderer no longer releases a thread-local it never
  installed. But "declared" is not yet true in the type system: there is no
  `PassSpec`, no pass list, no registry — `pass!` is a macro over a hardcoded
  straight-line sequence that lives in `python_bindings`, so a pure-Rust consumer
  of `crate::ir` sees no declared pipeline at all. Residue still executing inside
  the renderer, each verified at its call site: `renderable_dwarf_structs`
  (`src/ir/ast.rs:7681`), `recover_named_call_prototypes` (`:7722`),
  `infer_return_ctype` (`:7931`, which also runs pre-render at
  `python_bindings/ir.rs:2109` — it genuinely runs twice), and the
  `DEC_DECLARED_CTYPES` cell (written `:8009`/`:8160`, read `:10438`). That last
  one is not circular and is therefore extractable as a declaration plan.
  `DEC_SEMANTIC_WIDE_CAST` (`:10964`) is correctly called unmovable: it is a
  dynamically-scoped *formatting* parameter carrying destination type down an
  expression print, so it becomes a `&RenderCtx` argument, not a pass.

  **The declaration plan is extracted** (2026-08-16, `src/ir/ast/declaration_plan.rs`).
  `DEC_DECLARED_CTYPES` and the seven cells that were filled beside it —
  `DEC_PTR_ARGS`, `DEC_PTRS`, `DEC_INT_TYPES`, `DEC_INT_WIDTHS`,
  `DEC_STACK_OBJECTS`, `DEC_VOID_OUTPUT`, `DEC_RETURN_CTYPE` — are one immutable
  `DeclarationPlan` computed by a pure function of values before any output is
  produced. The coupling that mattered was not the number of cells but the write
  at `:8160`: the declaration block filled the table it was printing from, so the
  body's spelling depended on a side effect of the line above it. Ten write sites
  inside the printer became zero, and the printer's residue is now the two passes
  above it plus five unrelated cells. Byte-identical over 15,682 fixture
  functions; see the diary entry for the control that made "byte-identical"
  measurable.

  `infer_return_ctype` was confirmed to run twice with *literally identical*
  arguments (`&prepared`, `decl` at both sites, nothing mutating between them),
  and was deliberately NOT collapsed: the renderer's copy is its fallback when no
  authoritative prototype survives filtering, and removing it means handing the
  renderer a precomputed answer — a fifth parameter on a wrapper chain that is
  already four deep. That is the `&RenderCtx` item below, not this one.
- [~] Make all output profiles pure and deterministic.
  Determinism is tested; purity is not achieved; and the coverage is the inverse
  of what the risk profile wants. `python/tests/test_decompile_determinism.py`
  runs 9 cases (3 tests x x86-64 ELF, AArch64 ELF, PE): same-process repeat,
  sequential-process repeat, and 6-way concurrent processes against a serial
  baseline. But it calls `g.ir.decompile_all(...)` with no `style`, so it
  exercises the **plain** profile only; `decbench` is compared only across
  separate subprocesses
  (`test_decompiler_emission_invariants.py:509`), which by construction cannot
  observe thread-local leakage; and `c` (`render_c`) has no determinism test at
  all. So the one profile that owns the `DEC_*` thread-locals (16 cells until
  2026-08-16, 9 after the declaration plan was extracted;
  `src/ir/ast.rs:9150-9257`) is never rendered twice in one process by any test.
  Two purity defects worth carrying: `DEC_POINTER_WIDTH` is set and reset only by
  the decbench renderer but read by the shared `target_int_ctype`
  (`ast.rs:5127`), so the `c`/`plain` paths read a default of 8 regardless of
  target; and `symbol_env` install/clear (`python_bindings/ir.rs:1796`, `:1814`)
  is a bare statement pair with no `Drop` guard, so a panic mid-render leaves the
  previous function's prototypes installed for the next one on that thread.
  First step: parametrize the in-process determinism test over
  `style in {"", "c", "decbench"}` — that single change makes the whole
  thread-local class falsifiable.

  **The decbench non-determinism is fixed** (2026-08-16,
  `merge_exact_definition_widths`). It was measured while establishing a
  byte-identity control for the declaration-plan split: rendering all 15,698
  functions of the 766 objects in `tests/decompiler_fixtures/build` at
  `style="decbench"`, three same-process passes of ONE unmodified build disagreed
  on **13 functions** (0.083%), fifteen of the sixteen ever seen being the same
  two `memchr` symbols across six `rustc` fixtures plus `rust_slice_get_range`.
  Confirmed at `51c2b88` and again at `c2fb19d` after the return-class
  work: 13 of 15,698, same list
  (`uv run python repro.py '*' 3`, one process, three passes).

  The reading recorded here at the time — that within-process variation "rules
  out per-process hash seeding and points at a time-based budget" — was **wrong,
  and wrong in a way worth keeping on the page.** `RandomState::new` bumps a
  per-thread counter for every map it builds, so two `HashMap`s constructed at
  different moments inside ONE process already hash differently. Within-process
  variation is therefore evidence *for* hash ordering, not against it. The
  time-budget lead was also refuted directly: the only clocks reachable from a
  decompile are `Budgets::timeout_ms` and `Deadline` in `src/analysis/cfg.rs`
  (`grep -rl 'Instant::now\|\.elapsed()' src/` names 19 files, none of the
  others on this path), and `total_timeout_ms` is `0` at every decompile entry
  point, so no deadline can expire.

  The actual cause is one `HashMap` walk into a many-to-one projection:
  `merge_exact_definition_widths` (`src/python_bindings/ir.rs`) iterated
  `definition_widths: HashMap<VReg, u8>` and wrote each storage's width through
  `TypeMap::refine_from_value`, which is **last-write-wins on integer width**.
  `role_names` maps several machine storages onto one rendered role, so for
  `rust_slice_get_range` both `rax#3` (8 bytes) and `xmm0` (16) named `ret` and
  the hash picked the winner. Same class and same symptom as the
  `ir::stack_locals` `collect()` that alternated `char` and `long`.

  A census over the 30 `-rustc-` objects (11,190 merge calls) found 506 (4.5%)
  with a disagreeing role and **`ret` is the only role that ever disagrees**
  (`(8,16)` 384, `(4,8)` 84, `(4,16)` 22, `(2,8)` 16), so the blast radius is the
  return type alone. Conflicts are now resolved by *withholding* — an ambiguous
  storage-to-role projection states no width, exactly as `stack_locals`'s
  `ambiguous_coordinates` does — because `ret` already has two stronger
  value-keyed sources on either side of the call.

  After: **0 of 15,698 differ** over three same-process passes; 15,694 are
  byte-identical to a HEAD variant and all 4 that changed were in the
  already-flipping set, so no deterministic output moved. `@o0` and `@o2`, 368
  lanes each: no regressions and no improvements. `rust_slice_get_range` now
  renders `unsigned int`, and the fixture source declares `-> i32`, so the width
  is right where both coin-flip answers were wrong.

  `python/tests/test_decompile_determinism.py` now carries the missing shape:
  a same-process repeated `decompile_at(style="decbench")` check on the two
  symbols that flipped, RED at `51c2b88` and at `c2fb19d`, green after. The parametrization
  over `style in {"", "c", "decbench"}` for `decompile_all` is still open, and
  `c` still has no determinism test at all.
- [~] Split large owners only along migrated responsibility boundaries.
  One split, along one boundary. Until 2026-08-16 this read "zero splits":
  `git log --diff-filter=R -- src/ir` over the last 200 commits returned nothing,
  every new file under `src/ir` in the last 40 commits was additive capability
  (`x87.rs`, `memory_objects/shape.rs`, `indirect_targets.rs`, `effect_census.rs`,
  `mir/*`) rather than decomposition, and `ast.rs` grew monotonically across
  seven commits from 19,158 to 19,315 lines.

  `src/ir/ast/declaration_plan.rs` (365 lines) is the first. It takes the
  declaration decision — what each parameter and body local is declared as, and
  with which C type — out of the 660-line render function and makes it a value
  computed by a pure function before any output is produced. See the Phase 7
  renderer box above for what moved and what deliberately did not.

  Two things this split is NOT, both worth stating because the file-size targets
  invite the opposite reading. It is **not** a line-count win: `ast.rs` fell 92
  lines (19,315 to 19,223; product 11,628 to 11,536) while the tree gained 273,
  because the new module documents a contract that previously existed only as
  eight comments on eight cells. And it moved **zero fixture cells**, which under
  the two-track rule at the top of this file is the expected outcome.

  Remaining on this boundary: the plan is still transported to the printer
  through one thread-local rather than a parameter, because the readers are 24
  mutually recursive `write_*_dec` functions across 183 call sites. Threading
  them is the `&RenderCtx` item, and doing it as part of this split would have
  been ~200 mechanical edits riding on an unverified behaviour change. The
  reduction that was actually banked is different and is the one the constraint
  asks for: the printer went from filling eight mutable tables at ten sites — one
  of them *while printing the declaration block* — to reading one value it cannot
  modify. The next split does not need to re-derive that decision.
- [x] Add dependency and file-size ratchets. Both are live, green, and collected
  by default (`pytest.ini` `testpaths = python/tests`). File size:
  `tools/fitness_report.py` + `tools/fitness_baseline.json` +
  `python/tests/test_fitness_report.py` ratchet the seven measures, and
  `python/tests/test_large_module_review.py` (added 2026-08-15) ratchets the
  *set* of files over 1,000 LOC, which the count cannot. Dependencies:
  `python/tests/test_src_dependency_boundaries.py` — see the ownership map above
  for both. **A ratchet is not fitness, and this tick must not be read as one.**
  `tools/fitness_baseline.json` has been relaxed upward on five of its last seven
  commits (`product_mean_loc` 526.34 -> 530.11, `product_files_above_1000`
  27 -> 28, `ir_files_above_1000` 13 -> 14), two of them dedicated
  `chore: refresh the fitness baseline` commits. The gate is installed and the
  measures are moving away from target through it.
- [ ] Remove compatibility layers as parity is proven.
  Standing layers, none removed. The renderer overload chain is four wrappers
  deep (`render_decbench_typed` at `src/ir/ast.rs:7306` through
  `..._and_local_types` at `:7612`; only the last does work) with exactly one
  production caller; `ObjectIdentity::LegacyRegister`
  (`src/ir/memory_objects.rs:37`) is still load-bearing; `stack_locals.rs:2940`
  advances a counter "for legacy callers"; and `python_bindings/ir.rs` keeps
  `bits=` back-compat at `:672`. First step, and the only one where parity is
  already *proven* rather than assumed: the two legacy collectors kept alive
  purely as differential oracles —
  `indexed_image_string_pool_matches_the_legacy_collector`
  (`src/ir/strings_fold.rs:507`) and
  `indexed_image_readonly_regions_match_the_legacy_collector`
  (`src/ir/readonly_fold.rs:710`). Those are the healthy form of this debt and
  the ones actually ready to delete.

### Phase 8 — Persistence, deterministic parallelism, and hardening

**Outcome:** stable boundaries produce faster, safer long-running analysis.

This block overlaps the Performance plan almost box for box; audited 2026-08-15.
The pairings are: persistence *contains* the cache-key box (that one is
in-memory, this one is disk); parallel scheduling **is** the SCC box plus the
immutable-snapshot box; change epochs **is** the whole-HIR-clone box; and
cancellation/budgets **is** the budgets box plus three unrelated hardening
items. Read the reasoning there and the delta here.

- [ ] Persist versioned environment and artifacts with dependency fingerprints.
  Nothing in `src/` writes an environment or a decompiled artifact to disk; all
  three caches are a `HashMap` behind a `Mutex` and die with the process. The
  `.glaurung` SQLite KB (`python/glaurung/llm/kb/`) persists **analyst facts
  only** — names, comments, prototypes, xrefs, stack vars, bookmarks, undo — and
  the decisive evidence is that `render_decompile_with_names`
  (`xref_db.py:2070`) calls `g.ir.decompile_at` live and applies stored names to
  fresh output. No pseudocode, no HIR, no lifted IR, no environment is stored.
  It does anchor on a sha256 of the image (`persistent.py:104`), which is an
  image fingerprint on analyst facts, not a dependency fingerprint on artifacts;
  there is no pass-set hash or pipeline version anywhere. First step is
  ordering, not code: a persisted artifact without a pipeline fingerprint is
  unsafe to reuse across builds, so the fingerprint box has to close first.
- [ ] Add deterministic function-parallel scheduling and SCC phase barriers.
  The scheduler does not exist. `decompile_all_py` and `decompile_many_py` are
  plain sequential `for` loops with the GIL held
  (`src/python_bindings/ir.rs:2763`); `rayon` appears only in `src/strings/` and
  `src/python_bindings/triage.rs`, never on the decompile path; and the only
  `thread::spawn`s in the pipeline are single workers for stack size
  (`src/ir/ast.rs:3282`) and for Ctrl-C (`src/python_bindings/analysis.rs:241`).
  There are no barriers because there is nothing to barrier. The SCC half is the
  Performance-plan box above, and it is the keystone: the condensation is what
  would define the phase barriers, and it currently has no input.
- [ ] Add incremental invalidation for analyst edits, new facts, and pass changes.
  Every one of the ~30 `invalidate` matches in `src/` is intra-function dataflow
  (`copy_prop::invalidate`, `invalidate_loads`,
  `invalidate_written_definitions`); there is not a single cache-invalidation
  call site. The only lifecycle primitive is the blunt `clear_caches()`
  (`src/program/session.rs:327`), which is manual, all-or-nothing, and takes no
  argument saying what changed. Against the box's three axes: analyst edits live
  in the Python KB with no channel to the Rust caches (which is why
  `render_decompile_with_names` re-decompiles instead); a new fact requires a new
  session; and pass changes are undetectable because there is no pipeline
  fingerprint. First step: a per-key `invalidate_function(va)` so
  `clear_caches` stops being the only option.
- [~] Replace global rescans/clones with indices and change epochs.
  The indices half is the strongest measured work in this phase; the epochs half
  is untouched. `ProgramImage` (`src/program/image.rs:126`) is now a real index —
  segment/section/code mappings, executable and PLT ranges, eh_frame functions,
  symbols by name and by VA, plus four `OnceLock` lazies — and it retired the
  named anti-pattern of re-reading relocation tables per function. Measured:
  object parses per session went from `O(functions + branches + callees)` to a
  constant **19**, held by three tests in `src/program/session_tests.rs`
  (`indexing_one_image_parses_the_object_exactly_once` at `:845`,
  `discovery_parse_count_does_not_scale_with_the_number_of_functions` at `:870`,
  `address_scoped_discovery_reuses_the_session_image` at `:913`). The epochs half
  is the whole-HIR-clone box in the Performance plan: no `epoch`, no `ChangeSet`,
  no dirty tracking, and two clone-and-compare fixed points still live.
- [~] Add cancellation, resource budgets, fuzzing, crash recovery, and schema
  migration coverage.
  Five independent things at five different maturities; bundling them into one
  box hides that. Cancellation and resource budgets: see the Performance-plan
  budgets box — real for discovery through `analysis`, absent on every decompile
  entry point, and no memory budget exists. Fuzzing: `fuzz/` exists with
  `cargo-fuzz` and five targets, but the crate is pulled with
  `default-features = false, features = ["triage-core", "triage-heuristics",
  "triage-containers"]`, so the IR, lifters, MIR and HIR are **not compiled into
  the fuzz build at all** — it is triage-only, and the roadmap's own "fuzz
  decoders, lifters, MIR editors..." box is correctly still open. Crash
  recovery: `catch_unwind` appears exactly twice, in one place, wrapping
  `pelite` (`src/triage/parsers.rs:44`); there is no partial artifact on panic
  and no journal replay. Schema migration: self-declared unimplemented —
  `python/glaurung/llm/kb/persistent.py:213` raises with the string "migrations
  are not yet implemented" on a `SCHEMA_VERSION` mismatch, and the additive
  `ALTER TABLE` path in `xref_db.py` documents that it does not bump the
  version. First step, cheapest of the five: point one fuzz target at
  `lift_function_from_bytes` and drop `default-features = false`.
- [~] Meet the performance targets without correctness or coverage regression.
  Five of the six rows in the table above are met as measured and one is not:
  base object parses per session is **19** against a target of exactly one, and
  that is still true at this HEAD (the only commit touching `parse_object` since
  the measurement, `4ad8800`, refactored two existing call sites into typed
  errors without changing the site count). Two of the five "met" rows carry
  caveats already recorded above and repeated here because a table row is what
  gets quoted: the wall-clock row substituted 138 binaries sequential for the
  stated 224 at 12 workers, which is a different measurement rather than a met
  one; and the warm-query row is only meetable through `DecompilerSession`,
  since repeated `decompile_many` gives 1.98x. The "without regression" clause
  now has one real guard where it previously had none —
  `python/tests/test_decompile_determinism.py`, 9 cases over three real binaries
  — but its scope is process-level and plain-profile (see Phase 7), so it pins
  the property that holds today rather than proving the property the eventual
  parallel scheduler will need.

## Immediate rank-ordered plan

This is the practical next-work queue as of the planning baseline.

**Inserted 2026-08-16 — five defects found by one fixture, ahead of the queue
below.** `197_homogeneous_float_aggregates` (`205dcfc`) was added to cover the
one SysV return class `195` left out. It is 18 failing cells of 44, and pulling
on them produced four *more* defects that nothing in the queue below predicts.
They are ranked here because each is reproduced, located, and small, which the
items below mostly are not:

**Status at end of 2026-08-16: items 1 and 2 CLOSED, 3 and 5 open, 4 promoted.**

**Status at end of 2026-08-19: item 4 CLOSED, and it was two defects wearing one
symptom.** The whole-function float gate really did shut, and the reason it shut
was `abi::result_register_candidates` answering `None` for `CallConv::Aarch64`
so that EVERY AArch64 call was annotated `result = x0` whatever it returned.
Separately, `movlpd`/`movhpd`/`movlps`/`movhps` had no arm anywhere in
`src/ir/`, and the `pd` suffix made an unmodelled float producer that shut the
gate a second way. Both fixed; item 4's `hfa197_quad4f_roundtrip` reproduction
now passes and the eight declined `cvttss2si` opened exactly as predicted.

**Item 3 CLOSED, and my retitle was still wrong.** I had retitled it "a tail
call returning `rax` when the result is in `xmm0`". The actual owner is
`direct_output::RETURN_REGS` — a SECOND return-register list, separate from
`abi::return_registers`, carrying ARM32's hard-float `s0`/`d0` but **not**
x86-64's `xmm0`. A float result reaching a bare machine `ret` had nothing to
attach to and the assignment was dead-store eliminated, so the body vanished.
Five such lists were then found; `st0` (i386 x87) has the identical gap and is
filed.

**Item 5 remains open and is now better bounded.** Of the 70 float-cluster
failures I attributed to one mechanism, a census of all 104 cells found only
**22 contain the crossing at all** — a packed read of a register whose live
definition was a scalar write. Nine are fixed, 13 remain, and **48 are a
different mechanism entirely.** The single largest remaining float blocker is
instead the float->bits direction of reinterpretation: the bits->float direction
has a union spelling and the reverse did not, so `(unsigned int)(arg0)` on a
`float` was a C VALUE conversion. That fix moved 26 cells.

**Inserted 2026-08-17, ahead of all of the above: the overflow flags after a
multiply were poison, and the readers of those flags are overflow checks.**
CLOSED. `Mnemonic::Imul` marked CF/OF undefined under a comment that stated the
defect ("x86 IMUL defines CF/OF, but product truncation overflow is not
modelled"). The readers are `seto`/`jo`: Rust's `overflowing_mul` /
`checked_mul` / `saturating_mul`, and — the case that matters most —
`33_knapsack:clang:O2`, where Clang range-checks an allocation byte count with
`mul %rdx; seto %r8b`. **The decompiler was rendering integer-overflow checks as
reads of an explicitly poisoned value**, which for a vulnerability-discovery
substrate is close to the worst available failure: the analyst is shown a
program in which the check is not there. Fixed for the truncating forms at
8/16/32 bits and for the one-operand form at every width including 64 (the high
half is already materialised in `rdx`, so no 128-bit value is needed). 64-bit
*truncating* `imul` still poisons, and the comment now names that one case. Six
fixture cells `fail -> pass`, zero `pass -> fail` over all 752 lanes; the
"explicitly undefined" class in the def-use census is now empty (320 -> 313
required violations, seven removed, none added). Diary Entry 67.

**A structural fact behind items 4 and 5, recorded 2026-08-17.** `Op::Unknown`
is `{ mnemonic: String }` — one field, no operands — and `Op::opaque` builds
`Op::Intrinsic { ins: [], outs: [], reads_mem: true, writes_mem: true }`.
**Neither fallback declares a register write.** So an unmodelled instruction is
not conservatively modelled, it is invisible to register dataflow: the census
believes the destination was never written, and the previous value flows on.
That is the same shape as item 4's "stale value flows on" and item 5's
undefined read, and it means those items are not really about `lower_scalar_float`
or about one control — they are about what an unmodelled instruction costs.
`movlpd`/`movhpd`/`movlps`/`movhps` have no arm anywhere in `src/ir/` and take
this path (item 4's mechanism, confirmed).

**Measured down, 2026-08-19.** The guard that names these is
`SILENT_REGISTER_WRITERS`, and it has gone from **35 mnemonics / 1,372
occurrences to 28 / 1,130** — `tzcnt` (130), `bts` (82), `popcnt` (14),
`movlhps` (6), `btr` (6), `btc` (2), `rcr` (2), `movhlps`. The `movlpd`/`movhpd`
family named above was cleared earlier by the same programme.

Two lessons from that pass are worth carrying into the rest of the list. First,
**the fixture corpus already contains most of these**: compiling all ~200
fixture sources at O0/O2 under gcc and clang and grepping the disassembly found
lanes for six mnemonics assumed to exist only in `samples/` library code, and
one of them (`144_inline_asm:builtin_bit_intrinsics`) was a *failing* lane the
lift then fixed. Do that scan before ranking anything here by guessed value.
Second, **an empty-`outs` predicate is not the census**: `stosd`/`stosq` are
deliberately empty because they lower to a `memory.fill` effect, and any
predicate that cannot tell them from `movsb`/`movsq` — which really do update
`rdi`/`rsi` — will rank noise.

What remains, by volume: `syscall` 310, `movsb` 242, `aesenc` 222, `movsq` 134,
`vmovdqu` 58, `vzeroupper` 26, `fstp` 34, then a long tail of 2s. **The string
moves are the largest tractable entry** and were on no list until the bit
family cleared out ahead of them.

- **1 closed** by `fdbcf58` — `ReturnClass::SsePair`, 11 cells, −15 undefined
  reads. Its successor is the **mirror class**: `hfa197_pair2d_roundtrip` now has
  a fully correct RETURN and still fails on the ARGUMENT side, because a 16-byte
  all-SSE aggregate passed by value has no parameter-storage model
  (`types_recover::locked_sysv_amd64_parameter_storage`). The fixture function
  for it, `hfa197_consume_pair2d`, was written for that case and is waiting. That
  is now the top ABI item.
- **2 closed** by `9cfa912` — 12 cells across host and cross lanes.
- **4 promoted, and no longer a curiosity.** It is what blocks item 1's hardest
  remaining cells: on `clang:O0:quad4f` the split *engages*, then is discarded
  because every consumer of `xmm0`/`xmm1` is a declined `/* asm: movlpd */`. The
  mechanism is narrowed to one testable fact (Entry 61) — if
  `scalar_float_intrinsic` returns `None` for that op instance, both the shut
  gate and the `Stmt::Unknown` follow from it. Seven probes failed to reproduce
  it because every one had a `scalar_float_intrinsic` that resolved.
- 3 and 5 unchanged. **3 was retitled after disassembly**: it is not callee
  arity, it is a tail call returning `rax` when the result is in `xmm0`, so the
  function returns its own first argument.

1. **The all-SSE return class reads its second register from nowhere.** A struct
   of 2–4 floats returns in `xmm0:xmm1` — two registers, one value — and the
   recovery models one, so the later members come from undefined variables. The
   direct continuation of `c2fb19d` and `7105e26`; `abi.rs` already has the
   eightbyte classifier and this is the case it does not spell. Use
   `clang:O0:hfa197_quad4f_roundtrip` as the measure: it emits **ten** undefined
   reads, not one, so a four-member aggregate loses most of the body.
2. **Unsigned wraparound casts swallow the sign before a float conversion**
   (`src/ir/ast/dec_render.rs:786`, diary Entry 59). `NumericConvert` consults
   `from` only to choose float-or-not, so a `SignedInt` operand is rendered by
   `write_expr_dec` with `(unsigned int)`/`(unsigned long)` machine-width casts —
   correct for wraparound — and `(double)` then converts an unsigned value. Not
   "signed-to-float is broken": `widen_int_to_float` on a bare parameter passes
   on all four lanes and always has. Only *arithmetic* operands fail. Three
   renderer sites have the shape.
3. **A float-argument callee loses its arity and its result is dropped**
   (`172:gcc:O0:double_precision_horner`). A three-argument callee is declared
   with one, its result is computed and discarded, and the function returns its
   own first argument. Pre-existing and previously unexplained.
4. **A whole-function float gate shuts and the stale value flows on.**
   `lower_scalar_float` is computed once per function (`src/ir/ast.rs:3306`) and
   threaded unchanged, so one unmodelled float producer costs an entire function
   its float arithmetic; `cvttss2si` becomes `/* asm: … */` and the
   pre-instruction value silently continues. **What shuts the gate is not known**
   — two hypotheses tested and falsified, four probes failed to reproduce, and
   `197:gcc:O2:hfa197_tagged_control` is the only reproduction. Needs an `Op`
   stream dump, not more reading.
5. **A control passes execution while reading an undefined value.**
   `gcc:O2:hfa197_scalar_control` returns the right answer on every vector and
   still emits `var0 is read but never defined`. The clearest evidence yet that
   the execution gate and the def-use census are asking different questions, and
   the argument for keeping the `slow`-marked census separate rather than folding
   it in.

Two of these were found by *helper* functions written only as negative controls,
and none was visible to the fast loop until the fixture's first baseline refresh
(diary Entry 58, fixed in `6db5fbc`). The general lesson for this queue: the
corpus finds more than the plan predicts, and a fixture for a shape with no lane
is worth more than another pass over the items below.

1. Finish the current session-owned DWARF/`TypeStore` slice: make the existing
   RED alignment expectation pass conservatively, run focused Rust tests, then
   full Rust/Python/lint/type gates before commit.
2. **[UNBLOCKED — the prerequisite landed; the note below is kept for the
   reasoning, but its "see below" ordering claim is now history]** Migrate one
   real aggregate/type consumer from the AST compatibility adapter to verified
   MIR object, memory, and type evidence. Use a real stripped and a real debug
   fixture plus a conflict/near-miss control.

   The frame partition landed in `a45c1ae` and the join was completed in the
   `MergedPointer`/`base_offsets` work: on real gcc `-O0` `ua162_store_be32`,
   MIR — which never saw a promoted local — bounds all seven `frame_coordinates`
   entries at exactly their source widths, and both base spellings agree.

   **The roadmap names the wrong consumer.** `high_variables::refine_object_cursor_values`
   asks `has_conflict_free_extent`, which is a STRIDE question, not an extent
   question; its MIR analogue needs no partition at all, and the partition
   explicitly REFUSES stride-walked objects via `UnboundedCursor`. What actually
   blocks a migration is a name-to-value correspondence across pipeline stages:
   the AST adapter receives a frame that `stack_locals` has ALREADY SPLIT — a
   store to a promoted local is a definition there, not an access — so the AST
   model contains no frame object to migrate. Pick a different consumer, or
   state the correspondence first.

   The two models **partition memory differently**, so there is no join to
   write. `src/ir/memory_objects/mir.rs` keys every stack access by
   `ObjectIdentity::MirValue(root)` where `root` is the SP/FP `Input` value, and
   folds the displacement into each access's `offset` — one object per ROOT
   POINTER. Verified on a real two-array function: a single stack object
   carrying offsets -8, -16, -28, -40, -44, -56, -60, -76. The AST adapter
   instead builds one object per PROMOTED LOCAL, which is what
   `high_variables::refine_object_cursor_values` asks about.

   Migrating any aggregate consumer therefore requires first partitioning the
   MIR frame object into per-variable extents — which is item 10. **Item 10 is a
   prerequisite of item 2, not a follow-on.** Prerequisites already landed:
   `StackLocalFacts.frame_coordinates` (`d1ffbec`), MIR reachable outside the
   debug dump (`5ab8e7d`), and the EPIC 5 query surface (`a2fcd6f`).
3. Complete the MIR queries that consumer needs (`value_at`, clobbers, reaching
   sets) instead of adding local scans.
4. **[done]** Extend the dual current-SP/CFA entry-stack coordinate model to
   ARM32 and prove it in both Thumb and A32 modes. Thumb-2's `r7` anchor was the
   missing piece; Thumb had been promoting no frame storage at all. Still open in
   EPIC 4: VFP s/d/q overlap, hard/soft-float ABI selection, PC bias, literal
   pools, condition execution. Also unfixed: `153_many_live_locals` on Thumb
   reuses `r3` as both an address cursor and a constant register, which the
   register-keyed alias map cannot represent — that needs value numbering on
   that path, not a wider coordinate model.
5. Add the `-marm` A32 fixture lane and rebuild the x86-64 GCC 15 control.
6. **[done]** Implement indirect function-table call may-uses/contracts before
   DCE and reconstruct actual reaching call arguments.

   Both halves landed. The DIRECT half (`f72851e`) taught argument recovery to
   see past returning branch arms, answer live-in spellings from the enclosing
   scope, and prove entry-constant slots across a labelled join; it repaired six
   cells, four of them in fixtures unrelated to the one that found it.

   The INDIRECT half (`191_indirect_table_args`) rests on the observation that a
   call through a RELOCATION-PROVEN table has no single callee but a complete,
   proven callee SET, so the may-use set is the union over its entries. Union is
   the safe direction; refusing is the silent-wrong-code one.

   In both halves DCE turned out NOT to be the first wrong stage. The setup is
   alive after `reconstruct_args`, `eliminate_dead_stores` and `apply_role_names`,
   and is removed by `copy_prop::remove_dead` BECAUSE the call carries no
   arguments — consequence, not cause. The sharp form: a may-use set that is not
   MATERIALISED AS ARGUMENTS is cosmetic, since at the C boundary the recompiled
   indirect call passes nothing either way.

   Still open, and worse than what this item fixed: `lift_x86` lifts
   `call *(%rcx,%rax,8)` to `call @0x0`, destroying table identity before any AST
   pass runs. That is why the `95_function_pointer_table` O2 `fold_operations`
   cells and most `191` O2 lanes still fail, and why `dispatch_operation`
   improves at all — gcc happens to emit that one as `jmp *(...)`.
7. **[done]** Build the canonical `SymbolStore` and contextual
   operand-reference index; migrate exact symbols/relocations first, then bounded
   library-name knowledge. Landed in `9d4d0e0`/`16b`-era work: `src/program/symbols.rs`,
   `symbols/object_import.rs`, `symbols/verify.rs`.
8. **[restated — no DecBench required]** Investigate the linked-list correctness
   defect and the architecture-only failures with pass-attributed traces.

   This item was written against DecBench metrics, and it does not need them.
   Our own corpus answers the same questions with EXECUTION ground truth rather
   than a similarity score, which is strictly more actionable: DecBench says the
   output looks less like the original, the fixture corpus says it computes the
   wrong answer.

   Architecture-only failures, computed directly from `arch_baseline.json` as
   "passes on x86-64, fails here". Recomputed 2026-08-15 after the AArch64 scalar
   float, SysV SSE parameter, indirect-call and dual-width fixes landed and the
   corpus grew by four fixtures:

   | architecture | 2026-08-14 | 2026-08-15 | absolute failure rate |
   |---|---:|---:|---:|
   | armv7_a32 | 153 | **164** | 320/1288 = 24.8% |
   | armv7 | 144 | **159** | 312/1288 = 24.2% |
   | i386 | 102 | **116** | 280/1290 = 21.7% |
   | aarch64 | 94 | **93** | 243/1346 = 18.1% |
   | x86_64_gcc15 | 22 | **25** | 184/1346 = 13.7% |
   | x86_64 (reference) | — | — | 173/1345 = 12.9% |

   The differential grew even though the decompiler improved, because most of
   this week's fixes were x86-64-side: every cell they moved from fail to pass on
   x86-64 that is still failing elsewhere ENLARGES this column. It is a
   differential, not a defect count, and reading a rise in it as a regression
   would be a mistake. AArch64 is the one that fell, which is where the float
   lifting landed.

   Read the absolute rate alongside it: **ARM32 is the worst architecture in the
   corpus at roughly one function in four, nearly double x86-64** — on the
   architecture design rule 11 designates a conformance target, not an optional
   afterthought. A contributing measurement: ARM32 renders 6.6% of its lifted
   instructions as an OPAQUE intrinsic, all of them the single mnemonic `add`,
   against 0.18% for x86-64 and 0% for AArch64. An opaque declares a maximal
   memory footprint, so a pure register `add` modelled that way poisons dataflow
   for everything downstream.

   **A structural contributor, now removed (2026-08-16).** The two worst
   architectures were also the two with no iteration loop. `tools/dectest.py`
   answers a question about one function in seconds, and it covered the 748
   x86-64 gate lanes only; the 2208 cross lanes were reachable exclusively
   through `tools/arch_roundtrip.py`, which has no function selection and no
   named sets, and which forces the `x86_64` control lane alongside whatever you
   asked for. Asking "what does `fib` do on armv7_a32" therefore meant executing
   every export in the fixture, twice over. Measured on a 24-core host at
   `9c4ba21`: `03_loop_shapes:i386:O2` cost **11.1 s** and now costs **1.1 s**; a
   set on one architecture went from 16.9 s to 6.6 s. `dectest` now takes an
   architecture in its compiler slot
   (`173_float_int_conversions:i386:O2:widen_int_to_float`) and
   retargets any committed set (`@loops --arch armv7_a32`), judged against
   `arch_baseline.json`. `@o0`/`@o2` are unchanged at 368 lanes each: a glob in
   the compiler slot never reaches an architecture.

   This fixes no lifter defect, and it is recorded here rather than claimed as
   progress on the numbers above. What it removes is the reason a defect on these
   lanes was more expensive to look at than the same defect on x86-64 — which is
   the mechanism by which a conformance target (design rule 11) drifts. Contrary
   to the obvious guess, the cost was never the cross builds: of the ~1.1 s a
   one-function i386 lane takes, 0.08 s is the cross compile and 0.59 s the
   pinned reference build, while an unfiltered lane spent 11.7 s of its 12 s
   inside `diff_decompile`. Function scoping bought the 10x, and no build cache
   was added because the arch loop already runs at the speed of the host one.

   **i386 has no x87 lifting at all** — found 2026-08-15, and it is the same shape
   as the AArch64 scalar-float gap that `039c7d6` closed. Grepping `lift_x86.rs`
   for `fld`, `fstp`, `fadd`, `fmul`, `fdiv`, `fild`, `fistp`, `fucomi`, `faddp`
   returns ZERO for every one. i386 does all floating point on x87, so every float
   function on that lane lifts its arithmetic to nothing. Compiling
   `173_float_int_conversions.c` with `gcc -m32 -O2` gives 16 `fstp`, 12 `flds`,
   10 `fldcw`, 5 `fnstcw`, 3 `fistpl`, 2 each of `fxch`/`fldz`/`fistpll`/`fildl`,
   and the recovered C is:

       __attribute__((no_stack_protector)) int truncate_toward_zero(void) {
           long rsp;
           cf_2 = ((unsigned long)((unsigned int)(rsp)) < (unsigned long)(8));
           /* asm: fld */
           /* asm: fld */

   A function taking a float recovered as `(void)`, its arithmetic dropped to
   comments, and `rsp` read before definition. i386-only failures cluster
   accordingly: `173_float_int_conversions` 7, `175_float_matrix_kernel` 6,
   `181_compensated_summation` 5 — 18 of 116 from this one gap.

   The other i386 cluster is `193_mapped_constant_roles` at 8, the fixture added
   for EPIC 2 the day before. Its reference resolver is exercised only on x86-64;
   32-bit PIE resolves GOT-relative addresses through a different idiom, so that
   is a coverage gap in new code rather than an old one.

   The reverse differential is also worth keeping, because it shows this is not a
   one-sided deficit: 23 functions pass on aarch64 and fail on x86-64, 20 on
   armv7, 17 on armv7_a32, 14 on x86_64_gcc15, 9 on i386.

   That is 94 AArch64-only failures against the item's 43, and they cluster:
   `141_atomics` (7), `173_float_int_conversions` (6), `175_float_matrix_kernel`
   (5), `181_compensated_summation` (5) — a float and atomics cluster. Note ARM32
   is worse than AArch64 and was never the item's subject.

   **Resolved for the float cluster (`039c7d6`), and the clustering above is
   partly wrong.** Root cause: `lift_arm64.rs` had NO SCALAR FLOAT LIFTING AT
   ALL — grepping `src/ir/` for `fadd|fsub|fmul|fdiv|scvtf|fcvtz|fcmp|fneg|fsqrt`
   returned nothing outside `lift_arm32.rs` and `lift_x86.rs`. `return (float)value;`
   decompiled to `*(float*)&value`, and the first pass dump already read
   `[] = intrinsic scvtf()` with no output, no input and no footprint, so every
   later pass was faithfully processing garbage. Two ABI holes sat behind it:
   `return_registers(Aarch64)` was `["x0","w0"]` with no `v0`/`d0`/`s0`, and
   `float_argument_bank_slot` returned `None`. 12 functions fail → pass, 0
   regressions.

   The correction worth keeping: clustering by DISASSEMBLY rather than by fixture
   name shows `71_compound_interest`, `72_loan_amortization` and `64_root_finding`
   are FIXED-POINT INTEGER fixtures containing no float instruction whatsoever.
   The attributable float cluster is 20 of the 94, not the ~38 a name-based
   reading suggests; 7 more are `141_atomics`, whose cause is entirely different
   (`ldar`/`stlrb` are simply not decoded, and these are plain acquire/release
   accessors, not exclusive-monitor loops). The remaining 65 have no float
   instruction and no single identified cause. Also worth keeping: 19 functions
   PASS on aarch64 and FAIL on x86-64, so this is a genuine two-way differential,
   not a one-sided deficit.

   Remaining in the cluster, each with its blocker named rather than left as a
   count: `fcmp`/`fcmpe` 5 cells (needs a real float NZCV model), `fcvtzu`/`ucvtf`
   2 (needs an unsigned `ScalarType`), `fmadd`/`fnmsub` 3 (a rendering decision),
   `movi v31.2d,#0` in 7, and `141_atomics` 7.

   The linked-list half is already a recorded correctness defect rather than a
   metric movement: `111_self_referential_struct:link_and_sum` declares `rbp` as
   a local and never assigns it, so every address computed from it is an
   uninitialised read. A self-referential struct is the linked list.

   Entry 53 split that in two. The `gcc:O2` lane is FIXED (`fail -> pass`): its
   `nodes[8]` extent was proven by DWARF and lost to the CFA coordinate bug. The
   `gcc:O0` lane is unchanged and has a different cause — there `rbp` IS a real
   frame register, the proven object at `rbp-144` is live and used, and the
   uninitialised read is `*(int *)(((index << 4) + rbp) - 144)`, a scaled-index
   address `resolved_memory_address` does not fold into the object it lands in.
   That is a shape-recognition gap, not a coordinate one.

   Pass-attributed traces are now actually obtainable; the instrumentation was
   only reconnected in `0ecb8e1`.
9. Finish CFG completeness and verified region ownership, then target the large
   O2-noinline GED cohort.
10. Complete aggregate constraints and ABI handling, then project them to HIR.
    ~~**Promote ahead of item 2**~~ — **done**: partitioning the MIR frame
    object into per-variable extents landed in `a45c1ae` with covered runs,
    `Spanned`/`Abutting` evidence, `bounds_at` bounds and typed refusals, and the
    coordinate join was completed afterwards. What remains of item 10 is the
    classification and ABI work, not the partition.

    One soundness hole found and closed along the way, worth recording because
    it failed OPEN rather than closed: a phi's incoming edges are `ValueId`s
    inside `Definition::Phi`, not `MirUse`s, so the escape scan over
    `function.uses()` could not see them. Accesses through an unplaceable merged
    pointer rooted at the phi value instead, leaving the frame object reporting
    an empty conflict set while bounding variables in a frame written behind its
    back — `143_dynamic_frames:alloca_in_loop` reported `{}` with a runtime-sized
    alloca sitting in the middle of its frame. Census of falsely-bounded frames
    before the fix: gcc-O0 1 of 1363, gcc-O2 5 of 609, clang-O2 4 of 639.
11. Finish semantic HIR and pure renderers, splitting the large legacy owners as
    each responsibility migrates.
12. Add dependency-aware persistence, deterministic parallelism, cancellation,
    fuzzing, and profile-led optimization.

## Required validation

Every implementation increment follows RED -> GREEN -> REFACTOR -> VERIFY with a
real compiled fixture and at least one negative control.

Focused evidence by change type:

| Change | Minimum evidence |
|---|---|
| Target/register | generated view contracts, lifter/executor differential, real A32 and Thumb binaries |
| MIR/definitions | verifier/property tests, diamonds, loops, calls, memory and corruption controls |
| Call/type | optimized real caller/callee, variadic/sret/width negatives |
| CFG/structure | edge accounting, execution, irreducible/switch/large fixtures |
| Reference | relocation and same-bits/different-context controls |
| Aggregate | debug/no-debug, array/struct/union/bitfield, ABI execution |
| Cache/parallel | cold/warm and serial/parallel deterministic differential |

Broad gate before closing a phase:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --features python-ext     # NOT bare `cargo test` — see below
uv run pytest python/tests/
uvx ruff format --check python/
uvx ruff check python/
uvx ty check python/
scripts/decbench-local-gate.sh       # OUR fixture lanes 1-3; --decbench is opt-in
```

**Corrected 2026-08-16.** This block said `cargo test` for its whole life, and
that command is a false green: `src/python_bindings/` sits behind the
`python-ext` feature (`src/lib.rs`), so a bare `cargo test` skips ~120 tests
*and never compiles that tree at all*. On 2026-08-14 a signature change there
left five call sites on the old arity and `cargo test` still reported
`2321 passed; 0 failed` — green over code it had not built. This is not a corner
of the codebase: `python_bindings/ir.rs` is the real pipeline entry point, so
most passes are only reachable through it. The same gate applies to dead-code
counts — a bare `cargo build` reported ~98 never-used functions where the shipped
configuration had 4, and two files totalling 1,782 lines looked unreachable while
running on every decompile. A plan that specifies the weaker command will keep
producing that mistake, so the plan is what had to change.

Also run the 250-function external-eval replay, architecture roundtrip matrix,
perfect/canary cells, output-health report, and performance matrix when relevant.
Report focused tests, full local gates, remote CI, score, behavior, and performance
separately. A running, skipped, environment-missing, or unrelated-red gate is not
green.

## Stop conditions

Stop the affected change and repair the foundation when:

- a transform cannot prove definition, dominance, effect, alias, or edge
  preconditions;
- incomplete input becomes apparently complete downstream;
- an unknown call/intrinsic is treated as preserving unproven state;
- ARM32 needs a second incompatible semantic or ABI path;
- inference overwrites manual, relocation, or authoritative debug facts;
- a mapped integer becomes a pointer without contextual evidence;
- a metric gain breaks execution, verification, a perfect cell, or a semantic
  canary;
- a file split leaves the same responsibilities coupled by private mutation;
- a cache entry cannot name exact dependencies and revisions;
- serial and parallel output differ; or
- performance improves by reducing coverage or silently timing out work.

## Definition of done

**This list describes an architecture, not a product, and that is a defect in
it.** Every bullet below can be satisfied by a decompiler that lifts no x87 and
no AArch64 scalar float — as this one did until 2026-08-15, while satisfying
several of them. Conversely the four largest correctness wins of that week move
none of these bullets at all.

So read this as the ARCHITECTURE track's definition of done, and hold the
correctness track to a separate one:

> **Correctness is done when**, for every architecture the project claims to
> support, no whole instruction category is unlifted, the fixture corpus records
> no undefined reads in required functions, and no pass fabricates a fact it
> cannot prove. Those are measurable today: the capability census, the
> `defuse_baseline.json` ratchet, and the fail-closed stop conditions.

The redesign is complete when Glaurung has:

- one reusable session, image, pipeline, and typed artifact boundary;
- one validated target/machine/ABI model with full ARM32 conformance;
- one verified register and memory definition graph used by production passes;
- one provenance-bearing program environment for symbols, types, objects,
  references, and call facts;
- contextual operand symbolization over exact machine values;
- aggregate recovery over stable memory objects and ABI-aware layouts;
- total verified CFG-to-HIR projection with honest fallbacks;
- pure output profiles;
- substantially smaller, single-owner modules meeting the fitness targets;
- deterministic incremental and parallel analysis;
- prompt cancellation, typed partial results, persistence safety, and fuzzed
  boundaries; and
- green execution, verifier, fixture, score, architecture, performance, and
  reliability gates on exact reproducible revisions.

Until then, each completed phase must remain independently usable, tested, and
releasable.

## Evidence and decision records

This roadmap supersedes the ordering in the older plans but not their evidence:

- [Architecture redesign](glaurung-architecture-redesign-2026-08-05.md)
- [Execution diary, 2026-08-19](decompiler-roadmap-diary-2026-08-19.md) —
  a formatter emitting syntax the project cannot run, a regression `cargo
  test` structurally could not see, and three causes where I had filed one
- [Execution diary, 2026-08-18](decompiler-roadmap-diary-2026-08-18.md) —
  the feature blind spot (8.6% of the tree never compiled by the documented
  gate), byte/word division silently discarded, and a correctness bug traced
  correctly that measurement showed cannot occur
- [Architecture review diary](glaurung-architecture-review-diary-2026-08-05.md)
- [DecBench remediation roadmap](decbench-remediation-roadmap-2026-08-08.md)
- [DecBench gap-analysis diary](decbench-gap-analysis-diary-2026-08-08.md)
- [Decompiler middle architecture](decompiler-middle-architecture.md)
- [Value-model root cause and plan](value-model-root-cause-and-plan.md)
- [Register views and verifier boundary](register-views-and-the-verifier-boundary.md)
- [Semantic structuring](semantics-preserving-structuring.md)
- [Typed SSA and HIR](typed-ssa-hlir.md)
- [ARMv7 real defects](armv7-real-defects-2026-08-05.md)
- [Table-dispatch arguments](table-dispatch-arguments-2026-08-12.md)
- [Stack-bias affine-index record](stack-bias-affine-index-2026-08-13.md)
- [Dormant transform measurements](dormant-transforms-2026-08-12.md)
- [Goto-density measurement](goto-density-measurement-2026-08-12.md)
- [Measured GED trade](ged-recovery-measured-trade.md)
- [Master integration record](master-integration-2026-08-12.md)
- [Branch retirement manifest](branch-retirement-2026-08-13.md)
- [DecBench submission readiness](decbench-submission-readiness.md)

## Appendix A — DecBench and evaluation (ON DEMAND ONLY)

**Read this appendix only when refreshing published metrics.** It is retained in
full because a paper refresh needs every one of its reproducibility requirements,
and because its `[x]` entries are the audit trail for work that really did land
upstream. It is deliberately NOT scheduled: none of its open boxes appear in the
immediate rank-ordered plan or in the dependency-ordered phases, and a box here
going unticked for a year is not a defect.

The running gate is `scripts/decbench-local-gate.sh` lanes 1-3 (our fixture
corpus). Lanes 4-5 are this appendix, and require `--decbench` or
`GLAURUNG_RUN_DECBENCH=1`. In pytest, the same boundary is the `decbench` marker,
which `pytest.ini` deselects by default; run those tests with `-m decbench`.

### Benchmark correctness and reproducibility

- [x] Merge the verified additive orphan branch and preserve its real ARM fixes.
- [x] Audit and retire stale branches/worktrees, documenting the one stack-bias
  idea that requires a clean re-port.
- [x] Rebuild a local DecBench tree with preprocessed sources so GED and
  TypeMatch can be evaluated rather than asserted.
- [x] Submit the clear empty-disassembly ByteMatch correctness fix as DecBench
  PR #61. **Merged upstream** as `af02672db6dd`.
- [x] Submit the reproducibility/efficiency follow-up as DecBench PR #62; no
  further work is planned unless upstream requests it. **Merged upstream** as
  `3db5d557a6ae`.
- [x] Pin PR #56's deterministic Glaurung backend to the exact evaluated commit
  and publish the fresh artifact. **Merged upstream** as `08f891581e6b`, so the
  backend is now part of DecBench rather than a pending submission.
- [ ] Obtain a fresh official/current-evaluator score for the exact `fb4ee6b`
  artifact; do not infer it from the preceding package. Now that #56 is merged
  this is a question of running the current upstream evaluator against the
  pinned image, not of getting a backend accepted. Note the artifact pins
  `fb4ee6ba`, and `master` has since moved past it, so decide deliberately
  whether the next score should describe the pinned commit or a fresh package.
- [ ] Keep raw outputs, package hashes, evaluator revision, metric schema,
  compiler versions, target triples, and exact function joins in every ledger.
- [ ] Keep public publication separate from local evaluation and require explicit
  authorization for result/site changes.

### Metric attack order (historical — superseded as a prioritization order)

This ordering was how work was chosen when GED / TypeMatch / ByteMatch were the
scoreboard. It is kept because a paper refresh has to explain why the campaign
attacked the metrics in this order, not because it still selects work: execution
ground truth in `tests/decompiler_fixtures/` decides that now, and the changes
that actually moved fixture cells over 2026-08-13..16 were missing capabilities
(AArch64 scalar FP, i386 x87, ARM32 modified immediates, `call *(mem)`) that this
ordering does not mention at all.

1. TypeMatch and GED are the direct quality workstreams.
2. Function contracts and stable source types have the best near-term TypeMatch
   leverage.
3. CFG completeness, value ownership, and region recovery address GED without
   unsafe text shaping.
4. Aggregate/object recovery can improve TypeMatch and ByteMatch together.
5. Architecture fixes must be justified by execution/semantic evidence even when
   they also improve metrics.
6. Textual normalization comes last.

Open benchmark investigations (for a metric refresh; not scheduled):

- [ ] Score the exact current artifact and compute union from exact row-level
  joins.
- [ ] Explain the historical `linkedlist:clang:O0` ByteMatch drop from 0.47 to
  0.10. GED was already 0.0, so “structurally closer” is not supporting evidence.
- [x] Add and evaluate the A32 `-marm` lane. 350 ratcheted `armv7_a32` lanes in
  `arch_baseline.json`.
- [x] Rebuild the x86-64 control with GCC 15 to separate compiler-shape effects
  from architecture effects. `x86_64_gcc15` is in `REQUIRED_ARCHES` with 350
  ratcheted lanes.
- [ ] Diagnose the 43 AArch64-only failures at the first wrong stage.
- [ ] Preserve the ILP32-versus-ARM distinction, missing-lane caveat,
  control-compiler caveat, and metric-soundness findings in the canonical
  evidence register.
- [ ] Continue TypeMatch work from owner-grouped defects; do not patch function
  names or expected signatures.
- [ ] Prioritize large O2-noinline GED cases after control/data-flow correctness.

### Score-campaign acceptance policy

Every candidate must:

1. reproduce on a real binary and name the first wrong semantic stage;
2. add a failing test before implementation;
3. advance the intended owner rather than create a duplicate heuristic path;
4. include near-miss controls and execution/definedness evidence where relevant;
5. rerun affected cells plus all current perfect/canary cells;
6. report coverage, mean, median, perfect count, union, and regressions;
7. compare exact function identities, not adjusted aggregate arithmetic;
8. use fresh no-cache evaluation where cache identity is in doubt; and
9. delete superseded workaround code when the foundational owner replaces it.
