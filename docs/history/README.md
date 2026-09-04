# Documentation history

> **Kind:** record · **Date:** 2026-09-02

Nothing in this directory is current guidance. Every file here is a dated
record — a session diary, a superseded plan, a defect register, a measurement
pinned to a commit that has since moved, or a design for something that was
built differently or not at all. Read it to learn *why* something is the way
it is, never to learn *what* the code does today. For that, start at
[`docs/README.md`](../README.md).

The last two columns are drawn from the per-file audit ledgers in
[`docs/history/docs-rewrite-2026-09/audit/`](docs-rewrite-2026-09/audit/),
produced against `master` @ `b8884687` on 2026-09-02.

## Root

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [pyext-separation-2024-12.md](pyext-separation-2024-12.md) | 2025-09-03 | December-2024 plan to move all PyO3 code behind a `src/py/` boundary | `src/py/` was never created; core modules still carry `#[pyclass]`; its "keep `.pyi` stubs in sync" advice is reversed by the current never-hand-write-a-`.pyi` rule. The `cfg_attr(feature, pymethods)` gotcha it records is real and still true |
| [tutorial-plan-2026-04.md](tutorial-plan-2026-04.md) | 2026-08-05 | the tutorial track's design: 64 task IDs, chapter tree, and open GAPs | superseded as a plan by the shipped tutorial; its §CC precedence ladder is one of four mutually inconsistent copies and is wrong (the code's ladder is in `llm/kb/provenance.py`); its line-427 sample path does not exist |
| [program-measures-2026-09-02.md](program-measures-2026-09-02.md) | 2026-09-02 | the research synthesis behind function identity: a four-rung identity ladder (WARP GUIDs, L1 structural invariants, the CFR feature vector, L3 value fingerprints), the XO/XC/XM evaluation protocol, and a ranked plan, with an "Execution status" ledger recording which items shipped | its four supporting surveys are in [program-measures-2026-09-02/](program-measures-2026-09-02/); what shipped from it is documented live in [`reference/function-identity-structural.md`](../reference/function-identity-structural.md) and [`development/identity-measurement.md`](../development/identity-measurement.md), and the two open diagnoses it produced are [`design/mips-discovery-gap-2026-09-02.md`](../design/mips-discovery-gap-2026-09-02.md) and [`design/cfg-discovery-determinism-2026-09-02.md`](../design/cfg-discovery-determinism-2026-09-02.md) |

## `analysis-surveys-2025/`

Pre-implementation surveys and measurement records for lifting, symbols,
interpreted formats, and language detection.

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [interpreted-README.md](analysis-surveys-2025/interpreted-README.md) | 2025-09-07 | tiered MVP plan for interpreted-format analysis | superseded by shipped `glaurung classfile`, `glaurung luac`, `glaurung java`; see [`guides/java-jvm.md`](../guides/java-jvm.md) |
| [lifting-README.md](analysis-surveys-2025/lifting-README.md) | 2026-06-10 | survey of llvm-mctoll / RetDec / mcsema and an LLVM-IR lifting target | false: "RetDec currently integrated" and `reference/retdec` — neither exists; the shipped IR is the hand-rolled LLIR in `src/ir/` |
| [retdec-test-2025-10-20.md](analysis-surveys-2025/retdec-test-2025-10-20.md) | 2025-10-20 | RetDec v4.0 run on a two-function C program, with full transcripts | self-contained experiment record; RetDec was never integrated |
| [symbols-ENHANCEMENTS.md](analysis-surveys-2025/symbols-ENHANCEMENTS.md) | 2025-09-03 | 15 proposed symbol-analysis enhancements | every code block is headed `src/triage/symbols/…`, a directory that never existed; the shipped code is `src/symbols/` and `src/analysis/elf_{got,plt}.rs` |
| [symbols-IMPLEMENTATION.md](analysis-surveys-2025/symbols-IMPLEMENTATION.md) | 2025-09-03 | the "M2 — Symbols" milestone phase plan | proposes `src/triage/symbols/` and `src/triage/suspicious.rs`; neither path exists |
| [language-detection-FAILURE_ANALYSIS.md](analysis-surveys-2025/language-detection-FAILURE_ANALYSIS.md) | 2025-09-03 | per-file failure list at a 79.4% (181/228) detection rate | corpus never named; the three language-detection records report 79.4%, 82.0% and 74.5% against three different, unstated corpora |
| [language-detection-IMPLEMENTATION_SUMMARY.md](analysis-surveys-2025/language-detection-IMPLEMENTATION_SUMMARY.md) | 2025-09-03 | a 74.5% → 82.0% improvement pass | its sketched `detect_packer(data)` API is not what shipped (`src/triage/packers.rs`); see the rate caveat above |
| [language-detection-IMPROVEMENTS.md](analysis-surveys-2025/language-detection-IMPROVEMENTS.md) | 2025-09-03 | a 73.3% → 74.5% pass over 243 binaries | third inconsistent rate; current behaviour is [`reference/language-detection.md`](../reference/language-detection.md) |

## `architecture-reviews/`

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [2026-07-13-architecture-quality-review.md](architecture-reviews/2026-07-13-architecture-quality-review.md) | 2026-07-28 | whole-repo architecture review at `cf97906` with five recommendations | (1) landed as `ProgramSession`, (5) landed as the fitness gates, (3) "one versioned repository layer" did not; superseded in intent by `refactoring-portfolio-2026-08/architecture-review-2026-08-13.md` |
| [ida-ghidra-parity-2026-08.md](architecture-reviews/ida-ghidra-parity-2026-08.md) | 2026-08-29 | a capability checklist against IDA and Ghidra, plus the `set_by` provenance essay | its provenance essay is one of five copies of one ladder — the authority is `llm/kb/provenance.py`; its "#203/#204 gating Phase 5 launch" issue numbers reference a tracker not in this repo |

## `axeyum-integration-2026-07/`

The design, risk, and evidence record for integrating the pure-Rust `axeyum`
SMT solver behind `solver-axeyum`. The live parts moved to
[`architecture/solver-backends.md`](../architecture/solver-backends.md),
[`architecture/solver/`](../architecture/solver/) and
the 31 [`decisions/solver-0NN-*.md`](../decisions/README.md) records.

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [00-motivation-and-goals.md](axeyum-integration-2026-07/00-motivation-and-goals.md) | 2026-07-13 | why an in-process, wheel-shippable solver was wanted | its central claim — `symbolic` is in neither `default` nor `python-ext`, so the wheel ships no solver — is still true |
| [01-current-state.md](axeyum-integration-2026-07/01-current-state.md) | 2026-07-16 | an interface snapshot of `src/symbolic/solver/` at 2026-07-13 | every cited line number has drifted (`solve()` :106 → :931; `Solver` :46 → :82); a second `IncrementalSolver` trait has since been added; branch `sec/ioctlance-parity` is gone |
| [03-architecture.md](axeyum-integration-2026-07/03-architecture.md) | 2026-07-19 | the intended backend architecture | predates the retained-session / warm-path / direct-delta machinery that now dominates `axeyum_backend/` |
| [04-phased-plan.md](axeyum-integration-2026-07/04-phased-plan.md) | 2026-07-16 | the P0–P6 integration plan | P0–P3 landed; **P4 ("axeyum is the default") was abandoned**; P5 partial; P6 not started |
| [05-risks-and-open-questions.md](axeyum-integration-2026-07/05-risks-and-open-questions.md) | 2026-07-13 | the risk register for the integration | R1 (performance gap) is the one that materialised; it is documented far better in `PAPER-NOTES.md` and the decision log |
| [06-validation-and-ci.md](axeyum-integration-2026-07/06-validation-and-ci.md) | 2026-07-13 | the proposed differential-oracle-for-solvers validation | the pattern shipped as `GLAURUNG_SHADOW_DIFF`; the doc predates the 4/6-cell rotation and `scripts/feature-build-gate.sh` |
| [FEEDBACK-LOG.md](axeyum-integration-2026-07/FEEDBACK-LOG.md) | 2026-07-28 | an append-only log of upstream-solver and Glaurung-side defects | the only account of the integration's failure modes; its environment line names branch `sec/axeyum-backend`, which is gone |
| [PAPER-NOTES.md](axeyum-integration-2026-07/PAPER-NOTES.md) | 2026-07-14 | research notes toward a paper | carries its own major retraction: the earlier "axeyum is 12–29× faster than z3" claim **was wrong**, caused by a width-coercion bug that errored out ~98% of queries |
| [REVIEWER-CHECKLIST.md](axeyum-integration-2026-07/REVIEWER-CHECKLIST.md) | 2026-07-28 | a skeptical-reviewer self-critique for that paper | methodology record, not project documentation |
| [capture-README.md](axeyum-integration-2026-07/capture-README.md) | 2026-09-02 | the QF_BV corpus-capture protocol and ~1,300 lines of dated capture results | the live procedure and the corpus now live at `tests/corpora/axeyum-qfbv/`; the `GLAURUNG_DUMP_QUERIES` hook it documents is still real |

## `campaigns/`

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [analyst-ergonomics-2026-06-DIFF.md](campaigns/analyst-ergonomics-2026-06-DIFF.md) | 2026-06-01 | the landed analyst-ergonomics feature set (`locks`, `group`, `diff`, PDB fetch) | the origin record for [`guides/analyst-workflows.md`](../guides/analyst-workflows.md) and [`guides/annotation-loop.md`](../guides/annotation-loop.md); still accurate, but the guides are the current reference |
| [decbench-readacross-2026-08-12.md](campaigns/decbench-readacross-2026-08-12.md) | 2026-08-12 | a read-only review of the DecBench fork, with the Thumb-bit and `--vas` fail-closed reasoning | nothing was written upstream; consistent with the DecBench boundary rule in `CLAUDE.md` |
| [float-recovery-2026-08-12.md](campaigns/float-recovery-2026-08-12.md) | 2026-08-12 | why x86 scalar float recovery needed five separate layers to agree | the detail exists nowhere else; the fixtures it added (172–175) are still in the corpus |
| [windows-poc-2026-05-25-cross-name-matching.md](campaigns/windows-poc-2026-05-25-cross-name-matching.md) | 2026-05-25 | the cross-name-matching proof of concept for binary diff | landed: `CROSS_NAME_THRESHOLD_DEFAULT = 0.85` and `--cross-name-threshold` are live |

## `data-model-2025/`

A four-model design roundtable on the core data model, plus its critiques and
the implementation plan that followed. Kept whole: cherry-picking it destroys
the record of what was proposed and declined. The live successor is
[`architecture/data-model.md`](../architecture/data-model.md).

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [IMPLEMENTATION.md](data-model-2025/IMPLEMENTATION.md) | 2026-08-05 | the phase plan that opened with `src/core/address.rs` | its sketch has a 3-variant `AddressKind`; the shipped enum has 6 |
| [nesting.md](data-model-2025/nesting.md) | 2025-09-03 | a node/edge/budget tree for containers and overlays | shipped instead as `src/triage/containers.rs` + `recurse.rs` |
| [disassembly_decompiler_foundations.md](data-model-2025/disassembly_decompiler_foundations.md) | 2025-09-03 | a status matrix and a proposed `BinaryView` aggregate | realized instead as `src/program/image.rs::ProgramImage` + `src/analysis/view.rs`; the status legend is a pre-LLIR snapshot |
| [proposal-CLAUDE.md](data-model-2025/proposal-CLAUDE.md) | 2025-09-03 | the knowledge-graph-first data-model proposal | partly adopted; its `Address.confidence` was declined |
| [proposal-GEMINI.md](data-model-2025/proposal-GEMINI.md) | 2025-09-03 | a single top-level `Project` object holding binary, address space, functions, symbols | shipped as two objects instead: `ProgramSession` (Rust) and `PersistentKnowledgeBase` (Python) |
| [proposal-GPT5.md](data-model-2025/proposal-GPT5.md) | 2025-09-03 | a minimal `Address` with three kinds and `bits: 32\|64` | closest to what shipped, minus three extra kinds |
| [critique-GEMINI.md](data-model-2025/critique-GEMINI.md) | 2025-09-03 | a critique recommending CLAUDE's `Address` shape | `space`, `kind` and `symbol_ref` adopted; `confidence` rejected; `width` renamed `bits` |
| [critique-GPT5.md](data-model-2025/critique-GPT5.md) | 2025-09-03 | three P0 recommendations on `Address` | the record that narrowing `AddressKind` to VA/RVA/FileOffset was **proposed and declined** — without it the six variants look like an oversight |

## `decompiler-checkpoints-2026-07/`

Read these in filename order: they chain, and the causal path from 123 to 169
of 250 DecBench-compilable functions exists only here.

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [2026-07-27-three-way-roundtrip-diary.md](decompiler-checkpoints-2026-07/2026-07-27-three-way-roundtrip-diary.md) | 2026-07-28 | a Glaurung / Ghidra / angr round-trip comparison at `b66a4cb` | its own banner says the rankings are superseded by `39d1b44` / `416b02d` / `2f32318` |
| [2026-07-30-high-variable-pointer-propagation.md](decompiler-checkpoints-2026-07/2026-07-30-high-variable-pointer-propagation.md) | 2026-07-30 | 123/250 → 127/250 via pointer high-variables | the counts are pinned to July checkpoints; today's corpus and baselines are different instruments |
| [2026-07-30-named-callee-prototypes.md](decompiler-checkpoints-2026-07/2026-07-30-named-callee-prototypes.md) | 2026-07-30 | 127/250 → 162/250, the single largest step in the chain | as above |
| [2026-07-30-authoritative-call-prototypes.md](decompiler-checkpoints-2026-07/2026-07-30-authoritative-call-prototypes.md) | 2026-07-30 | 162/250 → 169/250 via authoritative call prototypes | as above; `src/ir/call_contracts.rs` still exists |
| [2026-07-30-call-site-specs-and-decbench.md](decompiler-checkpoints-2026-07/2026-07-30-call-site-specs-and-decbench.md) | 2026-07-30 | the `Stmt::Call` + `CallSiteSpec` design | still live as `call_contracts::refine_call_site_specs` |
| [2026-07-30-dwarf-locked-return-contracts.md](decompiler-checkpoints-2026-07/2026-07-30-dwarf-locked-return-contracts.md) | 2026-07-30 | locking return contracts to DWARF | `src/ir/dwarf_fields.rs` / `dwarf_type_env.rs` shipped |
| [2026-07-30-stripped-elf-tail-calls.md](decompiler-checkpoints-2026-07/2026-07-30-stripped-elf-tail-calls.md) | 2026-07-30 | tail-call recovery in stripped ELF | shipped as `call_args::recover_resolved_tail_calls` |
| [2026-07-30-terminal-branch-kinds.md](decompiler-checkpoints-2026-07/2026-07-30-terminal-branch-kinds.md) | 2026-07-30 | a successor-ordering fix in `detect_if_shape` | `src/ir/structure/` has since been split into eight modules |
| [2026-08-06-architecture-decbench-execution-diary.md](decompiler-checkpoints-2026-07/2026-08-06-architecture-decbench-execution-diary.md) | 2026-08-08 | a timestamped execution diary with an explicit evidence-rules preamble | its test and ratchet counts are an August snapshot; the five evidence rules in its preamble are the durable part |

## `decompiler-review-2026-09-02/`

An independently checked review of the decompiler as built, at `master` @
`5c4df8d2` and rechecked at `b8884687`. It is evidence, not a work queue: the
live plan is [`development/roadmap/`](../development/roadmap/README.md).

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [README.md](decompiler-review-2026-09-02/README.md) | 2026-09-02 | the review's index, scope, and the commits it was checked at | the entry point for the eight files below |
| [01-architecture-as-built.md](decompiler-review-2026-09-02/01-architecture-as-built.md) | 2026-09-02 | the decompiler's modules and their responsibilities, each claim cited to a `file:line` | a snapshot: the `file:line` citations drift with every split |
| [02-pipeline-map.md](decompiler-review-2026-09-02/02-pipeline-map.md) | 2026-09-02 | the ordered pass schedule of `decompile_at_session` under `style = "decbench"` | the live pass list is generated: [`reference/decompiler-passes.md`](../reference/decompiler-passes.md) |
| [03-observed-output.md](decompiler-review-2026-09-02/03-observed-output.md) | 2026-09-02 | six fixture functions decompiled by hand against the shipped extension | pinned to that build; re-run `tools/dectest.py` for current output |
| [04-defect-inventory.md](decompiler-review-2026-09-02/04-defect-inventory.md) | 2026-09-02 | every known-broken, known-bad, accepted and ratcheted entry the test estate carried, counted at `5c4df8d2` | the counts move with the baselines; the JSON files it names are the live source |
| [05-planning-docs-audit.md](decompiler-review-2026-09-02/05-planning-docs-audit.md) | 2026-09-02 | what 24 planning documents under `docs/design/` and `docs/development/` had already decided, tried, and abandoned | the tree it audited was reorganized by the 2026-09 documentation rewrite, so most of its paths have moved |
| [06-recommendations.md](decompiler-review-2026-09-02/06-recommendations.md) | 2026-09-02 | ten recommendations ordered by leverage, each with its evidence and how it would be judged | proposals only; nothing here is scheduled by being here |
| [PLAN.md](decompiler-review-2026-09-02/PLAN.md) | 2026-09-02 | a file-level execution specification for the recommendations: work packages, tests, sizing, stop conditions | explicitly subordinate to the roadmap; it is not a checkbox authority |
| [mir-trial-results.md](decompiler-review-2026-09-02/mir-trial-results.md) | 2026-09-02 | the WP1 bounded-MIR definedness trial | **rejected for production use**; the negative result is the durable part |
| [results/wp8-dwarf-variadic-declarations.md](decompiler-review-2026-09-02/results/wp8-dwarf-variadic-declarations.md) | 2026-09-04 | trusted DWARF variadic markers preserved through authoritative rendered declarations, with the remaining machine-to-C lowering defect separated | bounded GCC/Clang x86-64 fixture evidence; stripped inference, PDB variadic facts, and complete `va_start` lowering remain open |
| [results/wp6-per-use-signedness.md](decompiler-review-2026-09-02/results/wp6-per-use-signedness.md) | 2026-09-04 | first incremental type-constraint slice: exact-use signedness stops x86 register-write and index semantics from poisoning stripped C declarations | bounded to signedness at ABI live-ins; the general WP6 constraint solver and stripped jump-table body recovery remain open |
| [results/wp0-known-failure-batching.md](decompiler-review-2026-09-02/results/wp0-known-failure-batching.md) | 2026-09-04 | replaced duplicate per-function CLI decompiles with deterministic per-binary batches, bounded workers, filters, and checkpoint/resume; full 1,676-object refresh completed in 203.97 seconds | current inventory movement spans multiple landed increments and is not attributed wholly to WP6 |

## `design/`

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [decompiler-roadmap-2026-08-13.md](design/decompiler-roadmap-2026-08-13.md) | 2026-08-13 | the single consolidated decompiler tracker — 193 checkboxes over five epics, nine phases, a file-size program, and a DecBench appendix, at planning baseline `fb4ee6ba` | superseded by [`development/roadmap/README.md`](../development/roadmap/README.md) (its meta-guidance and its on-demand DecBench appendix), [`development/roadmap/real-binary-decompiler.md`](../development/roadmap/real-binary-decompiler.md) ("Carried from the 2026-08-13 roadmap" holds every item of it that was still open), and [`development/testing-gates.md`](../development/testing-gates.md) (its fitness/file-size program, as a measured gate). Known false: every number in its file-size section (it says 314 product files / 166,455 LOC / mean 530.1 / `ir/ast.rs` at 11,628 lines / 5 of 7 targets missed; the baseline measured 455 / 185,318 / 407.3 / 1,711 / 6 of 9 met), and "MIR is not BUILT on a production decompile" — `5ab8e7d3` and `614cd661` made it reachable as `PreparedLlir::mir()`; what is still open is that nothing consumes it |

## `design/campaigns/`

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [armv7-real-defects-2026-08-05.md](design/campaigns/armv7-real-defects-2026-08-05.md) | 2026-08-11 | ARMv7 defect archaeology with four root causes, all since fixed | its `210/256` and test counts are pinned to 2026-08-05; `arch_baseline.json` now holds 2,473 lanes |
| [backlog-2026-08-05.md](design/campaigns/backlog-2026-08-05.md) | 2026-08-13 | eight items preserved from a task list | superseded by `defect-register-2026-08-05.md`, which was written to reconstruct exactly these eight |
| [defect-register-2026-08-05.md](design/campaigns/defect-register-2026-08-05.md) | 2026-08-11 | a defect register with root-cause writeups | calls itself a "live evidence register"; it is closed — 10 items CLOSED, 1 FIXED, 1 OPEN, and untouched since 2026-08-07 |
| [string-recovery-root-cause-2026-08-03.md](design/campaigns/string-recovery-root-cause-2026-08-03.md) | 2026-08-11 | the string-recovery campaign, headlined by a metric correction | its gate numbers are August-03 vintage |
| [table-dispatch-arguments-2026-08-12.md](design/campaigns/table-dispatch-arguments-2026-08-12.md) | 2026-08-12 | why a table-dispatched call dropped its arguments, and a wrong fix that was reverted | **the defect it describes is fixed**: `95_function_pointer_table:gcc:O2:dispatch_operation` is `pass` in `baseline.json` |
| [multi-decompiler-roundtrip-2026-08-04.md](design/campaigns/multi-decompiler-roundtrip-2026-08-04.md) | 2026-08-13 | ten DecBench projects across four decompilers | its durable point is a caveat: Ghidra/IDA/Binja are not installed here, so every such number in our docs is imported and cannot be recomputed |
| [ged-recovery-measured-trade.md](design/campaigns/ged-recovery-measured-trade.md) | 2026-07-28 | a correctness bug in `drop_dead_preamble` on the retired `recover-ged-cells` branch | strictly experimental; `python/tests/test_loop_hoist_traps.py` cites this file in an assertion message |
| [fixture-expansion-2026-08-27.md](design/campaigns/fixture-expansion-2026-08-27.md) | 2026-08-27 | 14 new fixtures, 266 judged cells, and five newly named defects | its §0 argument — execution-differential testing is blind to structure — motivated the `has_switch` / `goto_free` predicates and belongs in the testing guide |
| [decbench-defect-reproductions-2026-08-27.md](design/campaigns/decbench-defect-reproductions-2026-08-27.md) | 2026-08-27 | that two of our three named defects were described backwards in our own docs | pinned to `5e168798`; its §7 four-workstream plan was never folded into a roadmap |
| [decbench-native-provenance-2026-08-27.md](design/campaigns/decbench-native-provenance-2026-08-27.md) | 2026-08-29 | that we drop `ins.va` at lowering, so no line map is possible | verified true; also the only record that DecBench's AST audit lives on an unmerged upstream draft and that the eval-kit format cannot carry provenance |
| [decbench-full-score-audit-2026-08-30.md](design/campaigns/decbench-full-score-audit-2026-08-30.md) | 2026-08-31 | a pinned score audit at `229fbb1d` (GED 32.275%, type 21.812%, byte 5.893%, union 41.553%) | correctly caveated as not a submission replay |
| [decbench-full-failure-taxonomy-2026-08-31.md](design/campaigns/decbench-full-failure-taxonomy-2026-08-31.md) | 2026-09-01 | the 217-row failure taxonomy over 803 binaries at Glaurung `7bc73539` | self-limiting: "the repository has moved since this measurement"; it is still the cited evidence for the live remediation plan |
| [decbench-submission-readiness.md](design/campaigns/decbench-submission-readiness.md) | 2026-08-11 | what would have to be true before opening a DecBench PR, and a "do not submit" decision | **false**: "there is no upstream PR, issue, or submission" — PRs #56, #61 and #62 were later merged (roadmap Appendix A) |

## `design/diaries/`

Append-only session logs. High-quality evidence, no guidance.

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [decbench-gap-analysis-diary-2026-08-08.md](design/diaries/decbench-gap-analysis-diary-2026-08-08.md) | 2026-08-13 | the DecBench gap analysis at Glaurung `c1cfdc97` / DecBench `0a4e85bc` | its projected leaderboard ranks are explicitly projections; its absolute GED/union totals were later called unusable |
| [decompiler-roadmap-diary-2026-08-13.md](design/diaries/decompiler-roadmap-diary-2026-08-13.md) | 2026-08-16 | entries 1–48 of the roadmap campaign, RED → GREEN → VERIFY | the largest single document in the old `design/` tree; a log, not a design |
| [decompiler-roadmap-diary-2026-08-16.md](design/diaries/decompiler-roadmap-diary-2026-08-16.md) | 2026-08-17 | entries 54–69 | its two methodology lessons — write the command next to the number; measure the tool's noise floor first — are the durable part |
| [decompiler-roadmap-diary-2026-08-18.md](design/diaries/decompiler-roadmap-diary-2026-08-18.md) | 2026-08-18 | entries 70–79, including the origin of the feature-gate rule | the `src/lib.rs` line number it cites has drifted; the rule itself is in `CLAUDE.md` |
| [decompiler-roadmap-diary-2026-08-19.md](design/diaries/decompiler-roadmap-diary-2026-08-19.md) | 2026-08-19 | entries 80+, including the ruff `target-version` mismatch | that defect is fixed |
| [decompiler-roadmap-diary-2026-08-31.md](design/diaries/decompiler-roadmap-diary-2026-08-31.md) | 2026-09-01 | the redirect of the durable plan to `development/roadmap/real-binary-decompiler.md` | its Entry 6 claim that ARM32 has no Cortex-M `MRS`/`MSR` implementation is **false**: `src/ir/lift_arm32/sysreg.rs` exists |
| [glaurung-architecture-review-diary-2026-08-05.md](design/diaries/glaurung-architecture-review-diary-2026-08-05.md) | 2026-08-13 | the evidence log behind the 2026-08-05 architecture redesign | observations before recommendations; checkout `89b220e` |

## `design/plans-superseded/`

Six of these each restate one thesis — introduce a typed SSA/MIR spine between
LLIR and rendering. The architecture that came out of them is
[`architecture/`](../architecture/).

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [decompiler-middle-architecture.md](design/plans-superseded/decompiler-middle-architecture.md) | 2026-07-26 | the original typed-SSA-spine thesis and its root causes | superseded by the 2026-08-05 redesign; its Phase 3/4 targets are still unbuilt — `src/ir/mir/` exists with no production consumer |
| [value-model-root-cause-and-plan.md](design/plans-superseded/value-model-root-cause-and-plan.md) | 2026-07-26 | that `VReg` is an overloaded key, and a 92% execution differential that regressed 25 of 56 metric cells | explicitly superseded by `decompiler-plan-2026-07-27.md`, itself superseded |
| [semantics-preserving-structuring.md](design/plans-superseded/semantics-preserving-structuring.md) | 2026-07-24 | "the structurer must be total, not a better matcher", and verifier-first | shipped in spirit: `src/ir/structure/` has `region.rs`, `verify.rs`, `fallback.rs`, `path_predicates.rs` |
| [typed-ssa-hlir.md](design/plans-superseded/typed-ssa-hlir.md) | 2026-08-07 | a Phase 1–5 ladder to delete `remap_type_map` and the render-time `DEC_*` cells | partly shipped: `remap_type_map` is still live and ten `DEC_*` thread-locals remain |
| [decompiler-plan-2026-07-27.md](design/plans-superseded/decompiler-plan-2026-07-27.md) | 2026-07-28 | the July-27 plan | self-labelled historical the next day; superseded by the roadmap |
| [decompiler-gap-plan-2026-08-01.md](design/plans-superseded/decompiler-gap-plan-2026-08-01.md) | 2026-08-11 | four workstreams against Ghidra/angr/RetDec, several marked RESOLVED inline | its `/nas4` corpus is not in this repo, so nothing here is reproducible from a clean checkout |
| [glaurung-architecture-redesign-2026-08-05.md](design/plans-superseded/glaurung-architecture-redesign-2026-08-05.md) | 2026-08-13 | the direct ancestor of `design/decompiler-roadmap.md` | its proposed `src/lift/`, `src/ir/hir/`, `src/render/` were **never created** |
| [decompiler-rearchitecture-2026-08-06.md](design/plans-superseded/decompiler-rearchitecture-2026-08-06.md) | 2026-08-07 | the same thesis one day later, with a 2026-08-07 checkpoint | a duplicate of the 08-05 redesign's argument |
| [decbench-remediation-roadmap-2026-08-08.md](design/plans-superseded/decbench-remediation-roadmap-2026-08-08.md) | 2026-08-13 | a ranked DecBench repair plan | its banner says "active"; it is not — the roadmap consolidated it, and its baseline is ~400 commits behind |
| [decompiler-refactors.md](design/plans-superseded/decompiler-refactors.md) | 2026-07-25 | July-25 metrics (GED 5.99 vs angr 7.59) and a refactor list | measured with a script in `/tmp` that no longer exists; irreproducible |
| [decbench-full-leaderboard-data-plan.md](design/plans-superseded/decbench-full-leaderboard-data-plan.md) | 2026-08-31 | the operational runbook for the full leaderboard run `20260831T180316Z` | the run completed; the score audit and failure taxonomy are its outputs, so the "execution in progress" banner is spent |

## `design/repo-operations/`

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [branch-retirement-2026-08-13.md](design/repo-operations/branch-retirement-2026-08-13.md) | 2026-08-13 | branch → SHA → disposition for every branch deleted in the 2026-08-13 audit | irreplaceable: branch deletion is the one step of that audit that cannot be recovered by reading the repository |
| [master-integration-2026-08-12.md](design/repo-operations/master-integration-2026-08-12.md) | 2026-08-13 | three hand-ported merge conflicts, with the commits that resolved them | self-closed the same day |
| [orphan-adjudication-2026-08-19.md](design/repo-operations/orphan-adjudication-2026-08-19.md) | 2026-08-19 | the adjudication of 300 dangling commits at `master@08046a87` | a one-time cleanup record; contains its own correction of a first, wrong pass |

## `development/`

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [roadmap.md](development/roadmap.md) | 2025-09-07 | the M0–M5 triage-pipeline roadmap, pre-decompiler | largely complete; its Nice-to-Haves (YARA, ssdeep) were abandoned. Do not infer current CLI support from it |
| [decompiler-test-strategy.md](development/decompiler-test-strategy.md) | 2026-08-13 | the fixture-corpus test strategy written at 131 fixtures | the corpus is now 219 sources; its "Rust and Go fixtures are out of scope" is false — both exist. Items 6–8 (producer matrix, csmith, coverage-guided gaps) are still open; the live successor is [`development/decompiler-testing.md`](../development/decompiler-testing.md) |
| [2026-07-27-uncommitted-work-handoff.md](development/2026-07-27-uncommitted-work-handoff.md) | 2026-07-28 | a closed handoff of uncommitted work | self-labelled closed on 2026-07-28; all cited files and commits still resolve |

## `development/test-estate/`

The test-estate phases that are finished or that were merged into a live
roadmap plan. The open phases stay live under
[`development/test-estate/`](../development/test-estate/).

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [01-reachability.md](development/test-estate/01-reachability.md) | 2026-08-31 | the plan to make every test file reachable and every skip accounted for | **landed**: `test_estate_reachability.py` exists, `pytest.ini` has `-ra`, all 14 `tests/triage/*.rs` are declared. Reads as an open plan; it is not. Five tests still cite it in docstrings |
| [02-canary-determinism.md](development/test-estate/02-canary-determinism.md) | 2026-08-31 | the plan for committed canary objects and a determinism check | **landed** at `b4d23221`: `tests/decompiler_fixtures/canary/` plus `test_decompiler_canary.py` and `test_decompiler_determinism.py` |
| [09-asset-hygiene.md](development/test-estate/09-asset-hygiene.md) | 2026-08-31 | 63 unparseable sample-metadata files and an asset-hygiene plan | **landed** at `937425d0`: 339 metadata files now parse, 0 fail; the flat path the doc names no longer exists |
| [04-pe-macho.md](development/test-estate/04-pe-macho.md) | 2026-09-01 | the plan to make PE and Mach-O real fixture lanes with clang-cl and zig | **merged into** [`development/roadmap/pe-pdb-macho-parity.md`](../development/roadmap/pe-pdb-macho-parity.md), which carries its three `lld-link`/`libcmt` caveats and the `win10-dismcore.dll` TLS finding. The lanes it planned landed at `8c0a89f6`, `99113bc8`, `c7200d2d` and `ba2fe5c2`; its own text says the newer plan supersedes its rough counts |
| [06-perf-ratchet.md](development/test-estate/06-perf-ratchet.md) | 2026-08-31 | the design for an instruction-count performance baseline and a gate that reads it | **merged into** [`development/roadmap/performance-determinism-ratchet.md`](../development/roadmap/performance-determinism-ratchet.md), which carries its instructions-not-seconds rationale and the RSS-canary argument. Built (`a5f47189`, `a938d897`) and then extended well past this design; its 6.3 asks for a `CLAUDE.md` bullet that now lives in `development/testing-gates.md` |

## `execution-engine-2026-06/`

A top-down design effort written in one 2026-06-10 session and overtaken by
its own implementation in the same commit. Its two "read this first" files
both assert that no code exists; `src/exec/` and `src/symbolic/` were created
by the commit that added them. The live description is
[`architecture/execution-engine.md`](../architecture/execution-engine.md); the
surviving research and decisions moved to
[`design/execution-engine-research/`](../design/execution-engine-research/) and
[`decisions/`](../decisions/).

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [STATUS.md](execution-engine-2026-06/STATUS.md) | 2026-06-11 | the June IOCTLance push worklog — loop bounds, z3 `SortDiffers`, exponential `collect_syms` | **self-contradicting**: says "no implementation code has been written yet; `src/exec/`, `src/symbolic/` do not exist" beneath a table calling Phases 0–6 done. All of it exists. The worklog is the only account of the obfuscation work |
| [PLAN.md](execution-engine-2026-06/PLAN.md) | 2026-08-05 | the task-level checklist for Phases 0–7 | best-maintained file of the tree, but blind to everything after June: no axeyum, no `ordered_trace`, no `concretization.rs`; 4.5 and 4.6 are wrong |
| [00-motivation-and-goals.md](execution-engine-2026-06/00-motivation-and-goals.md) | 2026-06-10 | goals G1–G7 and non-goals N1–N6 for the engine | the charter still describes the built system; its "there is no emulation or symbolic execution today" opening is false |
| [architecture/README.md](execution-engine-2026-06/architecture/README.md) | 2026-06-10 | the proposed module layout and Cargo feature block | roughly half fiction: `src/os/`, `exec/arch/`, `exec/hooks.rs`, `exec/liftcache.rs`, `symbolic/symstate.rs` were never created; the feature block is wrong in three places and omits four features |
| [architecture/executable-llir.md](execution-engine-2026-06/architecture/executable-llir.md) | 2026-08-07 | a proposed `Value::Reg(VReg, Width)` / `Const{value,width}` shape | **rejected in implementation**: width lives on `VReg`. What shipped instead — `Op::Undef`, `lower_unknowns`, `src/ir/verify.rs` — is not described here |
| [architecture/value-domain-trait.md](execution-engine-2026-06/architecture/value-domain-trait.md) | 2026-06-10 | the `Domain` trait keystone, which did ship | signature drift: the real trait has no `type Mem`/`load`/`store`; its concolic `Val = (ExprId, u128)` was never implemented |
| [architecture/machine-state.md](execution-engine-2026-06/architecture/machine-state.md) | 2026-06-10 | a flat byte-offset register file, COW memory, hooks and a lift cache | about half unbuilt: no perms, no dirty-page COW, no `code_pages`, no `hooks.rs`, no `liftcache.rs`; snapshots are `Machine: Clone` |
| [architecture/arch-abstraction.md](execution-engine-2026-06/architecture/arch-abstraction.md) | 2026-06-10 | a `trait CpuModel` in `src/exec/arch/{x86_64,arm64}.rs` | neither the trait nor the directory exists |
| [architecture/helpers-and-intrinsics.md](execution-engine-2026-06/architecture/helpers-and-intrinsics.md) | 2026-06-10 | `Op::Intrinsic` and the per-domain fallback semantics | the semantics shipped and are the durable part; the coverage roadmap (ARM64 scalar, SIMD, FP, atomics) is still open |
| [architecture/os-abi-layer.md](execution-engine-2026-06/architecture/os-abi-layer.md) | 2026-06-10 | an `OsLayer<D>` in `src/os/` with syscall and libc summaries | shipped instead as the much thinner `src/exec/simproc.rs`; the Windows/IRP half was superseded by `src/symbolic/ioctl.rs` |
| [architecture/symbolic-engine.md](execution-engine-2026-06/architecture/symbolic-engine.md) | 2026-06-10 | `SymState`, a `push`/`pop` `Solver` trait, and a `BinaryHeap` `Explorer` | none of those exist: the trait is one `check()` method, and `explore.rs` is a DFS worklist with no `dist_to_sink` |
| [architecture/determinism.md](execution-engine-2026-06/architecture/determinism.md) | 2026-06-10 | the determinism rules for the engine | rule 6 ("budgets are instruction counts, not timeouts") is contradicted by the shipped wall-clock deadline and 250 ms solve timeout |
| [phases/README.md](execution-engine-2026-06/phases/README.md) | 2026-06-10 | the phase index and its "net new modules" column | most of the named modules were never created |
| [phases/phase-0-ir-hardening.md](execution-engine-2026-06/phases/phase-0-ir-hardening.md) | 2026-08-05 | IR hardening tasks 0.1–0.8 | 0.1 (`Const{value,width}`) was rejected; 0.6 (`src/ir/verify.rs`) shipped |
| [phases/phase-1-concrete-emulator.md](execution-engine-2026-06/phases/phase-1-concrete-emulator.md) | 2026-06-10 | the concrete emulator tasks, and the only surviving copy of the validated `Domain` prototype | its `exec/arch/`, `exec/liftcache.rs`, `exec/helpers/` do not exist; the ≥95% Unicorn exit criterion was never reported as such |
| [phases/phase-2-coverage-and-arm64.md](execution-engine-2026-06/phases/phase-2-coverage-and-arm64.md) | 2026-06-10 | ARM64 and SIMD/FP coverage tasks | roughly 20% done; 2.3–2.8 are still open |
| [phases/phase-3-snapshots-hooks-os.md](execution-engine-2026-06/phases/phase-3-snapshots-hooks-os.md) | 2026-06-10 | snapshots, hooks, self-modifying code, and the OS layer | only 3.4 shipped, and as `src/exec/simproc.rs` |
| [phases/phase-4-concolic-and-smt.md](execution-engine-2026-06/phases/phase-4-concolic-and-smt.md) | 2026-06-10 | the concolic and SMT tasks | 4.2's concrete-shadow concolic and 4.3's `easy-smt` never shipped; 4.5 shipped as `solver/constraint_cache.rs` |
| [phases/phase-5-symbolic-exploration.md](execution-engine-2026-06/phases/phase-5-symbolic-exploration.md) | 2026-06-10 | exploration, symbolic memory, and directed search | `symstate.rs`, `symmem.rs` and directed search were never built; `explore.rs` shipped and was later split |
| [phases/phase-6-pyo3-and-agent-tools.md](execution-engine-2026-06/phases/phase-6-pyo3-and-agent-tools.md) | 2026-08-05 | the PyO3 surface and two proposed CLI commands | only `glaurung.engine.emulate_function` shipped; there is no `Emulator` class and no `emulate` / `find-inputs` command |
| [phases/phase-7-applications.md](execution-engine-2026-06/phases/phase-7-applications.md) | 2026-06-10 | the application phase (deobfuscation, IOCTL sinks, scorecard metrics) | entirely unstarted as written; 7.4 happened by another route via `src/symbolic/ioctl.rs` |
| [testing/README.md](execution-engine-2026-06/testing/README.md) | 2026-08-05 | the six-layer test strategy for the engine | understates reality: CI now runs `cargo test --features symbolic` and `scripts/feature-build-gate.sh` covers the solver lanes |
| [testing/differential-oracle.md](execution-engine-2026-06/testing/differential-oracle.md) | 2026-06-10 | the Unicorn differential oracle, which shipped as `src/exec/oracle.rs` | its caveat that Unicorn itself diverges from ARM silicon exists nowhere else; the ≥95% pass-rate target was never operationalised |
| [testing/fixtures-and-corpus.md](execution-engine-2026-06/testing/fixtures-and-corpus.md) | 2026-06-10 | a proposed `tests/fixtures/exec/` layout and corpus rules | the layout was never built; the rules — no fabricated CPU state, seeded generated corpora allowed — are the durable part |

## `java-jvm-2026-05/`

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [jvm-agentic-analysis-plan.md](java-jvm-2026-05/jvm-agentic-analysis-plan.md) | 2026-05-16 | the JVM analysis implementation diary and roadmap | carries its own staleness warning: its "current state" passages lag the capability ledger, which is now [`guides/java-jvm.md`](../guides/java-jvm.md) |

## `llm/`

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [ROADMAP.md](llm/ROADMAP.md) | 2026-08-05 | the LLM subsystem roadmap and its "Built" status table | **false**: "Atomic tools (22)" — `llm/tools/` holds ~239 files. Its §1–§7 design sketch is the original 2025 draft, superseded by its own "Not built" table |
| [AGENT_ITERATION.md](llm/AGENT_ITERATION.md) | 2025-09-07 | the single-pass-only limitation of the first agent design | predates `agents/{single_pass,iterative,iterative_refinement}.py`, all of which exist |
| [ITERATION_SUMMARY.md](llm/ITERATION_SUMMARY.md) | 2025-09-07 | a pre-refactor assessment of the same limitation | near-verbatim duplicate of `AGENT_ITERATION.md` |
| [AGENT_REFACTOR_GUIDE.md](llm/AGENT_REFACTOR_GUIDE.md) | 2026-08-05 | the refactor-era guide to `ModelHyperparameters`, `AnalysisResult`, `ExecutionState` | `agents/base.py` still carries those types; the contract doc is now [`reference/llm-tool-contract.md`](../reference/llm-tool-contract.md) |
| [RE_TOOLS_OVERVIEW.md](llm/RE_TOOLS_OVERVIEW.md) | 2025-09-07 | the first-generation RE tool overview | uses `openai:gpt-4.1-mini` and references `tools.py` / `re_tools_simple.py`, none of which are current |
| [FEATURES-001.md](llm/FEATURES-001.md) | 2025-09-07 | a per-agent output-model design via `models/analysis.py` | abandoned in favour of KB nodes and edges, per the roadmap's own "Diverged from plan" section |

## `parsers-2025/`

Per-format parser design records. The accurate current index is
[`guides/parsers-and-formats.md`](../guides/parsers-and-formats.md); the
shipped format references are under [`reference/formats/`](../reference/formats/).

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [elf-README.md](parsers-2025/elf-README.md) | 2025-08-31 | the pre-consolidation ELF parser design | predates the owned ELF parser; `src/formats/elf/` shipped with 12 submodules and a different API |
| [elf-consolidation-plan.md](parsers-2025/elf-consolidation-plan.md) | 2025-09-12 | the ELF consolidation plan | **executed**: the named submodules all exist |
| [elf-migration-guide.md](parsers-2025/elf-migration-guide.md) | 2025-09-12 | the ELF migration sketch | never revalidated against the current ELF API |
| [elf-technical-design.md](parsers-2025/elf-technical-design.md) | 2025-09-12 | the ELF technical design snapshot | a snapshot, not the current Rust API |
| [pe-coff-README.md](parsers-2025/pe-coff-README.md) | 2026-05-16 | the pre-consolidation PE/COFF parser design | the real API is `src/formats/pe/` plus `directories/{debug,export,import,resource,tls}.rs` |
| [pe-coff-windows-resources-test-plan.md](parsers-2025/pe-coff-windows-resources-test-plan.md) | 2026-05-16 | a Windows resource capability and test plan | much of it shipped as `directories/resource.rs` and the `pe resources/manifest/version` commands |
| [pe-consolidation-plan.md](parsers-2025/pe-consolidation-plan.md) | 2025-09-12 | the PE consolidation plan | **executed** |
| [pe-migration-guide.md](parsers-2025/pe-migration-guide.md) | 2025-09-12 | the PE migration sketch | code samples are archival |
| [pe-technical-design.md](parsers-2025/pe-technical-design.md) | 2025-09-12 | the PE technical design snapshot | as above |
| [macho-README.md](parsers-2025/macho-README.md) | 2025-08-31 | the proposed consolidated Mach-O parser | **never built**: there is no `src/formats/macho`; Mach-O is handled by `src/symbols/macho.rs` and triage sniffers |
| [macho-consolidation-plan.md](parsers-2025/macho-consolidation-plan.md) | 2025-09-12 | the Mach-O consolidation plan | never implemented |
| [macho-migration-guide.md](parsers-2025/macho-migration-guide.md) | 2025-09-12 | a migration guide for that unimplemented parser | targets a parser that does not exist |
| [macho-technical-design.md](parsers-2025/macho-technical-design.md) | 2025-09-12 | the Mach-O technical design | cites `reference/specifications/macho/golang_macho.go`; the file is actually under `.../elf/` |
| [android-README.md](parsers-2025/android-README.md) | 2025-08-31 | the Android APK/DEX parser design | superseded by the shipped `src/formats/{apk,axml,dex,sepolicy}` and [`reference/formats/android.md`](../reference/formats/android.md) |
| [archive-README.md](parsers-2025/archive-README.md) | 2025-08-31 | an archive-extraction design | never built: triage does bounded container detection only. Cites `reference/specifications/archive/archive.h`, which does not exist |
| [dotnet-README.md](parsers-2025/dotnet-README.md) | 2025-08-31 | a .NET/CIL parser design | shipped instead as `src/analysis/cil_metadata.rs`; there is no `src/formats/dotnet` |
| [python-README.md](parsers-2025/python-README.md) | 2025-08-31 | a Python bytecode deep-parser design | never built: no marshal or code-object parsing anywhere in `src/`, only header/magic detection |
| [wasm-README.md](parsers-2025/wasm-README.md) | 2025-08-31 | a WebAssembly deep-parser design | never built: only `Format::Wasm` detection in triage |

## `program-measures-2026-09-02/`

The four literature surveys the identity research synthesis rests on. Every URL
in them came from a fetch or a search result on 2026-09-02, and unverified
claims are marked as such in the text.

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [01-binary-similarity-literature.md](program-measures-2026-09-02/01-binary-similarity-literature.md) | 2026-09-02 | a survey of classical and learned binary code similarity, scoped to what is deterministically implementable in Rust without a GPU | a literature snapshot; what we built from it is [`reference/function-identity-structural.md`](../reference/function-identity-structural.md) |
| [02-program-measures-foundations.md](program-measures-2026-09-02/02-program-measures-foundations.md) | 2026-09-02 | the mathematical foundations — distances, kernels, canonical forms, quotients — for "how far apart are two functions" | background for the ladder; no code depends on it directly |
| [03-signature-schemas-and-indexes.md](program-measures-2026-09-02/03-signature-schemas-and-indexes.md) | 2026-09-02 | signature schemas and similarity indexes, with each crate claim checked against the crates.io JSON API | crate versions drift; the shipped schema is the `function_structural` KB table |
| [04-program-representations-and-schemas.md](program-measures-2026-09-02/04-program-representations-and-schemas.md) | 2026-09-02 | per-function fact schemas and program representations across binary-analysis frameworks | a survey of other tools, not of ours |

The SQL sketch that accompanies them is
[`program-measures-2026-09-02/03-schema.sql`](program-measures-2026-09-02/03-schema.sql);
it is a proposal, not a migration that ran.

## `refactoring-portfolio-2026-08/`

A one-day planning exercise (2026-08-13) that produced a well-specified
seven-project portfolio and was then never referenced by a commit. The
underlying work is driven instead by `tools/fitness_report.py`,
`tools/fitness_baseline.json` and the file-size tests.

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [OUTCOMES.md](refactoring-portfolio-2026-08/OUTCOMES.md) | 2026-09-02 | each of the seven projects scored against the code at `13faa6f7`, with the then/now line counts | current as a scoring of a closed exercise; the boundaries themselves are restated live in [`architecture/module-boundaries.md`](../architecture/module-boundaries.md) |
| [README.md](refactoring-portfolio-2026-08/README.md) | 2026-08-13 | the seven-project portfolio and its repo-wide completion gate | orphaned: one inbound link in the repository, zero commits citing any project; its gate omits the four decompiler baselines and the six structural side-files |
| [architecture-review-2026-08-13.md](refactoring-portfolio-2026-08/architecture-review-2026-08-13.md) | 2026-08-13 | the file-concentration measurement at `fb4ee6ba` that the portfolio was built on | the only before-measurement of file concentration; without it the CFG 7,125 → 1,992 result is unprovable |
| [01-program-semantic-authority.md](refactoring-portfolio-2026-08/01-program-semantic-authority.md) | 2026-08-13 | one owner for images, symbols, types and provenance | **not started as specified**; `src/program/diagnostics.rs` does not exist, and the precedence-table goal was met on the Python side in `llm/kb/provenance.py` instead |
| [02-ir-decompiler-boundaries.md](refactoring-portfolio-2026-08/02-ir-decompiler-boundaries.md) | 2026-08-13 | the target pipeline — lifter → LLIR → SSA → verified typed MIR → recovery → HIR → pure renderer — and "rendered C is a view, never an input" | **partially executed, different shape**: of its target directories only `mir/` exists; orchestration is still `src/python_bindings/ir/pipeline.rs`, which the plan forbids |
| [03-cfg-discovery-decomposition.md](refactoring-portfolio-2026-08/03-cfg-discovery-decomposition.md) | 2026-08-13 | splitting CFG discovery from the graph model and its algorithms | **largely executed**: `cfg.rs` 7,125 → 1,992 with 19 submodules — under different module names than the plan proposed |
| [04-native-python-api-boundary.md](refactoring-portfolio-2026-08/04-native-python-api-boundary.md) | 2026-08-13 | thin PyO3 adapters over Rust application services | **partially executed**; `src/decompile/service.rs`, `src/analysis/service.rs`, `python/glaurung/api/` do not exist, and the "no pass sequencing in bindings" criterion is squarely violated |
| [05-windows-workflow-decomposition.md](refactoring-portfolio-2026-08/05-windows-workflow-decomposition.md) | 2026-08-13 | splitting the Windows CLI from fact extraction, rendering and validation | **not started**: both named files are byte-for-byte the same size as at review time. Its "deterministic fact packet is the contract shared by CLI and LLM tools" rule is worth keeping |
| [06-knowledge-base-boundaries.md](refactoring-portfolio-2026-08/06-knowledge-base-boundaries.md) | 2026-08-13 | explicit KB repositories, migrations and provenance rules | **not started; one file regressed** (`xref_db.py` grew). The migration gap it names is real and still unaddressed |
| [07-execution-symbolic-boundaries.md](refactoring-portfolio-2026-08/07-execution-symbolic-boundaries.md) | 2026-08-13 | separating interpreter mechanism from exploration and solver policy | **partially executed**: `explore/` and `solver/` exist, `explore.rs` 3,617 → 1,768; `src/exec/` is still ten flat files. Its feature-combination criterion is now met by `scripts/feature-build-gate.sh` |

## `sessions/`

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [2026-09-03-signature-libraries.md](sessions/2026-09-03-signature-libraries.md) | 2026-09-03 | the day the signature library went from a 16-signature demo to a published, signed database of 533,820 signatures on assets.glaurung.dev: what shipped, the per-cell coverage numbers, what broke, and what is open | a point-in-time record; the live state is in `reference/function-signature-libraries.md`, `reference/signature-sources.md` and `reference/signature-distribution.md` |
| [2026-04-26-tutorial-and-bug-L-verification.md](sessions/2026-04-26-tutorial-and-bug-L-verification.md) | 2026-04-26 | a tutorial and bug-verification session | internally consistent; the `out/` tree it describes is gitignored build output and is expected to be absent |

## `triage-2025/`

Four overlapping feature wishlists and one implementation checklist from the
2025 triage push. The live guide is [`guides/triage.md`](../guides/triage.md).

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [IMPLEMENTATION.md](triage-2025/IMPLEMENTATION.md) | 2025-08-31 | the triage implementation checklist | predates the current native pipeline; its feature-flag table still matches `Cargo.toml` |
| [ADDITIONAL_FEATURES.md](triage-2025/ADDITIONAL_FEATURES.md) | 2025-09-02 | proposals for overlay handling, Rich header, Authenticode, resources | overlay and Rich header shipped; Authenticode is still thin. Heavy overlap with the three files below |
| [ADVANCED-FEATURES.md](triage-2025/ADVANCED-FEATURES.md) | 2025-09-01 | "binary DNA" fingerprinting, clustering, control-flow proposals | duplicate coverage of the fuzzy-hashing and certificate topics |
| [DETAILED_IMPLEMENTATION_PLAN.md](triage-2025/DETAILED_IMPLEMENTATION_PLAN.md) | 2025-09-02 | step-by-step code sketches for overlay and Rich header | both shipped; the real implementations diverge from the sketches |
| [RECOMMENDATIONS.md](triage-2025/RECOMMENDATIONS.md) | 2025-09-02 | a prioritized list over the same feature set | duplicate coverage; the surviving unbuilt idea is the tiered signature design, kept live at [`design/signature-tiers.md`](../design/signature-tiers.md) |

## `windows-port-2026-05/`

The May-2026 Windows campaign. The live guide is
[`guides/windows-analysis.md`](../guides/windows-analysis.md) and the live
references are [`reference/windows-analysis-config.md`](../reference/windows-analysis-config.md)
and [`reference/windows-api-type-sync.md`](../reference/windows-api-type-sync.md).

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [roadmap.md](windows-port-2026-05/roadmap.md) | 2026-05-17 | the May-2026 Windows campaign checklist | its "the Windows-specific atomic tools remain future work" is false: 113 `windows_*.py` tool files exist |
| [agentic-ai-functionality-roadmap.md](windows-port-2026-05/agentic-ai-functionality-roadmap.md) | 2026-05-21 | the agentic Windows functionality roadmap plus its own completion audit | the completion audit at its tail is accurate and self-correcting; the roadmap body describes work that has since landed |
| [atomic-tools.md](windows-port-2026-05/atomic-tools.md) | 2026-05-21 | 15 named CVE-pattern detector tools and a bug-class taxonomy | **none of the 15 filenames exist**; a different tool family (composable fact/query tools) solved the same problem. The bug-class taxonomy is the durable part |
| [pdb-ingestion-design.md](windows-port-2026-05/pdb-ingestion-design.md) | 2026-05-17 | the PDB ingestion design | core ingestion shipped as `src/symbols/pdb.rs`; `pdb_types.rs` / `dwarf_types.rs` never materialised, its `pe.rs` line cite is stale, and its exit-signal CLI example uses a flag `symbols` does not have |
| [pe-hardening-design.md](windows-port-2026-05/pe-hardening-design.md) | 2026-05-16 | the PE directory-hardening design | the four named directory capabilities shipped |
| [bsim-similarity-design.md](windows-port-2026-05/bsim-similarity-design.md) | 2026-05-16 | a BSim-style function similarity design | partially implemented as `windows_function_similarity_manifest.py` |
| [co-investment-policy.md](windows-port-2026-05/co-investment-policy.md) | 2026-05-16 | the collaboration policy with the external agentic-security-bot repo | governs a relationship outside this repository and is unverifiable from here; unrelated to the DecBench upstream boundary |
| [glaurung-vs-ghidra-regression-review.md](windows-port-2026-05/glaurung-vs-ghidra-regression-review.md) | 2026-05-20 | a 10-fixture regression dashboard narrative, 2026-05-19 | a dated comparison snapshot |
| [glaurung-vs-ghidra-full-debug-review.md](windows-port-2026-05/glaurung-vs-ghidra-full-debug-review.md) | 2026-05-20 | a 30-fixture debug narrative, 2026-05-19 | as above |

## docs-rewrite-2026-09/

The plan and evidence for the September 2026 documentation rewrite that produced the current tree.

| file | date | what it recorded | superseded by / known-false claims |
|---|---|---|---|
| [plan.md](docs-rewrite-2026-09/plan.md) | 2026-09-02 | the eight-phase work order for the 2026-09 docs rewrite (audit findings, target tree, generators, phases, decisions) | executed 2026-09-02 on branch docs/rewrite-2026-09; the live tree is its outcome |
| [audit/00-brief.md](docs-rewrite-2026-09/audit/00-brief.md) | 2026-09-02 | the shared brief the nine audit agents worked from | — |
| [audit/01-claude-agents-readme.md](docs-rewrite-2026-09/audit/01-claude-agents-readme.md) | 2026-09-02 | claim-by-claim ledger of CLAUDE.md, AGENTS.md, README.md | the rewritten top-level files |
| [audit/02-code-ground-truth.md](docs-rewrite-2026-09/audit/02-code-ground-truth.md) | 2026-09-02 | the code as it was at b8884687: crate map, pipeline, package, CLI, LLM, env vars, gates, git themes | architecture/ and reference/ (generated) |
| [audit/03-design.md](docs-rewrite-2026-09/audit/03-design.md) | 2026-09-02 | per-file verdicts for docs/design/ (48 files) | history/design/, architecture/decompiler-pipeline.md |
| [audit/04-execution-engine-axeyum-misc.md](docs-rewrite-2026-09/audit/04-execution-engine-axeyum-misc.md) | 2026-09-02 | per-file verdicts for execution-engine, axeyum, research, benchmarks, IOC doc | architecture/execution-engine.md, solver-backends.md, decisions/ |
| [audit/05-analysis-architecture-refactoring.md](docs-rewrite-2026-09/audit/05-analysis-architecture-refactoring.md) | 2026-09-02 | per-file verdicts for analysis/, architecture/, refactoring/ | architecture/, history/refactoring-portfolio-2026-08/OUTCOMES.md |
| [audit/06-parsers-formats-syscalls-triage.md](docs-rewrite-2026-09/audit/06-parsers-formats-syscalls-triage.md) | 2026-09-02 | per-file verdicts for parsers, formats, syscalls, triage | guides/, reference/formats/, reference/syscalls/ |
| [audit/07-development-cli-campaigns-demos.md](docs-rewrite-2026-09/audit/07-development-cli-campaigns-demos.md) | 2026-09-02 | per-file verdicts for development, test-inventory, cli, campaigns, sessions, demos | development/, guides/ |
| [audit/08-windows-llm-agentic.md](docs-rewrite-2026-09/audit/08-windows-llm-agentic.md) | 2026-09-02 | per-file verdicts for windows-port, llm, agentic-glaurung | guides/windows-analysis.md, architecture/{windows-port,llm-subsystem}.md, design/agentic-source-recovery/ |
| [audit/09-tutorial.md](docs-rewrite-2026-09/audit/09-tutorial.md) | 2026-09-02 | per-chapter verdicts and the verifier mechanism | tutorial/ fixes; development/contributing-docs.md |
| [audit/EXECUTION-BRIEF.md](docs-rewrite-2026-09/audit/EXECUTION-BRIEF.md) | 2026-09-02 | ground rules and the seven decisions the executing agents worked under | — |
| [audit/MOVE-MANIFEST.md](docs-rewrite-2026-09/audit/MOVE-MANIFEST.md) | 2026-09-02 | the old→new path for every file moved in Phase 2 | — |
| [audit/contract-assertions.md](docs-rewrite-2026-09/audit/contract-assertions.md) | 2026-09-02 | behavioral doc contracts rescued from the deleted classification tests | python/tests/test_docs_contracts.py |
