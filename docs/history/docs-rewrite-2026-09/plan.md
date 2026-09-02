# Documentation rewrite plan

> **Kind:** record · **Date:** 2026-09-02
> Evidence: nine per-file audit ledgers in [`audit/`](audit/),
> produced against `master` @ `b8884687` by reading code and git, not other docs.
> This file is the work order. The ledgers are the per-file verdicts. Both move to
> `docs/history/docs-rewrite-2026-09/` when the last phase closes.

## 0. Summary

`docs/` holds 311 markdown files (103,055 lines) plus about 900 non-markdown
files. Roughly 85% of the prose is dated engineering record: session diaries,
superseded plans, defect registers, and AI-roundtable proposals. The live
guidance is thin, scattered across 23 top-level directories that each mix
guide, reference, design, and record, and in several places wrong.

The three top-level files have the opposite problem. `README.md` is accurate
but has an install-blocking omission. `CLAUDE.md` is accurate on hard facts and
has become a 24 KB incident log with three false paths and contradictory
bullets. `AGENTS.md` is 70% generic boilerplate.

The plan:

1. **Move data and scripts out of `docs/`** and rewrite the one test file that
   pins a hundred doc paths and banner strings, so the tree can change at all.
2. **Reorganize by document kind**, not by subsystem: `tutorial/`, `guides/`,
   `reference/`, `architecture/`, `decisions/`, `design/`, `development/`,
   `history/`. About one third of today's files stay live; the rest move to a
   dated, indexed `history/` or are deleted.
3. **Rewrite from source, not from old docs**, using the ground-truth map in
   ledger 02. Generate what can be generated (CLI surface, env vars, cargo
   features, provenance ladder, pass list) and test the generated tables.
4. **Rewrite `CLAUDE.md` to ~130 lines of rules and commands**, turn
   `AGENTS.md` into a ~20-line pointer, and patch `README.md`.

Eight phases, each with an acceptance gate. Phases 1 and 2 are code and
mechanical moves; phases 3 to 7 are writing, parallelizable across agents.

---

## 1. What the audit found

### 1.1 Verified falsehoods in live guidance

Each row was checked against code or git by the ledger named in the last
column. These are the defects a reader following current docs will hit.

| # | Where | Claim | Truth | Ledger |
|---|---|---|---|---|
| 1 | `CLAUDE.md` | KB lives at `python/glaurung/kb/` | `python/glaurung/llm/kb/` (27 modules, 14,835 LOC) | 01, 02, 05 |
| 2 | `CLAUDE.md`, `.claude/agents/rust-data-model-creator.md` (6×) | patterns in `docs/data-model/` | `docs/architecture/data-model/` | 01, 05 |
| 3 | `CLAUDE.md` | `GLAURUNG_AGENT_ROUTE=1` enables routing | var exists nowhere in code; only `--route` is real | 01, 08 |
| 4 | `CLAUDE.md` | CI runs "the full Python suite" and `ty` | python job is `-m "not fixtures and not decbench"`; `ty` runs in no workflow; an undocumented `cargo test --features symbolic` job exists | 01 |
| 5 | `CLAUDE.md` | fixture baselines "gate nothing"; perf gate "fails open" | `decompiler-fixtures.yml` gates `baseline.json` + `structural_baseline.json`; perf gate exits 3 on non-evidence since `4f4f88e3` | 01 |
| 6 | `CLAUDE.md` | ~345 Python test files, ~125 Rust test modules | 461 and 276 (+25 in `tests/`) | 01 |
| 7 | `CLAUDE.md` | "a split has four side files" and, 80 lines later, "six" | six | 01 |
| 8 | `README.md`, `setup.md`, `project-structure.md` | CPython 3.11+ | `requires-python = ">=3.12"`; pyproject's own 3.11 classifier is also stale | 01, 07 |
| 9 | `README.md`, `setup.md` | clone and run the smoke test | sample is a Git LFS pointer on a fresh clone; neither file mentions LFS | 01 |
| 10 | `README.md` | `cargo test` as the dev check | must be `cargo test --features python-ext` | 01 |
| 11 | `docs/analysis/decompiler/README.md` (linked as THE decompiler doc) | `glaurung::decompiler::Decompiler`, `glaurung.Decompiler(engine="ghidra")`, `--engine/--ai-enhance/-o` flags, 87%/94% benchmarks | none exist; ~470 of 583 lines are a 2025 competitor survey | 05 |
| 12 | `docs/analysis/decompiler/pipeline.md` | 21 passes, x86 + AArch64 | 57 `src/ir` modules driven from the bindings, 20 `pass!` groups plus a second ~30-step decbench chain; 3 lifters incl. ARM32 | 02, 05 |
| 13 | `docs/design/execution-engine/README.md`, `STATUS.md` | "No code yet" / "`src/exec/`, `src/symbolic/` do not exist" | created by the same commit; now 3,591 + 21,459 LOC | 04 |
| 14 | `docs/axeyum-integration/README.md` | "Current source gate: failing" (E0004) | fixed 2026-08-17 in `114a5c4c`; **a test asserts the stale string** (`test_verify_tutorial.py:402`) | 04 |
| 15 | `tutorial/reference/set-by-precedence.md`, `tutorial/PLAN.md`, `CLAUDE.md`, `IDA_GHIDRA_PARITY.md` | four different provenance ladders | `provenance.py`: manual 100 > dwarf=pdb=gopclntab 80 > stdlib 60 > flirt=cil 50 > ported 40 > propagated 30 > auto=analyzer=borrowed 20 | 09, 05, 02 |
| 16 | `tutorial/reference/cli-cheatsheet.md` | 36 commands | 40; `rename/comment/label/proto` added 2026-08-28 | 09 |
| 17 | `docs/design/decompiler-roadmap.md` | 314 files / 166,455 LOC / `ir/ast.rs` 11,628 / 2 of 7 targets | 455 / 185,318 / 1,711 / 6 of 9; baseline is 399 commits behind HEAD | 03 |
| 18 | `docs/design/README.md` | `decompiler-roadmap.md` is "the single tracker" | the newest diary redirects to `development/real-binary-decompiler-roadmap-2026-08-31.md` | 03 |
| 19 | `docs/design/decbench-submission-readiness.md` | "no upstream PR, issue, or submission" | roadmap Appendix A records PRs #56/#61/#62 merged | 03 |
| 20 | `docs/windows-port/README.md` status table | atomic tools "not started" | 113 `windows_*.py` tool files exist | 08 |
| 21 | `docs/llm/ROADMAP.md` | "Atomic tools (22)" | ~239 tool files | 08 |
| 22 | `docs/test-inventory/coverage.md` vs `index.json` | 986 entries / 89 unreachable | 984 / 74, different commit stamps, live drift | 07 |
| 23 | `docs/design/roundtrip/gcc-O0.md` | 9 of 25 correct (36%) | 24 of 26 (92%) per a later doc | 04 |
| 24 | `docs/benchmarks/baseline.json` | a baseline | 4 months old; no code, test, or workflow reads it | 04 |
| 25 | `docs/development/decompiler-testing.md` | `@exceptions` set | not in `sets.toml` | 07 |
| 26 | `docs/parsers/archive/README.md`, `macho/README.md` | spec file paths | `archive.h` absent; `golang_macho.go` is under `elf/` | 06 |
| 27 | `tutorial/03-walkthroughs/05-vulnerable-parser.md` | `disasm --function parse_record` | silently ignored without `--db` | 09 |
| 28 | ADR-0006, `symbolic-engine.md` | concolic default with taint gating and directed search | `Symbolic::Val = ExprId`, DFS, no concrete shadow | 04 |
| 29 | `docs/README.md` | index of `docs/` | does not list `design/execution-engine/`, `benchmarks/`, `IOC_VALIDATOR_V2.md` | 04 |
| 30 | `python/glaurung/cli/commands/repl.py` | "51 tools available" | 219 registered (the `memory_agent.py` docstring's "~163" is itself stale); the tutorial fixture faithfully captures the wrong number | 09, 02 |
| 31 | `CLAUDE.md` "Active frontier" | Windows port, `ioctl_taint`, `windows-risk`, L1–L5 routing | git says otherwise: 221 of 245 Windows commits, 129 of 143 LLM-routing commits and 84 of 86 Java commits landed in May 2026; symbolic work stopped 2026-08-19. The live frontier since July is decompiler correctness (~460 + 103 + 142 commits), the test estate, DecBench scoring and performance | 02 §9 |
| 32 | `CLAUDE.md` crate map | lists `triage, formats, disasm, …` | omits `exec`, `symbolic`, `program`, `unpack`, `flirt`; `src/io/` and `src/hashing/` are tracked but declared in no build; `triage-core`, `triage-heuristics`, `triage-containers` gate nothing | 02 §1 |
| 33 | `llm/tool_routing.py` intents | 15 tool names per intent | ~7 survive; `_apply_tool_filter` drops unmatched names silently | 02 §5 |

### 1.2 Systemic patterns

- **Narrative accretes in place.** `CLAUDE.md` gained 19 of its 25 commits in
  four months with subjects like "three traps that cost a day". Nine of its
  fourteen war-story bullets are now enforced by a test or workflow and could
  be a pointer. Design directories show the same pattern: six documents each
  restate the "typed SSA/MIR spine" thesis; eight cover DecBench evaluation.
- **Status tables lag code.** The Windows README, the LLM roadmap, the
  execution-engine STATUS, the refactoring portfolio, and the test-estate
  phase files all present landed work as open or open work as landed.
- **Tests pin transient facts.** `test_verify_tutorial.py` asserts
  `"Current source gate: failing"`, `"Refresh audit: 2026-08-07"`, and two
  commit SHAs in doc prose. The suite currently requires a doc to be wrong.
- **Five copies of one ladder.** The provenance ranking appears in five places
  and is right in one (the code).
- **Filename dates are not currency.** 24 of 48 `docs/design/` names carry a
  date; the undated `ioctl-taint.md` is accurate and the undated
  `decbench-submission-readiness.md` is wrong.
- **Data lives in `docs/`.** 842 `.smt2` files, a Python script four Rust
  tests execute, a benchmark harness, and four JSON baselines that are runtime
  defaults for the Windows CLI and eleven LLM tool modules.
- **The tree grew 46% under a note that stood still**, and the mass banner
  pass of 2026-08-07 (`0ec35a2e`, 283 files) made most files honest about
  being old without making any of them current.

### 1.3 What is good and must be preserved

- **The tutorial and its verifier.** 24 fixture directories, 157 `.out`
  files, exactly one recipe per chapter in `scripts/verify_tutorial.py`, and
  fixtures that move only when the CLI genuinely changes. 21 of 26 chapters
  had zero findings. This is the backbone of the user-facing docs.
- **Docs that verified clean, claim by claim:** `docs/README.md` (37 links),
  `analysis/disassembly/README.md`, `analysis/language-detection/README.md`,
  `triage/{README,packer-config,similarity}.md`, `cli/*` (3), `formats/*` (4),
  `syscalls/*` (3), `windows-port/{windows-analysis-config,windows-api-type-sync}.md`,
  `architecture/PERSISTENT_PROJECT.md`, `development/{setup,decompiler-testing,guidelines,decompiler-parity-backlog}.md`,
  `test-estate/EXECUTION.md`, `IOC_VALIDATOR_V2.md`, `parsers/{README,java/README}.md`,
  and all 20 files of `agentic-glaurung/`.
- **The self-correction norm.** Several documents retract themselves in
  writing. `docs/design/README.md`'s closing rule, "a number in a document is
  not a measurement; write the command next to the number", belongs in the new
  `CLAUDE.md`.
- **Records with knowledge that exists nowhere else.** Appendix B lists them
  with a destination each. None may be deleted before its content is absorbed.

---

## 2. Hard constraints

Anything below breaks if a file moves without a matching code change. Phase 1
exists to clear this list.

### 2.1 Code, tests, and CI that read `docs/` at runtime

| Path under `docs/` | Consumers | Action |
|---|---|---|
| `windows-port/glaurung_vs_ghidra_vendor_windows_30_{after_tiny_stub_gate,diagnostics}.json`, `…_windows.json`, `…_windows_30.json` | `cli/commands/windows.py` (3 argparse defaults), 11 modules under `llm/{agents,tools}/windows_*`, ~17 tests, `.github/workflows/windows-ghidra-parity-refresh.yml` | move to `data/baselines/windows-ghidra-parity/`; introduce one constants module so the path is defined once |
| `axeyum-integration/capture/validate_ordered_trace.py` | `src/symbolic/ordered_trace.rs:1539,1767,1868,1938` (test sites) | move to `tools/axeyum/`; update the four `.join(...)` calls; run `cargo test --features symbolic` |
| `axeyum-integration/capture/{build_corpus,lineage_gate,shard_corpus,validate_shadow_splits}.py` + 4 `test_*.py` | nothing runs them (`testpaths = python/tests`) | move scripts to `tools/axeyum/`, tests to `python/tests/test_axeyum_*.py` so they run |
| `axeyum-integration/capture/shadow-splits/**/*.smt2` (842), `lineage-*.json` (14), `*.tsv` (4) | `capture/README.md` procedure | move to `tests/corpora/axeyum-qfbv/` (decision D1 below) |
| `axeyum-integration/benchmark/run_benchmark.sh` + `results/` | manual | move to `bench/axeyum/` |
| `tutorial/_fixtures/**` | `scripts/verify_tutorial.py`, `test_verify_tutorial.py` | do not move; do not hand-edit |
| `test-inventory/{index.json,index.yaml,unreachable.json}` | `tools/build_test_inventory.py` output; `test_estate_reachability.py` | keep in place; the generator's inputs are not committed (ledger 07) |

### 2.2 Tests that assert on doc content

`python/tests/test_verify_tutorial.py` lines 106–520 contain 15 tests that
read ~100 specific files under `docs/` and assert literal strings: banner text
in the first 600–700 bytes, specific phrases, and in three cases transient
facts (a failing-gate sentence, a refresh date, two SHAs). Every move or
rewrite in this plan touches this file. Phase 1 replaces the eleven
classification tests with a manifest-driven test; the four behavioral tests
(tier-5 CLI contract, `ask` reference, demos, examples) stay and get new paths.

Other tests cite docs only in docstrings or assertion messages and do not
break on a move, but the message text should follow the file:
`test_loop_hoist_traps.py:171` (`design/ged-recovery-measured-trade.md`),
`test_fitness_report.py`, `test_large_module_review.py`,
`test_src_dependency_boundaries.py` and `tools/fitness_report.py:3` (all cite
`design/decompiler-roadmap.md` by section name), `test_estate_reachability.py`
and four others (`test-estate/01-reachability.md`), `pytest.ini:10`,
`fuzz-nightly.yml:18`.

### 2.3 Source comments that cite design docs by path

`src/exec/{interp,memory,helpers,domain,budget}.rs`, `src/symbolic/{mod,expr,explore}.rs`,
`src/ir/{verify,types,structure}.rs`, `src/lib.rs:74,79`, `src/analysis/cfg.rs:791`,
`python/glaurung/llm/kb/{function_identity,xref_db,persistent,provenance}.py`,
`tools/{compare_decompilers,fixture_harness,decbench_redecompile_tree}.py`.
A link-rewrite pass over `src/`, `python/`, `tools/`, `scripts/`, `.github/`
is part of Phase 2, followed by the link checker.

### 2.4 Policy constraints

- The DecBench upstream boundary in `CLAUDE.md` is unchanged and is the one
  section of that file that must not be shortened. Nothing in this plan touches
  DecBench upstream, runs DecBench, or spawns Joern.
- Nothing may write to `/tmp`. Two things currently do and get fixed in
  Phase 1: `scripts/verify_tutorial.py:43` (`TMP = Path("/tmp/tutorial-fixtures")`)
  and the examples in `tutorial/02-daily-basics/patch-and-verify.md` and
  `architecture/PERSISTENT_PROJECT.md`.
- Adding or renaming a CLI command drifts `tutorial/_fixtures/01-install/help-head.out`.
  This plan adds no commands, so the fixture is untouched.

---

## 3. Principles for the rewritten tree

1. **Source of truth is code and git.** Every live document names the code it
   describes. When two documents disagree the fix is deletion, not a third.
2. **One kind per document, declared in line 3.** Every file under `docs/`
   except `history/` and `tutorial/_fixtures/` opens with
   `> **Kind:** guide | reference | architecture | decision | design | plan`
   and `**Status:** maintained | generated | proposed`. `history/` files carry
   `**Kind:** record` and a date. A test enforces the vocabulary (Phase 1),
   replacing the per-file string pins.
3. **Generate the tables that drift.** CLI surface from `cli/main.py`'s
   `_REGISTRY`, env vars from a grep over `python/`, `src/`, `tools/`, `scripts/`,
   cargo features from `Cargo.toml`, the provenance ladder from
   `provenance.py`, the AST pass list from `pipeline.rs`. Each generator has a
   `--check` mode and a test, the way `gen_native_stub.py` already does.
4. **Write the command next to the number.** A count or percentage in a live
   document is accompanied by the command that produced it and the commit it
   was run at, or it is removed.
5. **Live documents carry no dated narrative.** An incident becomes one
   durable rule in the live doc and one dated entry in `history/` or
   `development/traps.md`. Corrections to a document happen in the document,
   not as appended "Correction, 2026-08-31" paragraphs.
6. **One authority per fact.** Provenance ladder: `reference/provenance.md`.
   Live roadmap: `development/roadmap/README.md`. Cargo features:
   `reference/cargo-features.md`. Everything else links there.
7. **No dates in live filenames.** `history/` is organized by date and topic.
8. **No data or executable scripts under `docs/`.** Fixtures for the tutorial
   verifier are the one exception, because they are review evidence for the
   prose beside them.
9. **Archive, do not delete, when in doubt.** Deletion is reserved for
   regenerable dumps and documents whose every fact is stale and which nothing
   links (Appendix C lists the nine).
10. **Status banner tests assert classification, never facts.** A test may
    require that a file declares a kind. It may not require that the file
    says a build is failing.

---

## 4. Target structure

Legend: **new** = written from source; **rewrite of** = same subject, new
text; **move** = content kept, path changed; **merge of** = several sources,
one output; **gen** = produced by a tool with a `--check` test.

```
docs/
├── README.md                          rewrite of docs/README.md — same "find a workflow"
│                                      shape; every top-level directory indexed
│
├── tutorial/                          KEEP layout and all 24 fixture dirs
│   ├── README.md                      keep
│   ├── 01-getting-started/            keep; cli-tour.md gains a scriptable-annotation section
│   ├── 02-daily-basics/               keep; patch-and-verify.md → $TMPDIR paths;
│   │                                  strings-and-data.md citation fix
│   ├── 03-walkthroughs/               keep; 05-vulnerable-parser.md --db fix
│   ├── 04-recipes/                    keep; exporting adds header/bundle formats
│   ├── 05-agent-workflows/            keep
│   └── _fixtures/                     keep, never hand-edit
│   (tutorial/PLAN.md → history/tutorial-plan-2026-04.md; tutorial/reference/* → docs/reference/)
│
├── guides/                            task-oriented, not in the tutorial track
│   ├── triage.md                      move of triage/README.md
│   ├── analyst-workflows.md           move of cli/analyst-ergonomics.md
│   ├── annotation-loop.md             move of cli/analyst-annotation-loop.md
│   ├── ask.md                         move of cli/ASK_COMMAND.md
│   ├── windows-analysis.md            rewrite of windows-port/README.md — capability index
│   │                                  with the corrected tools row; links to reference/
│   ├── java-jvm.md                     move of parsers/java/README.md (the living ledger)
│   ├── parsers-and-formats.md          move of parsers/README.md (the accurate index)
│   └── demos/                          move of demos/ (4 files, link the same fixtures)
│
├── reference/                         fact tables; generated where marked
│   ├── cli.md                         gen from cli/main.py _REGISTRY + per-command help
│   │                                  (replaces tutorial/reference/cli-cheatsheet.md;
│   │                                  closes tutorial/PLAN.md §AA's open gap)
│   ├── environment-variables.md       gen — the 18 GLAURUNG_* Python vars, the Rust/solver
│   │                                  vars (GLAURUNG_SHADOW_DIFF, _DUMP_QUERIES,
│   │                                  _CONCRETIZATION_POLICY, …), fixture/CI vars, ASB_REPO
│   ├── cargo-features.md              gen from Cargo.toml [features] + src/lib.rs cfg lines,
│   │                                  with the "what each build actually compiles" table
│   ├── provenance.md                  gen from llm/kb/provenance.py SET_BY_PRIORITY;
│   │                                  prose from IDA_GHIDRA_PARITY.md's essay (the ONE ladder)
│   ├── decompiler-passes.md           gen from python_bindings/ir/pipeline.rs pass! names
│   │                                  + decbench_render.rs refine chain
│   ├── decompiler-output-format.md    merge of analysis/decompiler/README.md §JSON schema + CLI ¶
│   ├── disassembly.md                 move of analysis/disassembly/README.md (verified clean)
│   ├── language-detection.md          move of analysis/language-detection/README.md
│   ├── packer-config.md               move of triage/packer-config.md
│   ├── similarity.md                  move of triage/similarity.md
│   ├── windows-analysis-config.md     move
│   ├── windows-api-type-sync.md       move
│   ├── ioc-validator.md               move of IOC_VALIDATOR_V2.md + one V1 status line
│   ├── repl-keymap.md                 move of tutorial/reference/repl-keymap.md + cross-link
│   ├── sample-corpus.md               move of tutorial/reference/sample-corpus.md
│   ├── formats/                       move of formats/ (4 files, verified clean)
│   └── syscalls/                      move of syscalls/ (3 files, verified clean)
│
├── architecture/                      how the code is built, written from source
│   ├── README.md                      new — one page: crate, package, data flow, where the
│   │                                  entry points are (from ledger 02 §1–§4)
│   ├── rust-crate-map.md              new — per-directory purpose/LOC/feature (ledger 02 §1),
│   │                                  incl. dead dirs src/io, src/hashing
│   ├── python-package-map.md          new — ledger 02 §3 incl. the .glaurung 35-table schema
│   ├── decompiler-pipeline.md         new — merge of decompiler-roadmap.md §target architecture
│   │                                  + non-negotiable rules, decompiler-middle-architecture §2/§4,
│   │                                  glaurung-architecture-redesign-2026-08-05 §§1–9,
│   │                                  semantics-preserving-structuring §3/§5,
│   │                                  value-model-root-cause §0/§1, typed-ssa-hlir §2/§3,
│   │                                  refactoring/02's target diagram; STATE what is built
│   │                                  (ledger 02 §2) vs. not (hir/, FunctionFacts, MIR consumer)
│   ├── register-model.md              rewrite of design/register-views-and-the-verifier-boundary.md
│   ├── x86-flags.md                   rewrite of design/x86-flags.md (past tense for pre-fix stats)
│   ├── persistent-project.md          move of architecture/PERSISTENT_PROJECT.md ($TMPDIR fix)
│   ├── data-model.md                  rewrite of architecture/data-model/README.md + src/program/
│   ├── module-boundaries.md           merge of refactoring/01..07 target designs, stated as
│   │                                  boundaries to hold, with the P1–P7 scoreboard
│   ├── execution-engine.md            new — src/exec + src/symbolic as built (ledger 04 §ground truth)
│   ├── solver-backends.md             rewrite of axeyum-integration/{README,02,06,08,09} prose
│   ├── ioctl-taint.md                 move of design/ioctl-taint.md
│   ├── llm-subsystem.md               new — agents, tools (~239 files, ~163 exposed), kb,
│   │                                  L1–L5 routing and F1–F7 guards named and explained
│   ├── windows-port.md                merge of windows-port/{atomic-tools,pdb-ingestion,
│   │                                  pe-hardening,bsim}-design.md — capability origins,
│   │                                  stale line cites removed
│   └── competitive-position.md        move of design/decompiler-ux-competitive-ranking.md
│
├── decisions/                         ADRs; rejected alternatives are not recoverable from code
│   ├── README.md                      new — index with status column (held / superseded / never built)
│   ├── exec-0001-single-domain-core.md            keep (fix `type Mem` line)
│   ├── exec-0002-harden-llir-in-place.md          keep (renamed; ends the ADR-002 collision)
│   ├── exec-0003-interpreter-not-jit.md           keep (note: lift cache never built)
│   ├── exec-0004-symbolic-memory.md               rewrite — the shipped ConcretizationPolicy seam
│   ├── exec-0005-native-solver-first.md           rewrite — renamed; add the axeyum outcome
│   ├── exec-0006-execution-mode.md                rewrite — DFS + folding + solver pruning, as built
│   ├── solver-001 … solver-031.md                 split of axeyum-integration/07-decision-log.md
│   └── whole-binary-serialization.md              move of design/whole-binary-serialization-2026-08-20.md
│
├── design/                            LIVE proposals for things not built
│   ├── README.md                      new — what is here and why it is not architecture/
│   ├── function-facts-and-call-facts.md   move (still literally unimplemented)
│   ├── open-questions.md              merge of stack-bias-affine-index, dormant-transforms
│   │                                  "retire or repoint", goto-density "what would have to
│   │                                  change", decbench-defect-reproductions §7, refactoring/06
│   │                                  migration gap — each with the experiment that decides it
│   ├── execution-engine-research/     move of design/execution-engine/01-research/ (4 files;
│   │                                  smt-backends.md rewritten with real crate versions)
│   ├── signature-tiers.md             move of triage/SIGNATURE_DESIGN.md (coherent, unbuilt)
│   └── agentic-source-recovery/       move of agentic-glaurung/ (20 files, all verified; optional, D3)
│
├── development/                       contributor-facing
│   ├── setup.md                       revise — 3.12, git lfs, +3 env vars, LFS note
│   ├── project-structure.md           revise — 3.12; or fold into architecture/README.md
│   ├── guidelines.md                  keep
│   ├── testing-gates.md               new — the "which gate runs where" table (from ledger 01
│   │                                  §5.1): command | protects | in CI? for all nine gates;
│   │                                  absorbs the fitness/file-size program section that
│   │                                  tools/fitness_report.py and three tests cite
│   ├── decompiler-testing.md          revise — @exceptions example; absorb fixture-expansion §0
│   ├── traps.md                       new — every dated narrative extracted from CLAUDE.md,
│   │                                  one section per trap: rule first, then incident + commit
│   ├── contributing-docs.md           new — the kind/status vocabulary, the generators, how
│   │                                  verify_tutorial.py works (CHAPTERS dict, --capture,
│   │                                  fixtures), the link checker, "command next to the number"
│   ├── decompiler-parity-backlog.md   keep (live)
│   ├── decompiler-curriculum-corpus.md revise — Go lanes are opt-in now
│   ├── roadmap/                       the ONE live plan set (undated filenames)
│   │   ├── README.md                  move of decompiler-roadmap-package-2026-08-31.md
│   │   ├── real-binary-decompiler.md  move of real-binary-decompiler-roadmap-2026-08-31.md
│   │   │                              (+ the still-open items of design/decompiler-roadmap.md)
│   │   ├── decbench-failure-remediation.md, large-functions.md, optimized-structural-quality.md,
│   │   │   pe-pdb-macho-parity.md (+test-estate/04), performance-determinism-ratchet.md
│   │   │   (+test-estate/06, P9 landed), real-world-malware-assets.md, test-inventory-authority.md
│   │   └── (each: move, date dropped, progress section current)
│   ├── test-estate/                   keep; README gains done/open markers; 01/02/09 → history
│   ├── test-inventory/                keep generated set; coverage.md regenerated or banner'd
│   └── decompiler-open-questions → see design/open-questions.md
│
└── history/                           read-only, dated, indexed; never linked as guidance
    ├── README.md                      new — one line per file: date, what it recorded, what
    │                                  superseded it, which claims are now known false
    ├── design/                        ~36 files from docs/design/ (diaries/, plans-superseded/,
    │                                  campaigns/, repo-operations/) — see ledger 03 §Proposed
    ├── execution-engine-2026-06/      STATUS, PLAN, 03-phases/*, the unbuilt 02-architecture/*
    ├── axeyum-integration-2026-07/    00, 01, 03, 04, 05, FEEDBACK-LOG, PAPER-NOTES, REVIEWER-CHECKLIST
    ├── decompiler-checkpoints-2026-07/ analysis/decompiler/2026-* (8) + the two diaries
    ├── data-model-2025/               proposals/, critique/, IMPLEMENTATION, nesting, foundations
    ├── refactoring-portfolio-2026-08/ all 10 files + new OUTCOMES.md (P3 done, P2/P4/P7 partial,
    │                                  P1/P5/P6 not started)
    ├── parsers-2025/                  18 elf/pe/macho/android/archive/dotnet/python/wasm docs
    ├── triage-2025/                   IMPLEMENTATION + one merged roadmap-2025.md (from 4)
    ├── analysis-surveys-2025/         lifting/, symbols/, interpreted/, language-detection records
    ├── windows-port-2026-05/          roadmap, agentic-ai-functionality-roadmap, two ghidra
    │                                  reviews, co-investment-policy (+banner), 3 generated .md tables
    ├── llm/                           ROADMAP (tables refreshed once, then frozen),
    │                                  AGENT_ITERATION+ITERATION_SUMMARY merged, REFACTOR_GUIDE,
    │                                  RE_TOOLS_OVERVIEW, FEATURES-001
    ├── architecture-reviews/          2026-07-13 review, IDA_GHIDRA_PARITY capability half
    ├── campaigns/                     move of campaigns/ (4, accurate, unique)
    ├── sessions/                      move of sessions/ (1)
    ├── development/                   roadmap.md, decompiler-test-strategy.md, 2026-07-27 handoff,
    │                                  test-estate/{01,02,09}
    ├── tutorial-plan-2026-04.md       tutorial/PLAN.md
    ├── pyext-separation-2024-12.md    research/pyext-separation.md (cfg_attr gotcha lifted to traps.md)
    └── docs-rewrite-2026-09/          this plan + the nine ledgers, when done

OUT OF docs/:
  data/baselines/windows-ghidra-parity/*.json       4 files, 11 product modules + 17 tests + 1 workflow re-pointed
  tools/axeyum/{validate_ordered_trace,build_corpus,lineage_gate,shard_corpus,validate_shadow_splits}.py
  python/tests/test_axeyum_{build_corpus,lineage_gate,shard_corpus,validate_shadow_splits}.py
  tests/corpora/axeyum-qfbv/                         842 .smt2 + 4 .tsv + 14 lineage json + excluded-hashes
  bench/axeyum/{run_benchmark.sh,results/}

DELETED (regenerable, wrong, and unlinked):
  docs/design/roundtrip/gcc-O0.md                    generated dump, headline 2.5× wrong
  docs/benchmarks/{baseline.md,baseline.json}        orphan, no reader
  docs/design/decompiler-next-implementation-directive.md
  docs/design/review-findings-cf-closure.md          line cites dead since the ir.rs split
  docs/design/review-findings-width-effect.md        one claim now false, cites dead
  docs/architecture/data-model/proposals/GROK4.md    weakest of four parallel proposals
  ~470 lines of docs/analysis/decompiler/README.md   competitor survey, invented APIs and benchmarks
```

### 4.1 Disposition by current directory

| Current directory | Files | Keep/move live | Rewrite/merge | → history | Delete | Move out of docs |
|---|---:|---:|---:|---:|---:|---:|
| `design/` (top) | 48 | 7 | 8 sources → 3 | 33 | 3 | — |
| `design/execution-engine/` | 38 | 8 | 6 | 24 | — | — |
| `design/roundtrip/` | 1 | — | — | — | 1 | — |
| `axeyum-integration/` | 16 md + 894 | 5 | 5 → 1 | 8 | — | 894 |
| `research/`, `benchmarks/`, `IOC_VALIDATOR_V2.md` | 4 | 1 | — | 1 | 2 | — |
| `parsers/` | 21 | 3 | — | 18 | — | — |
| `formats/`, `syscalls/` | 7 | 7 | — | — | — | — |
| `triage/` | 9 | 3 | 4 → 1 | 2 | — | — |
| `analysis/` | 22 | 2 | 1 → 3 | 17 | — | — |
| `architecture/` | 14 | 2 | 2 | 9 | 1 | — |
| `refactoring/` | 10 | — | 7 → 1 | 10 (+1 new) | — | — |
| `development/` + `test-estate/` | 30 | 16 | 10 | 5 | — | — |
| `test-inventory/` | 4 md + 3 | 7 | — | — | — | — |
| `cli/`, `demos/` | 7 | 7 | — | — | — | — |
| `campaigns/`, `sessions/` | 5 | — | — | 5 | — | — |
| `windows-port/` | 15 md + 4 json | 2 | 5 → 2 | 8 | — | 4 |
| `llm/` | 10 | 2 | 2 (+1 new) | 6 → 5 | — | — |
| `agentic-glaurung/` | 20 | 20 | — | — | — | — |
| `tutorial/` | 32 md + fixtures | 26 | 6 revise | 1 | — | — |
| **Total** | **311** | **~118** | **~35 outputs** | **~150** | **8** | **898** |

Live tree after the rewrite: roughly 120 markdown files, of which about 20 are
new from source and 6 are generated.

---

## 5. The three top-level files

### 5.1 `CLAUDE.md` → ~130 lines

Principle: rules and commands here, evidence in `docs/development/`. A rule an
automated gate enforces shrinks to naming the gate. A rule whose narrative is
longer than the rule moves to `traps.md` with a one-line pointer.

```
# CLAUDE.md — Glaurung
## What Glaurung is                    ~10 lines; fix kb path → python/glaurung/llm/kb
## DecBench upstream boundary          verbatim from today; the one section not to shorten;
                                       AGENTS.md links here instead of restating
## Commands                            today's fenced block minus stale counts and runtimes;
                                       export TMPDIR first; cargo test --features python-ext
                                       marked as THE test command; the coverage command rescued
                                       from AGENTS.md; all ten benches named
## Gates, and which ones CI runs       a nine-row table (see development/testing-gates.md)
                                       replacing nine prose bullets: python-ext tests, symbolic
                                       tests, pytest (-m "not fixtures and not decbench" in CI),
                                       ruff, ty (developer-only), feature-build-gate (12 lanes),
                                       dectest --arch (NOT in CI), defuse census (NOT in CI),
                                       fixture matrix + structural (CI)
## Conventions                         ruff/ty only; Rust Result/?/docs/unsafe; naming; never
                                       hand-write a .pyi; absorbs AGENTS.md's style sections
## Working style                       TDD; real fixtures only; surface failures; never run
                                       DecBench/Joern unless asked; a split touches SIX side
                                       files (named); adding a CLI command drifts the install
                                       fixture (refresh command named); measure against
                                       --release; git diff/apply not stash; rustfmt <file> not
                                       cargo fmt -- <file>; "write the command next to the number"
## LLM model policy                    today's section minus GLAURUNG_AGENT_ROUTE
## Pointers                            docs/README.md, development/{traps,testing-gates,
                                       decompiler-testing,contributing-docs}.md,
                                       development/roadmap/README.md, .claude/agents/…
```

Corrections to make while rewriting, all verified in ledgers 01 and 02: the
two false paths; the "active frontier" line rewritten from ledger 02 §9 (or
dropped, since it dates within weeks); the crate map extended with `exec`,
`symbolic`, `program`, `unpack`, `flirt` and the Java/JVM front, which
`CLAUDE.md` never mentions; delete `GLAURUNG_AGENT_ROUTE`; perf gate fails closed (exit 3); CI is
four jobs and `ty` is not among them; `baseline.json` and
`structural_baseline.json` are gated, `arch_baseline.json` and
`defuse_baseline.json` are not; `dev-oracle` is in no feature-gate lane;
delete the test counts or make them a test; delete the `cm.py` note, the
"re-counted 2026-08-31" paragraph and the "Correction, 2026-08-31" paragraph;
merge the four-vs-six side-files bullets. Also fix
`.claude/agents/rust-data-model-creator.md` (6 occurrences of the dead path).

### 5.2 `AGENTS.md` → ~20-line pointer, filename kept

The filename is the cross-vendor convention and nothing in the repo reads the
file as configuration (three shell scripts cite it in an error string). Not a
symlink: raw-content fetchers do not resolve them. Content: read `CLAUDE.md`
first; the DecBench boundary in six lines or a link; the four commands
(`uv sync --locked --dev`, `uv run maturin develop`,
`cargo test --features python-ext`, the pytest + ruff + ty line scoped to
`python/`). Delete the "Production Mindset" section, the checklists, the
duplicated style guidance, and the three bare-`.` lint commands that disagree
with `CLAUDE.md`, CI, and `scripts/typecheck-python.sh` (which uses a third
scope; pick one and make all three agree).

### 5.3 `README.md` → revise, do not rewrite

43 of 45 claims verify; the honest pre-1.0 framing from `bab803fd` should
survive. Five changes: add `git lfs install && git lfs pull` to the install
block with one sentence on why; 3.11 → 3.12 (and fix pyproject's stale
classifier); `cargo test` → `cargo test --features python-ext`; add
`rust-version = "1.88"` to `Cargo.toml` so the asserted floor is enforced
(decision D4); update the documentation map to the new tree once it exists.

---

## 6. Generators and tests that keep the rewrite true

New tools under `tools/`, each with `--check` and a test in `python/tests/`:

| Tool | Writes | Source | Test |
|---|---|---|---|
| `gen_cli_reference.py` | `docs/reference/cli.md` | `cli/main.py` `_REGISTRY` + each command's parser help | `test_docs_generated.py::test_cli_reference_current` |
| `gen_env_reference.py` | `docs/reference/environment-variables.md` | grep `os.environ`/`getenv`/`env::var`/`option_env!` over `python/glaurung`, `src`, `tools`, `scripts`, `.github` | same file |
| `gen_feature_reference.py` | `docs/reference/cargo-features.md` | `Cargo.toml [features]`, `src/lib.rs` `cfg` lines, `pyproject.toml [tool.maturin]` | same file |
| `gen_provenance_reference.py` | `docs/reference/provenance.md` (table section) | `llm/kb/provenance.py` `SET_BY_PRIORITY` | same file |
| `gen_pass_reference.py` | `docs/reference/decompiler-passes.md` | `pass!` names in `python_bindings/ir/pipeline.rs`; refine calls in `decbench_render.rs` | same file |

Two new structural tests replace the eleven classification tests in
`test_verify_tutorial.py`:

- `test_docs_manifest.py`: every `.md` under `docs/` (excluding `history/`,
  `tutorial/_fixtures/`) declares a `Kind:` from the allowed set and a
  `Status:` from `{maintained, generated, proposed}` within its first 5 lines;
  every file under `history/` declares `Kind: record` and is listed in
  `history/README.md`; no file under `history/` is linked from `docs/README.md`
  or `tutorial/`; no live file contains `Status: historical`.
- `test_docs_links.py`: every relative markdown link and every
  `docs/...` path mentioned in `src/`, `python/`, `tools/`, `scripts/`,
  `.github/`, `CLAUDE.md`, `AGENTS.md`, `README.md` resolves to an existing
  file.

The four behavioral doc tests in `test_verify_tutorial.py` (tier-5 CLI
contract, `ask` reference, demos, examples) stay, with paths updated. The
harness tests (lines 31–103) stay untouched.

---

## 7. Execution plan

Each phase names its agents, inputs, outputs, and the gate that closes it.
Phases 3 to 6 can run in parallel once Phase 2 lands. Every agent gets the
brief in `docs-audit-2026-09-02/00-brief.md` plus its ledger; writing agents
also get ledger 02 (ground truth) and Section 3 of this file.

Standing gate for every phase, run from the repository root with
`export TMPDIR="$HOME/.cache/glaurung/tmp"`:

```bash
uv run pytest python/tests/ -q -m "not fixtures and not decbench"
cargo test --features python-ext
uvx ruff format --check python/ && uvx ruff check python/ && uvx ty check python/
uv run python scripts/verify_tutorial.py --check          # all chapters
```

### Phase 0 — Evidence (done)

The nine ledgers and this plan. Commit them as-is under
`docs/development/docs-audit-2026-09-02/` so executing agents in later
sessions have the per-file verdicts.

### Phase 1 — Unblock: code and test changes (1 opus agent, serial)

1. Move the four Windows JSON baselines to `data/baselines/windows-ghidra-parity/`;
   add `python/glaurung/windows_baselines.py` exposing the paths; re-point the
   3 argparse defaults, 11 product modules, ~17 tests, and
   `windows-ghidra-parity-refresh.yml`.
2. Move `docs/axeyum-integration/capture/*.py` to `tools/axeyum/`, the four
   self-tests to `python/tests/test_axeyum_*.py`, the corpus to
   `tests/corpora/axeyum-qfbv/`, the benchmark to `bench/axeyum/`; update the
   four `.join(...)` sites in `src/symbolic/ordered_trace.rs`.
3. Rewrite `test_verify_tutorial.py`: delete the eleven classification tests;
   add `test_docs_manifest.py` and `test_docs_links.py` (Section 6) in a mode
   that passes on the current tree (allow the old `Status:` banners until
   Phase 2 flips them, then tighten).
4. Fix `scripts/verify_tutorial.py:43` to honour `TMPDIR`.
5. Fix `repl.py`'s "51 tools" strings (two sites) and re-capture
   `_fixtures/01-repl-tour` with `--capture`; read the diff.
6. Fix `.claude/agents/rust-data-model-creator.md` paths; pyproject's 3.11
   classifier; add `rust-version = "1.88"` (D4).
7. Gate: standing gate **plus** `cargo test --features symbolic` (the
   `ordered_trace` path change) and `scripts/feature-build-gate.sh`.

### Phase 2 — Mechanical reorganization (1 opus agent, serial)

1. `git mv` per Section 4, in one commit per current directory, so history
   follows the files.
2. Write `docs/history/README.md` from the ledger "verdict" and "evidence"
   columns: one line per archived file with date, subject, superseder, and
   known-false claims.
3. Add the `Kind:`/`Status:` line to every live file; replace every
   `Status: historical …` banner in `history/` with `Kind: record` plus the
   original date.
4. Link-rewrite pass over `docs/`, `src/`, `python/`, `tools/`, `scripts/`,
   `.github/`, and the three top-level files; tighten `test_docs_links.py`.
5. Delete the eight files in Appendix C.
6. Gate: standing gate, `test_docs_manifest.py` in strict mode, link checker
   green.

### Phase 3 — Top-level trio and contributor docs (1 opus agent)

Inputs: ledger 01, Section 5. Outputs: `CLAUDE.md`, `AGENTS.md`, `README.md`,
`docs/README.md`, `development/{testing-gates,traps,contributing-docs}.md`,
`development/setup.md` revisions. `traps.md` must contain every narrative
listed in ledger 01 §1.5 rows 41, 42, 44, 47, 53, 62, 65, 67, 69, 70, 71, 75,
plus the `cfg_attr`/`pymethods` gotcha from `research/pyext-separation.md`
and the two methodology lessons from `decompiler-roadmap-diary-2026-08-16.md`.
Gate: standing gate; `test_verify_tutorial.py::test_check_mode_does_not_rewrite_install_fixtures`
(no CLI change, so the fixture must be byte-identical).

### Phase 4 — Architecture from source (3 opus agents in parallel)

- **4a decompiler:** `architecture/{decompiler-pipeline,register-model,x86-flags}.md`,
  `reference/decompiler-passes.md` + its generator, `reference/decompiler-output-format.md`.
  Inputs: ledger 02 §2, ledger 03 §4 "knowledge only in docs", ledger 05,
  the six design sources named in Section 4. Must state built vs. unbuilt
  explicitly (no `hir/`, no `FunctionFacts`, MIR has no consumer,
  `remap_type_map` live, ten `DEC_*` thread-locals remain).
- **4b execution and solvers:** `architecture/{execution-engine,solver-backends,ioctl-taint}.md`,
  `decisions/exec-000{1..6}`, `decisions/solver-*` split, `design/execution-engine-research/smt-backends.md`
  rewrite. Inputs: ledger 04 in full. Must record ADR-0006 as never implemented.
- **4c crate, package, KB, LLM, Windows:** `architecture/{README,rust-crate-map,python-package-map,
  persistent-project,data-model,module-boundaries,llm-subsystem,windows-port}.md`,
  `reference/provenance.md` + generator, `history/refactoring-portfolio-2026-08/OUTCOMES.md`.
  Inputs: ledger 02 §1/§3/§4, ledgers 05 and 08. `llm-subsystem.md` names
  L1–L5 and F1–F7 from the code comments that use them.
Gate: standing gate; every new file passes the manifest test; every path or
symbol named in a new architecture doc exists (`test_docs_links.py` covers
paths; the agent spot-checks symbols with `rg` and records the command).

### Phase 5 — Reference generators (2 sonnet agents in parallel)

- **5a:** `gen_cli_reference.py`, `gen_env_reference.py`, `gen_feature_reference.py`
  and their `--check` tests; run them; delete `tutorial/reference/cli-cheatsheet.md`.
- **5b:** move the verified-clean references (Section 4 `reference/` "move"
  rows); fix the two spec-file paths from ledger 06; fix `@exceptions` in
  `decompiler-testing.md`; regenerate or banner `test-inventory/coverage.md`.
Gate: standing gate; `--check` on every generator; `test_docs_generated.py`.

### Phase 6 — Guides and tutorial (1 sonnet agent)

The six tutorial revisions from ledger 09 (cli-tour annotation section,
strings-and-data citation, searching note, patch-and-verify `$TMPDIR`,
05-vulnerable-parser `--db`, exporting header/bundle); `repl-keymap.md`
cross-link; `guides/` moves; `guides/windows-analysis.md` rewrite with the
corrected tools row; `guides/demos/`; `llm/{EMBEDDED_CONTENT,SOURCE_RECOVERY}_TOOLS.md`
banner corrections. Any chapter whose commands change gets `--capture` for
that chapter and a read diff. Gate: standing gate; `verify_tutorial.py --check`
over all chapters; the demos test.

### Phase 7 — Roadmap consolidation (1 opus agent)

Move the nine 2026-08-31 plans into `development/roadmap/` (dates dropped,
progress sections current: P9/perf gate landed, Go lanes opt-in); reconcile
the still-open items of `design/decompiler-roadmap.md` into
`roadmap/real-binary-decompiler.md`, then archive the roadmap whole; move the
fitness program section to `testing-gates.md` and re-point
`tools/fitness_report.py` and the three tests' docstrings; mark test-estate
phases done/open per `EXECUTION.md`; merge test-estate 04 and 06 into their
successors; write `design/open-questions.md`. Gate: standing gate;
`test_fitness_report.py`, `test_large_module_review.py`,
`test_src_dependency_boundaries.py` green; `CLAUDE.md`'s roadmap pointer
resolves.

### Phase 8 — Close (1 opus agent)

Full `uv run pytest python/tests/` (everything, not the CI subset),
`cargo test --features python-ext`, `cargo test --features symbolic`,
`scripts/feature-build-gate.sh`, all generators `--check`, link checker,
manifest test, `verify_tutorial.py --check`. Move this plan and the ledgers to
`history/docs-rewrite-2026-09/`. Update `docs/README.md`'s counts if any are
stated. Write a closing entry in `history/README.md` naming what was deleted
and why.

### 7.1 Agent allocation summary

| Phase | Agents | Model | Parallel with |
|---|---|---|---|
| 1 | 1 | opus | — |
| 2 | 1 | opus | — (depends on 1) |
| 3 | 1 | opus | 4, 5, 6 |
| 4 | 3 | opus | 3, 5, 6 |
| 5 | 2 | sonnet | 3, 4, 6 |
| 6 | 1 | sonnet | 3, 4, 5 |
| 7 | 1 | opus | after 4a (needs decompiler-pipeline.md to exist) |
| 8 | 1 | opus | — |

Concurrency rules for the writing phases: no two agents edit the same file;
`docs/README.md` and `history/README.md` are owned by Phase 3 and Phase 2
respectively and receive link updates by message, not by edit; every agent
uses `git diff > patch` for A/B and never `git stash` (shared ref across
worktrees, per `CLAUDE.md`).

### 7.2 What not to do

- Do not rewrite tutorial chapter prose beyond the six listed fixes. The
  chapters are verified; the reference files were the problem.
- Do not hand-edit anything under `tutorial/_fixtures/` or any generated file.
- Do not delete a file named in Appendix B before its destination exists and
  contains the knowledge.
- Do not run DecBench, Joern, or any `tools/decbench_*` script.
- Do not add a CLI command or flag as part of this work.
- Do not write status banners that state facts ("gate failing", "N tools");
  state kind and status only.

---

## 8. Decisions for the owner

| # | Decision | Recommendation |
|---|---|---|
| D1 | The 842-file `.smt2` corpus (3.9 MB): keep in git under `tests/corpora/`, move to LFS, or drop and rely on the documented regeneration (`GLAURUNG_DUMP_QUERIES`) | keep in git under `tests/corpora/axeyum-qfbv/`; it is small and 14 ADRs cite it as evidence |
| D2 | Keep `history/` in the repository at all | yes; ~150 files of dated record, and Appendix B shows nine of them hold knowledge that exists nowhere else |
| D3 | Move `agentic-glaurung/` under `design/agentic-source-recovery/` | yes, but last, and only because the manifest test is being rewritten anyway; the directory itself needs no content change |
| D4 | Pin `rust-version = "1.88"` in `Cargo.toml` | yes; three docs assert the floor and nothing enforces it |
| D5 | Fold `development/project-structure.md` into `architecture/README.md` | yes; the crate and package maps make it redundant |
| D6 | Split `axeyum-integration/07-decision-log.md` (31 ADRs, 1,160 lines) into files | yes, one per ADR with a `solver-` prefix; ends the ADR-002 collision `Cargo.toml:99` currently points into |
| D7 | Whether `guides/` and `reference/` are the right split, or one `docs/using/` | two directories; a guide is read once, a reference is grepped |

---

## Appendix A — Hard dependencies on `docs/` paths

Produced by `rg -n 'docs/[A-Za-z0-9_./-]+' python/tests scripts tools src python/glaurung .github pyproject.toml pytest.ini`
at `b8884687`. Full listing with line numbers is in the session transcript;
the consumers per path are in Section 2.1. Counts:

| Path | Consumer files |
|---|---:|
| `docs/windows-port/*_30_after_tiny_stub_gate.json` | 24 references |
| `docs/windows-port/*_30_diagnostics.json` | 22 references |
| `docs/windows-port/glaurung_vs_ghidra_vendor_windows.json` | 1 (`test_windows_analysis_helpers.py`) |
| `docs/axeyum-integration/capture/validate_ordered_trace.py` | 4 (Rust tests) |
| `docs/development/test-estate/01-reachability.md` | 5 (docstrings) |
| `docs/design/decompiler-roadmap.md` | 5 (docstrings, `fitness_report.py`) |
| `docs/design/execution-engine/02-architecture/*.md` | 9 (`//!` comments) |
| `docs/architecture/{PERSISTENT_PROJECT,IDA_GHIDRA_PARITY}.md` | 3 (module docstrings) |
| `docs/design/whole-binary-serialization-2026-08-20.md` | 2 |
| `docs/development/{decompiler-testing,decompiler-parity-backlog}.md` | 4 |

## Appendix B — Knowledge that exists only in docs

Consolidated from all ledgers. Each must be absorbed into the destination
before the source is archived.

| Source | Knowledge | Destination |
|---|---|---|
| `design/goto-density-measurement-2026-08-12.md` | goto-sinking negative result: −11% gotos cost `statemachine:gcc:O0` GED 10→35; `goto_sink.rs` deleted | `design/open-questions.md` |
| `design/dormant-transforms-2026-08-12.md` | fire counts 21/0/0 for three live `loop_form.rs` passes; why sentinel search cannot match | `design/open-questions.md` |
| `design/function-facts-and-call-facts-2026-08-15.md` §6 | four measurements proving `CallGraph` cannot found `FunctionFacts` | `design/function-facts-and-call-facts.md` (kept whole) |
| `design/x86-flags.md` | flag producer/consumer protocol and the mistake to avoid | `architecture/x86-flags.md` |
| `design/register-views-and-the-verifier-boundary.md` | why `regview.rs` owns register views; prepare-then-render boundary | `architecture/register-model.md` |
| `design/whole-binary-serialization-2026-08-20.md` | WARP adopt-vs-build analysis | `decisions/whole-binary-serialization.md` |
| `design/stack-bias-affine-index-2026-08-13.md` | only description of an idea whose branch is deleted | `design/open-questions.md` |
| `design/decbench-native-provenance-2026-08-27.md` | DecBench's AST audit lives only on an unmerged upstream draft; eval-kit cannot carry provenance | `architecture/decompiler-pipeline.md` (provenance section) |
| `design/branch-retirement-2026-08-13.md` | SHAs of deleted branches | `history/` (kept whole) |
| `design/decompiler-roadmap.md` meta-guidance | two tracks; phases are views; `[x]` requires a production caller; capability census first | `development/roadmap/README.md` |
| `design/decompiler-roadmap-diary-2026-08-16.md` preamble | "write the command next to the number"; measure the tool's noise floor first | `CLAUDE.md`, `traps.md` |
| `design/fixture-expansion-2026-08-27.md` §0 | why execution-differential testing is blind to structure | `development/decompiler-testing.md` |
| `design/multi-decompiler-roundtrip-2026-08-04.md` | every Ghidra/IDA/Binja number in our docs is imported and unrecomputable here | `architecture/competitive-position.md` preamble |
| `design/execution-engine/01-research/*` (4) | IR totality/width lessons; KLEE query numbers; memory-model taxonomy; oracle-is-not-ground-truth | `design/execution-engine-research/` (kept) |
| `design/execution-engine/05-decisions/*` §Alternatives | rejected alternatives for six decisions | `decisions/exec-*` |
| `design/execution-engine/03-phases/phase-1` §Prototype | the only copy of the `Domain` prototype | `architecture/execution-engine.md` appendix |
| `design/execution-engine/STATUS.md` worklog | the June obfuscation-handling account (`MAX_BLOCK_VISITS`, z3 `SortDiffers`, exponential `collect_syms`) | `history/` (kept whole) + one paragraph in `execution-engine.md` |
| `axeyum-integration/PAPER-NOTES.md` | the 12–29× speedup retraction | `history/` + one line in `solver-backends.md` |
| `axeyum-integration/07-decision-log.md` | 31 ADRs behind ~5,100 LOC | `decisions/solver-*` |
| `axeyum-integration/09-taint-provenance…md` | why raw symbolic sinks are not findings | `architecture/solver-backends.md` |
| `research/pyext-separation.md` §Critical Patterns | `cfg_attr(feature, pymethods)` does not work | `development/traps.md` |
| `design/execution-engine/04-testing/fixtures-and-corpus.md` §Rules | the seeded-generated-corpus carve-out from the no-mock rule | `development/contributing-docs.md` or `testing-gates.md` |
| `refactoring/02-…/README.md` | target pipeline diagram; "rendered C is a view, never an input" | `architecture/decompiler-pipeline.md` |
| `refactoring/03`, `07` | soundness stop-conditions | `architecture/module-boundaries.md` |
| `refactoring/architecture-review-2026-08-13.md` | the before-measurement of file concentration | `history/refactoring-portfolio-2026-08/OUTCOMES.md` |
| `analysis/decompiler/2026-07-30-*.md` (6) | the 123→127→162→169/250 causal chain | `history/decompiler-checkpoints-2026-07/` (kept, ordered) |
| `analysis/decompiler/2026-08-06-…-diary.md` §Evidence rules | five evidence rules | `development/contributing-docs.md` |
| `analysis/decompiler/README.md` §Structured JSON | why `addresses` is empty for params; why no line map | `reference/decompiler-output-format.md` |
| `architecture/PERSISTENT_PROJECT.md` §Function identity | why one table is not keyed by VA; two deliberate limits | kept in `architecture/persistent-project.md` |
| `architecture/data-model/critique/GPT5.md` | `AddressKind` narrowing proposed and declined | `history/data-model-2025/` + one line in `data-model.md` |
| `parsers/{macho,dotnet,wasm,python}` designs | only data-model record for unbuilt parsers | `history/parsers-2025/` |
| `triage/SIGNATURE_DESIGN.md` | three-tier signature design, unbuilt | `design/signature-tiers.md` |
| `syscalls/{linux,windows}.md` | binding a syscall claim to OS/build/arch/ABI | kept in `reference/syscalls/` |
| `campaigns/float-recovery-2026-08-12.md` | five-layer x86 float fix | `history/campaigns/` (kept) |
| `campaigns/decbench-readacross-2026-08-12.md` | Thumb-bit reasoning; `--vas` fail-closed rationale | `history/campaigns/` (kept) |
| `test-estate/10-ci-environment-gap.md` | a fix endorsed by one gate and reverted by another | kept live |
| `development/decompiler-parity-backlog.md` item 4 | two candidate fixes measured and reverted | kept live |
| `development/setup.md` | env-var tables; Docker clean-room recipe | kept; tables become generated |
| `windows-port/co-investment-policy.md` + README "Why this exists" + `atomic-tools.md` bug-class table | the ASB collaboration rationale and bug-class taxonomy | `history/windows-port-2026-05/` + summary in `architecture/windows-port.md` |
| `llm/SOURCE_RECOVERY_TOOLS.md` | why the 25-tool ladder is in that order | kept, banner corrected |
| `agentic-glaurung/00-…scope.md`, `architecture/04`, `implementation/05` | reusable-asset map; V1–V7 validators; D1–D10 risks | kept whole |

## Appendix C — Files to delete

`design/roundtrip/gcc-O0.md`; `benchmarks/baseline.md`; `benchmarks/baseline.json`;
`design/decompiler-next-implementation-directive.md`;
`design/review-findings-cf-closure.md`; `design/review-findings-width-effect.md`;
`architecture/data-model/proposals/GROK4.md`; the survey sections of
`analysis/decompiler/README.md` (the file itself becomes
`reference/decompiler-output-format.md`). Justification per file is in the
ledgers; none has an inbound link from code or tests.

## Appendix D — Ground truth at `b8884687`

Numbers a writer will need, with the command. Re-run before quoting.

| Fact | Value | Command |
|---|---|---|
| CLI subcommands | 40 | `uv run glaurung --help` / `cli/main.py` `_REGISTRY` |
| `glaurung windows` subcommands | 29 | `rg -c 'add_parser\(' python/glaurung/cli/commands/windows.py` |
| Cargo features | 13 names (12 + `default`) | `sed -n '/^\[features\]/,/^\[/p' Cargo.toml` |
| `src/` Rust files / LOC | 489 / 290,841 | `find src -name '*.rs' \| xargs wc -l` |
| `src/ir/` files / LOC | 202 / 164,779 | same, scoped |
| `src/symbolic/` files / LOC | 26 / 21,459 | same, scoped |
| `src/exec/` files / LOC | 10 / 3,591 | same, scoped |
| Python package files / LOC | 389 / 158,845 | `find python/glaurung -name '*.py' \| xargs wc -l` |
| `llm/tools/` files | ~239 (113 `windows_*`, ~70 `java_*`) | `ls python/glaurung/llm/tools \| wc -l` |
| Registered memory tools | 219 (docstring at `llm/agents/memory_agent.py:590` still says ~163) | ledger 02 §5 |
| Baseline JSONs with a named regenerator | 16 | ledger 02 §7 |
| KB tables | 35 across 9 modules | `rg -n 'CREATE TABLE' python/glaurung/llm/kb` |
| Python test files | 461 | `find python/tests -name 'test_*.py' \| wc -l` |
| Rust files with `#[cfg(test)]` | 276 (+25 in `tests/`) | `rg -l '#\[cfg\(test\)\]' src \| wc -l` |
| Decompiler fixtures | 219 (196 .c, 10 .cpp, 7 .rs, 5 .go, 1 .S) | `ls tests/decompiler_fixtures/src \| wc -l` |
| `baseline.json` lanes | 839 (2,895 pass / 433 fail / 121 structural) | ledger 03 |
| `arch_baseline.json` lanes | 2,473 | ledger 03 |
| Lifters | 3: x86/x86-64, ARM32, AArch64 | `src/ir/lift_function.rs::supports_arch` |
| Calling conventions | 6 | `src/target/abi.rs:10` |
| AST `pass!` groups | 20 (+1 health probe) | `rg -c 'pass!\(' src/python_bindings/ir/pipeline.rs` |
| Render styles | `plain`, `c`, `decbench` | `cli/commands/decompile.py:227` |
| Provenance ranks | 12 values, 7 ranks | `llm/kb/provenance.py` `SET_BY_PRIORITY` |
| Workflows | 10 | `ls .github/workflows` |
| Fuzz targets | 8 | `ls fuzz/fuzz_targets` |
| Criterion benches | 10 | `ls benches` |
| Feature-gate lanes | 12 | `scripts/feature-build-gate.sh` `lanes=()` |
| `GLAURUNG_*` env vars read in `python/glaurung/` | 18 | `rg -o 'GLAURUNG_[A-Z_]+' python/glaurung \| sort -u` |
| Python floor | 3.12 | `pyproject.toml:7` |
| Rust floor | 1.88 asserted, unenforced | no `rust-version` in `Cargo.toml` |
| Paths that do not exist but are cited | `python/glaurung/kb/`, `docs/data-model/`, `src/formats/macho/`, `src/triage/symbols/`, `src/ir/hir/`, `src/lift/`, `src/render/`, `src/os/`, `src/exec/arch/`, `reference/retdec` | `ls` each |
