# Phase 2 move manifest

> **Kind:** plan · **Status:** proposed

Every tracked `.md` under `docs/` (excluding `tutorial/_fixtures/` and this
audit directory) with its Phase 2 destination. Phase 2 moves content
unchanged; later phases rewrite in place. "stays" = untouched in Phase 2, with
the phase that owns it. Verdicts come from the ledgers in this directory.

Conventions: `H/` = `docs/history/`. Flattened names inside `H/` keep the
original basename unless two collide. Every file landing in `H/` gets
`> **Kind:** record · **Date:** YYYY-MM-DD` (the date of its last substantive
commit, from `git log --follow`) and one line in `H/README.md`.

## Root, misc

| old | new | note |
|---|---|---|
| `docs/README.md` | stays | Phase 3 rewrites |
| `docs/IOC_VALIDATOR_V2.md` | `docs/reference/ioc-validator.md` | verified current |
| `docs/research/pyext-separation.md` | `H/pyext-separation-2024-12.md` | lift the `cfg_attr` gotcha to `traps.md` in Phase 3 |
| `docs/benchmarks/baseline.md`, `baseline.json` | **delete** | orphan, no reader |
| `docs/design/roundtrip/gcc-O0.md` | **delete** | regenerable dump, headline wrong |

## `docs/tutorial/`

| old | new | note |
|---|---|---|
| all chapter files, `README.md` | stays | Phase 6 edits six chapters |
| `tutorial/PLAN.md` | `H/tutorial-plan-2026-04.md` | |
| `tutorial/reference/cli-cheatsheet.md` | `docs/reference/cli.md` | Phase 5 replaces with generated |
| `tutorial/reference/set-by-precedence.md` | `docs/reference/provenance.md` | Phase 4c rewrites from `provenance.py` |
| `tutorial/reference/repl-keymap.md` | `docs/reference/repl-keymap.md` | Phase 6 cross-links |
| `tutorial/reference/sample-corpus.md` | `docs/reference/sample-corpus.md` | |

## `docs/cli/`, `docs/demos/`, `docs/campaigns/`, `docs/sessions/`

| old | new |
|---|---|
| `cli/analyst-ergonomics.md` | `docs/guides/analyst-workflows.md` |
| `cli/analyst-annotation-loop.md` | `docs/guides/annotation-loop.md` |
| `cli/ASK_COMMAND.md` | `docs/guides/ask.md` |
| `demos/README.md`, `demo-1..3-*.md` | `docs/guides/demos/` (same basenames) |
| `campaigns/*.md` (4) | `H/campaigns/` (same basenames) |
| `sessions/2026-04-26-tutorial-and-bug-L-verification.md` | `H/sessions/` |

## `docs/triage/`, `docs/parsers/`, `docs/formats/`, `docs/syscalls/`

| old | new | note |
|---|---|---|
| `triage/README.md` | `docs/guides/triage.md` | |
| `triage/packer-config.md`, `similarity.md` | `docs/reference/` | |
| `triage/SIGNATURE_DESIGN.md` | `docs/design/signature-tiers.md` | coherent, unbuilt |
| `triage/{IMPLEMENTATION,ADDITIONAL_FEATURES,ADVANCED-FEATURES,DETAILED_IMPLEMENTATION_PLAN,RECOMMENDATIONS}.md` | `H/triage-2025/` | |
| `parsers/README.md` | `docs/guides/parsers-and-formats.md` | |
| `parsers/java/README.md` | `docs/guides/java-jvm.md` | |
| `parsers/java/JVM_AGENTIC_ANALYSIS_PLAN.md` | `H/java-jvm-2026-05/jvm-agentic-analysis-plan.md` | |
| `parsers/{elf,pe-coff,macho,android,archive,dotnet,python,wasm}/README.md` | `H/parsers-2025/<dir>-README.md` | flatten |
| `parsers/pe-coff/WINDOWS_RESOURCES_CAPABILITIES_TEST_PLAN.md` | `H/parsers-2025/pe-coff-windows-resources-test-plan.md` | |
| `parsers/{elf,pe,macho}-{consolidation-plan,migration-guide,technical-design}.md` (9) | `H/parsers-2025/` | fix the `golang_macho.go` path in the two macho files |
| `formats/*.md` (4) | `docs/reference/formats/` | verified clean |
| `syscalls/*.md` (3) | `docs/reference/syscalls/` | verified clean |

## `docs/analysis/`

| old | new | note |
|---|---|---|
| `analysis/README.md` | **delete** | pure link list for a dissolved directory |
| `analysis/decompiler/README.md` | `docs/reference/decompiler-output-format.md` | Phase 4a rewrites (keeps only JSON schema + CLI) |
| `analysis/decompiler/pipeline.md` | `docs/reference/decompiler-passes.md` | Phase 4a replaces with generated |
| `analysis/decompiler/2026-07-27-three-way-roundtrip-diary.md` | `H/decompiler-checkpoints-2026-07/` | |
| `analysis/decompiler/2026-07-30-*.md` (7), `2026-08-06-*.md` | `H/decompiler-checkpoints-2026-07/` | keep order by filename |
| `analysis/disassembly/README.md` | `docs/reference/disassembly.md` | |
| `analysis/language-detection/README.md` | `docs/reference/language-detection.md` | |
| `analysis/language-detection/{FAILURE_ANALYSIS,IMPLEMENTATION_SUMMARY,IMPROVEMENTS}.md` | `H/analysis-surveys-2025/language-detection-*.md` | |
| `analysis/interpreted/README.md` | `H/analysis-surveys-2025/interpreted-README.md` | |
| `analysis/lifting/README.md` | `H/analysis-surveys-2025/lifting-README.md` | |
| `analysis/lifting/experiments/retdec-test-2025-10-20.md` | `H/analysis-surveys-2025/` | |
| `analysis/symbols/{ENHANCEMENTS,IMPLEMENTATION}.md` | `H/analysis-surveys-2025/symbols-*.md` | |

## `docs/architecture/`, `docs/refactoring/`

| old | new | note |
|---|---|---|
| `architecture/README.md` | stays | Phase 4c rewrites |
| `architecture/PERSISTENT_PROJECT.md` | `docs/architecture/persistent-project.md` | Phase 4c fixes the `/tmp` example |
| `architecture/data-model/README.md` | `docs/architecture/data-model.md` | Phase 4c adds `src/program/` |
| `architecture/IDA_GHIDRA_PARITY.md` | `H/architecture-reviews/ida-ghidra-parity-2026-08.md` | Phase 4c mines the provenance essay |
| `architecture/2026-07-13-architecture-quality-review.md` | `H/architecture-reviews/` | |
| `architecture/data-model/{IMPLEMENTATION,nesting,disassembly_decompiler_foundations}.md` | `H/data-model-2025/` | |
| `architecture/data-model/critique/{GEMINI,GPT5}.md` | `H/data-model-2025/critique-*.md` | |
| `architecture/data-model/proposals/{CLAUDE,GEMINI,GPT5}.md` | `H/data-model-2025/proposal-*.md` | |
| `architecture/data-model/proposals/GROK4.md` | **delete** | |
| `refactoring/README.md`, `architecture-review-2026-08-13.md` | `H/refactoring-portfolio-2026-08/` | Phase 4c adds `OUTCOMES.md` |
| `refactoring/0N-*/README.md` (7) | `H/refactoring-portfolio-2026-08/0N-<name>.md` | flatten |

## `docs/design/` (top level)

| old | new | note |
|---|---|---|
| `design/README.md` | stays | Phase 7 rewrites as the index of live designs |
| `design/decompiler-roadmap.md` | stays | Phase 7 reconciles, then archives to `H/design/decompiler-roadmap-2026-08-13.md` |
| `design/ioctl-taint.md` | `docs/architecture/ioctl-taint.md` | |
| `design/decompiler-ux-competitive-ranking.md` | `docs/architecture/competitive-position.md` | |
| `design/x86-flags.md` | `docs/architecture/x86-flags.md` | Phase 4a rewrites |
| `design/register-views-and-the-verifier-boundary.md` | `docs/architecture/register-model.md` | Phase 4a rewrites |
| `design/whole-binary-serialization-2026-08-20.md` | `docs/decisions/whole-binary-serialization.md` | |
| `design/function-facts-and-call-facts-2026-08-15.md` | `docs/design/function-facts-and-call-facts.md` | |
| `design/dormant-transforms-2026-08-12.md` | `docs/design/dormant-transforms.md` | Phase 7 merges into `open-questions.md` |
| `design/goto-density-measurement-2026-08-12.md` | `docs/design/goto-density.md` | Phase 7 merges |
| `design/stack-bias-affine-index-2026-08-13.md` | `docs/design/stack-bias-affine-index.md` | Phase 7 merges |
| `design/{decompiler-middle-architecture,typed-ssa-hlir,semantics-preserving-structuring,value-model-root-cause-and-plan,glaurung-architecture-redesign-2026-08-05,decompiler-rearchitecture-2026-08-06,decompiler-plan-2026-07-27,decompiler-gap-plan-2026-08-01,decbench-remediation-roadmap-2026-08-08,decompiler-refactors,decbench-full-leaderboard-data-plan}.md` | `H/design/plans-superseded/` | Phase 4a mines the first four |
| `design/{decompiler-roadmap-diary-2026-08-13,-16,-18,-19,-31,glaurung-architecture-review-diary-2026-08-05,decbench-gap-analysis-diary-2026-08-08}.md` | `H/design/diaries/` | |
| `design/{armv7-real-defects-2026-08-05,backlog-2026-08-05,defect-register-2026-08-05,string-recovery-root-cause-2026-08-03,table-dispatch-arguments-2026-08-12,fixture-expansion-2026-08-27,multi-decompiler-roundtrip-2026-08-04,decbench-defect-reproductions-2026-08-27,decbench-native-provenance-2026-08-27,decbench-full-score-audit-2026-08-30,decbench-full-failure-taxonomy-2026-08-31,decbench-submission-readiness,ged-recovery-measured-trade}.md` | `H/design/campaigns/` | `table-dispatch-arguments` gets a one-line resolution note; `decbench-submission-readiness` gets a one-line correction note (PRs #56/#61/#62 merged) |
| `design/{branch-retirement-2026-08-13,master-integration-2026-08-12,orphan-adjudication-2026-08-19}.md` | `H/design/repo-operations/` | |
| `design/{decompiler-next-implementation-directive,review-findings-cf-closure,review-findings-width-effect}.md` | **delete** | |

## `docs/design/execution-engine/`

| old | new | note |
|---|---|---|
| `execution-engine/README.md` | `docs/architecture/execution-engine.md` | Phase 4b rewrites from source |
| `execution-engine/01-research/{README,ir-design-lessons,symbolic-execution-survey,emulator-engineering,smt-backends}.md` | `docs/design/execution-engine-research/` | Phase 4b rewrites `smt-backends.md` |
| `execution-engine/05-decisions/adr-0001-single-domain-core.md` | `docs/decisions/exec-0001-single-domain-core.md` | |
| `execution-engine/05-decisions/adr-0002-executable-ir-vs-new-tier.md` | `docs/decisions/exec-0002-harden-llir-in-place.md` | |
| `execution-engine/05-decisions/adr-0003-interpreter-not-jit.md` | `docs/decisions/exec-0003-interpreter-not-jit.md` | |
| `execution-engine/05-decisions/adr-0004-memory-model-concretize-threshold.md` | `docs/decisions/exec-0004-symbolic-memory.md` | Phase 4b rewrites |
| `execution-engine/05-decisions/adr-0005-smt-pipe-then-native-optional.md` | `docs/decisions/exec-0005-native-solver-first.md` | Phase 4b rewrites |
| `execution-engine/05-decisions/adr-0006-concolic-default.md` | `docs/decisions/exec-0006-execution-mode.md` | Phase 4b rewrites |
| `execution-engine/05-decisions/README.md` | **delete** | Phase 4b writes `docs/decisions/README.md` |
| `execution-engine/{STATUS,PLAN,00-motivation-and-goals}.md` | `H/execution-engine-2026-06/` | |
| `execution-engine/02-architecture/*.md` (9) | `H/execution-engine-2026-06/architecture/` | source comments in `src/exec`, `src/symbolic`, `src/ir` cite five of these; re-point in the link pass, Phase 4b re-points again to the new doc |
| `execution-engine/03-phases/*.md` (9) | `H/execution-engine-2026-06/phases/` | |
| `execution-engine/04-testing/*.md` (3) | `H/execution-engine-2026-06/testing/` | |

## `docs/axeyum-integration/` (prose only; Phase 1B moved the data)

| old | new | note |
|---|---|---|
| `axeyum-integration/README.md` | `docs/architecture/solver-backends.md` | Phase 4b rewrites; the "source gate failing" section goes |
| `axeyum-integration/02-interface-mapping.md` | `docs/architecture/solver/interface-mapping.md` | cited from `src/symbolic/solver/axeyum_backend/translate.rs:63` |
| `axeyum-integration/08-concretization-policy.md` | `docs/architecture/solver/concretization-policy.md` | |
| `axeyum-integration/09-taint-provenance-and-finding-labels.md` | `docs/architecture/solver/taint-provenance.md` | |
| `axeyum-integration/07-decision-log.md` | `docs/decisions/solver-decision-log.md` | Phase 4b splits into `solver-NNN-*.md` |
| `axeyum-integration/benchmark/README.md` | `bench/axeyum/README.md` | lives beside the harness |
| `axeyum-integration/capture/README.md` | `H/axeyum-integration-2026-07/capture-README.md` | Phase 4b writes the short procedure into `tests/corpora/axeyum-qfbv/README.md` |
| `axeyum-integration/{00-motivation-and-goals,01-current-state,03-architecture,04-phased-plan,05-risks-and-open-questions,06-validation-and-ci,FEEDBACK-LOG,PAPER-NOTES}.md`, `benchmark/REVIEWER-CHECKLIST.md` | `H/axeyum-integration-2026-07/` | |

## `docs/windows-port/`

| old | new | note |
|---|---|---|
| `windows-port/README.md` | `docs/guides/windows-analysis.md` | Phase 6 rewrites |
| `windows-port/windows-analysis-config.md`, `windows-api-type-sync.md` | `docs/reference/` | |
| `windows-port/{atomic-tools,pdb-ingestion-design,pe-hardening-design,bsim-similarity-design}.md` | `H/windows-port-2026-05/` | Phase 4c mines for `architecture/windows-port.md` |
| `windows-port/{roadmap,agentic-ai-functionality-roadmap,glaurung-vs-ghidra-full-debug-review,glaurung-vs-ghidra-regression-review,co-investment-policy}.md` | `H/windows-port-2026-05/` | |
| `windows-port/glaurung_vs_ghidra_vendor_windows*.md` (3) | `H/windows-port-2026-05/` | generated tables, generator lost |

## `docs/llm/`, `docs/agentic-glaurung/`

| old | new | note |
|---|---|---|
| `llm/README.md` | **delete** | link list for a dissolved directory |
| `llm/TOOLS.md` | `docs/reference/llm-tool-contract.md` | |
| `llm/EMBEDDED_CONTENT_TOOLS.md` | `docs/reference/llm-embedded-content-tools.md` | Phase 6 corrects banner |
| `llm/SOURCE_RECOVERY_TOOLS.md` | `docs/reference/llm-source-recovery-tools.md` | Phase 6 corrects banner |
| `llm/{ROADMAP,AGENT_ITERATION,ITERATION_SUMMARY,AGENT_REFACTOR_GUIDE,RE_TOOLS_OVERVIEW,FEATURES-001}.md` | `H/llm/` | |
| `agentic-glaurung/**` (20) | `docs/design/agentic-source-recovery/**` | same relative layout (D3) |

## `docs/development/`

| old | new | note |
|---|---|---|
| `development/{setup,guidelines,decompiler-testing,decompiler-parity-backlog,decompiler-curriculum-corpus,docs-rewrite-plan}.md`, `docs-audit-2026-09-02/` | stays | |
| `development/project-structure.md` | stays | Phase 4c folds into `architecture/README.md` then deletes (D5) |
| `development/decompiler-roadmap-package-2026-08-31.md` | `docs/development/roadmap/README.md` | |
| `development/real-binary-decompiler-roadmap-2026-08-31.md` | `docs/development/roadmap/real-binary-decompiler.md` | |
| `development/decbench-failure-remediation-plan-2026-08-31.md` | `docs/development/roadmap/decbench-failure-remediation.md` | |
| `development/large-function-plan-2026-08-31.md` | `docs/development/roadmap/large-functions.md` | |
| `development/optimized-structural-quality-plan-2026-08-31.md` | `docs/development/roadmap/optimized-structural-quality.md` | |
| `development/pe-pdb-macho-parity-plan-2026-08-31.md` | `docs/development/roadmap/pe-pdb-macho-parity.md` | |
| `development/performance-determinism-ratchet-plan-2026-08-31.md` | `docs/development/roadmap/performance-determinism-ratchet.md` | |
| `development/real-world-malware-asset-plan-2026-08-31.md` | `docs/development/roadmap/real-world-malware-assets.md` | |
| `development/test-inventory-authority-plan-2026-08-31.md` | `docs/development/roadmap/test-inventory-authority.md` | |
| `development/{roadmap,decompiler-test-strategy,2026-07-27-uncommitted-work-handoff}.md` | `H/development/` | |
| `development/test-estate/{01-reachability,02-canary-determinism,09-asset-hygiene}.md` | `H/development/test-estate/` | landed per `EXECUTION.md`; `test_estate_reachability.py` and four others cite `01-reachability.md` in docstrings only |
| `development/test-estate/` (rest) | stays | Phase 7 marks done/open, merges 04 and 06 |
| `docs/test-inventory/` | stays | generated set; generator default output path |
