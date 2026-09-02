# Docs audit: `docs/windows-port/`, `docs/llm/`, `docs/agentic-glaurung/`

## Executive summary

All three areas verify better against code than a typical stale-docs corpus, because an August 2026 pass retrofitted maturity banners ("historical design record," "unimplemented design contract," etc.) onto almost every file — readers are usually warned not to trust the numbers. `docs/agentic-glaurung/` (20 files) is the cleanest: it documents an unshipped feature, every design doc self-labels as unimplemented, and every spot-checked claim (file existence, task-ID counts, model defaults) is accurate — no rewrite needed, just periodic date refreshes. `docs/llm/` (10 files) is a working "history museum": 6 files are correctly self-labeled historical/superseded and point to the two living docs (`README.md`, `TOOLS.md`), but `ROADMAP.md`'s own "Built" status table is itself stale (claims 22 atomic tools; real count is ~239 files), two files (`AGENT_ITERATION.md`/`ITERATION_SUMMARY.md`) are near-duplicates, and `FEATURES-001.md` is the one orphan without a banner. `docs/windows-port/` (19 files) has the sharpest single defect: `README.md`'s own roadmap-status table says Windows atomic-tools work is "not started," while 113 `windows_*.py` tool files actually exist — the most misleading line in a file every reader hits first. `atomic-tools.md` also proposes 15 specific tool filenames that were never built; a different tool architecture shipped instead, and the banner wrongly implies continuity. Three `glaurung_vs_ghidra_vendor_windows*.md` benchmark files have no discoverable generator script anywhere in the repo — they are frozen forever. Model-policy claims (`openai:gpt-5.4-mini`, fallback `anthropic:claude-haiku-4-5`, service tier `flex`) are correct everywhere they're checkable, with zero references to old models (gpt-4o, gpt-5, claude-3-x) found in current-guidance docs. One CLAUDE.md-level inaccuracy surfaced: `GLAURUNG_AGENT_ROUTE` is named in CLAUDE.md but does not exist anywhere in code — only the `--route` CLI flag is real. No DecBench-upstream-contact violations were found in any of the three scopes. Full per-file tables, directory summaries, cross-cutting findings, proposed structures, and ground truth follow.

---

# Part 1: `docs/windows-port/` (19 files)

## Per-file table

| path | lines | last commit (date, sha) | kind | verdict | evidence | recommendation |
|---|---|---|---|---|---|---|
| README.md | 179 | 2026-08-07, 0ec35a2e | index | mostly-current | Self-labels "maintained capability index" and is largely accurate, but its own roadmap-item table row `tools \| 12-15 Windows-specific llm/tools/ files \| ... \| not started` is flatly wrong: `python/glaurung/llm/tools/windows_*.py` has 113 files (241 tool files total in that directory), far beyond the 12-15 estimate, and dozens are cited as shipped two rows earlier in the same table. All 29 `windows` CLI subcommands the table implies (diff-ghidra, ioctl, project-xrefs, project-function-chunks, project-function-start-explain, project-symbol-ranges, project-function-boundary-diff, project-data-tables, project-data-table-diff, project-callgraph-diff, project-guard-condition-diff, project-memory-access-diff/query, function-similarity-manifest, bootstrap-project-facts, etc.) were independently confirmed present in `cli/commands/windows.py` (4027 lines, 29 `add_parser` calls). | revise: fix the "tools" status row; everything else checks out |
| roadmap.md | 395 | 2026-08-07, 0ec35a2e | roadmap/plan | historical | Self-labeled "historical campaign roadmap" (accurate). Claims (2026-05-17) "#186 and the Windows-specific atomic tools remain future work" — contradicted by current code (`windows_function_similarity_manifest.py` and 113 windows tool files exist) but the doc is honestly dated and banner-flagged. | archive: keep as dated record, banner already correct |
| agentic-ai-functionality-roadmap.md | 2270 | 2026-08-07, 0ec35a2e | roadmap/plan | mostly-current | Banner: "many tools described as future work have since landed... use current tool registry." Its own tail section "Current Completion Audit" (line ~1585) confirms all 10 low-level primitives and 10 high-level agents shipped, cites 61 passing tests by name — spot-checked `test_windows_agent_exports.py` and `test_windows_functionization_review_agent.py`; both real files under `python/tests/`. Internally consistent and self-correcting. | keep; large but load-bearing — could be split into design-rationale vs. completion-audit files |
| atomic-tools.md | 814 | 2026-08-07, 0ec35a2e | design-proposal | superseded | Proposes 15 named tool files (`find_dpc_callbacks.py`, `paged_pool_deref_under_dispatch.py`, `classify_attacker_for_pe_fn.py`, `pdb_struct_layout.py`, etc.) — none of these filenames exist anywhere in the repo. Instead 113 differently-named `windows_*.py` tools shipped under a different design (composable fact/query tools, not CVE-pattern detectors). The doc's own banner ("many proposed tools now exist") overstates the correspondence — it's a different architecture that solved the same problem, not the same tools. | revise: correct the banner to say the specific proposed tool names were superseded by a different tool family, not "now exist" |
| bsim-similarity-design.md | 315 | 2026-08-07, 0ec35a2e | design-proposal | mostly-current | Self-labeled "historical design record with partial implementation." `windows_function_similarity_manifest.py` exists and is cited in README's status table as "initial deterministic opcode/byte n-gram similarity manifest shipped," matching the doc's own framing. | keep as historical design context |
| pdb-ingestion-design.md | 313 | 2026-08-07, 0ec35a2e | design-proposal | historical | Banner "core ingestion has shipped" is correct: `src/symbols/pdb.rs` (1629 lines, NOT under `src/debug/` — `src/debug/` is DWARF only) is real. Two sketch file paths never materialized: `src/symbols/analysis/pdb_types.rs` and `src/symbols/analysis/dwarf_types.rs` don't exist. Cross-ref `src/symbols/pe.rs:549-580` is stale — that line range is now TLS-directory code; the actual RSDS/CodeView scan is ~line 663-679 today. The "Exit signal" example (`glaurung symbols ... --pdb-cache`) doesn't match current CLI — `symbols.py` has no `--pdb-cache` flag (that flag lives on `kickoff`, `decompile`, `view`, `windows`, `windows_risk`, `binary_diff`, `explain` instead). Named tests `test_pdb_ingest.py`/`test_pdb_type_mapping.py` don't exist; real tests are `test_pdb_type_recovery.py`, `test_pdb_type_db.py`, `test_windows_import_pdb_facts_tool.py`. | revise: fix the two file-path sketches, the `pe.rs` line cite, and the exit-signal CLI example; otherwise keep as historical record |
| pe-hardening-design.md | 374 | 2026-08-07, 0ec35a2e | design-proposal | historical | Banner "the four named directory capabilities have shipped" — plausible: `IMAGE_DIRECTORY_ENTRY_RESOURCE/TLS/DELAY_IMPORT` constants confirmed present in `src/formats/pe/types.rs`. | keep as historical record |
| windows-analysis-config.md | 70 | 2026-08-07, 0ec35a2e | reference | current | Verified field-for-field against `python/glaurung/windows_config.py`: all 11 documented keys (`max-read-bytes`, `max-file-size`, `max-functions`, `max-blocks`, `max-instructions`, `timeout-ms`, `total-timeout-ms`, `pdb-cache-dir`, `symbol-cache-dir`, `symbol-server`, `corpus-manifest`) match the frozen dataclass `WindowsAnalysisConfig` exactly, including defaults (`max_read_bytes=104_857_600`, `max_blocks=1_000_000`, `max_instructions=30_000_000`, `timeout_ms=600_000`, `total_timeout_ms=0`). Config resolution order (explicit path → `$GLAURUNG_WINDOWS_ANALYSIS_CONFIG` → `.glaurung/windows-analysis.yaml` → defaults) matches `_resolve_config_path` exactly. `bootstrap-project-facts` example flags (`--pe-path`, `--project-path`, `--no-import-pdb-facts`, `--max-functions`, `--max-blocks`, `--max-instructions`, `--timeout-ms`, `--force-reindex`) all confirmed present in `cli/commands/windows.py`. Sample fixture path exists on disk. | keep, no changes needed |
| windows-api-type-sync.md | 101 | 2026-08-07, 0ec35a2e | reference | current | `uv run glaurung types sync` command and `--source-lock`, `--overlay`, `--output`, `--generated-dir`, `--cache-dir`, `--header`, `--clang`, `--clang-arg`, `--offline`, `--no-overlays`, `--format` flags all verified in `cli/commands/types.py`. `data/types/windows-api-sources.lock.json` and generated bundle both exist on disk. | keep, no changes needed |
| glaurung_vs_ghidra_vendor_windows.md | 12 | 2026-05-20, 874800cc | record | historical | Generated benchmark table (10-file). No generator script found anywhere under `tools/` or `scripts/` matching "vendor_windows"/"vendor-windows" — orphaned data artifact with no discoverable regeneration path. | archive: keep as dated evidence |
| glaurung_vs_ghidra_vendor_windows_30.md | 32 | 2026-05-20, 874800cc | record | historical | Same generated-table issue, 30-file version. Data is internally well-formed (35-column table, consistent "parity_or_over"/"thunk_classification_gap"/"address_missing_tiny_function_gap" reason codes across all 30 rows). | archive |
| glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.md | 32 | 2026-05-20, 874800cc | record | historical | Same generated-table issue, post-fix version — numbers visibly differ from the pre-fix file (e.g. `win10-dismapi.dll` recall moves 0.9934→0.9948), consistent with a real regenerate-after-fix workflow whose driver script is now gone. | archive |
| glaurung-vs-ghidra-regression-review.md | 123 | 2026-08-07, 0ec35a2e | record | historical | 10-fixture dashboard narrative, dated 2026-05-19, correctly banner-flagged historical. Cites `samples/binaries/platforms/windows/vendor/realworld/`, which exists. | archive |
| glaurung-vs-ghidra-full-debug-review.md | 581 | 2026-08-07, 0ec35a2e | record | historical | 30-fixture debug narrative, dated 2026-05-19, correctly banner-flagged. Consistent internally with the JSON/md dashboard files it cites. | archive |
| co-investment-policy.md | 222 | 2026-05-16, 8c45b171 | design-proposal | historical | Governs a relationship with an external "asb" (agentic-security-bot) repo at a path outside this repo and unverifiable from here. Not related to the DecBench upstream-boundary rule in CLAUDE.md — a different external project, no policy contradiction. **The one file in this directory without a maturity banner** — every sibling got one in the 2026-08-07 pass, this one was missed. | revise: add the same maturity banner the rest of the directory got; otherwise archive as external-governance record |

*(The three `glaurung_vs_ghidra_vendor_windows*.json` files and `_30_diagnostics.json` are data files, not `.md`; used only as evidence per the brief, no table row produced.)*

## Directory summary

`docs/windows-port/` is two things layered together: (1) a genuinely maintained, code-verified operator/reference pair (`windows-analysis-config.md`, `windows-api-type-sync.md`) that should survive any rewrite essentially unchanged, and (2) a large body of dated campaign records from an external collaboration ("asb"/agentic-security-bot) — design proposals, roadmaps, and generated benchmark dashboards from May-August 2026 — that an August 2026 documentation pass retrofitted with maturity banners rather than deleting. That retrofit was mostly honest: nearly every file correctly warns the reader not to trust its own numbers as current. The one place it under-corrected is `README.md`'s own roadmap-status table, which still says the Windows atomic-tools work is "not started" when 113 `windows_*.py` tool files exist — the single largest doc/code contradiction in this directory, and it sits in the file every reader is pointed to first.

## Ground truth established (windows-port)

- `windows`, `windows-risk`, `pe` CLI commands are all registered in `cli/main.py`.
- `windows.py` (4027 lines) has 29 subcommands: `diff-ghidra`, `ioctl`, `analyst`, `analyst-loop`, `analyst-notebook`, `corpus-guard`, `high-volume-preflight`, `project-fact-manifest`, `project-xrefs`, `project-callgraph-reachability`, `project-callgraph-diff`, `project-guard-condition-diff`, `project-function-chunks`, `project-function-boundary-diff`, `project-function-start-explain`, `project-symbol-ranges`, `project-memory-access-query`, `project-memory-access-diff`, `project-data-tables`, `project-data-table-diff`, `project-prototype-diff`, `bootstrap-project-facts`, `blocker-task-plan`, `symbol-similarity-plan`, `function-similarity-manifest`, `runner-artifact-review`, `runner-artifact-promotion-plan`, `runner-artifact-promotion-apply`, `target-pipeline`.
- `bootstrap-project-facts` CLI flags (windows.py:904-1024): `--pe-path`, `--project-path`, `--pdb-cache-dir`, `--analysis-config`, `--max-read-bytes`, `--max-file-size`, `--max-functions`, `--max-blocks`, `--max-instructions`, `--timeout-ms`, `--project-facts-output-path`, `--project-fact-id`, `--target-id`, `--build-label`, `--build-number`, `--architecture` (default `x64`), `--binary-filename`, `--manifest-note`, `--struct-name` (repeatable), nine `--no-index-*` toggles, `--max-memory-operand-functions` (default 512), `--no-import-pdb-facts`, `--max-pdb-prototypes` (default 512), `--force-reindex`, `--add-to-kb`.
- `WindowsAnalysisConfig` (`python/glaurung/windows_config.py`) fields: `max_read_bytes` (104,857,600), `max_file_size` (104,857,600), `max_functions` (0), `max_blocks` (1,000,000), `max_instructions` (30,000,000), `timeout_ms` (600,000), `total_timeout_ms` (0), `pdb_cache_dir`, `symbol_cache_dir`, `symbol_server`, `corpus_manifest`. Load order: explicit path → `$GLAURUNG_WINDOWS_ANALYSIS_CONFIG` → `.glaurung/windows-analysis.yaml` → defaults. Unknown keys raise `ValueError`; hyphen/underscore both accepted.
- `ioctl_taint` is real and substantial: `src/analysis/ioctl_taint.rs`, 1511 lines, last modified 2026-08-07 (commit `d6944e96`). Its design doc, `docs/design/ioctl-taint.md`, is outside this scope (`docs/design/`, not `docs/windows-port/`) — flag for whoever audits that directory. No file in `docs/windows-port/` documents it directly beyond passing mentions of the real `windows ioctl` CLI subcommand.
- PDB parsing lives at `src/symbols/pdb.rs` (1629 lines) — **not** `src/debug/` (that tree is DWARF-only: `dwarf.rs`, `dwarf_signatures.rs`, `mod.rs`). This corrects an assumption in the original task brief.
- `src/winmd.rs` (203 lines): `WinmdPrototypeParam`, `WinmdPrototype`, `WinmdExport` structs, `export_winmd_prototypes()` function — small, real, matches `windows-api-type-sync.md`'s framing as a narrow WinMD-export helper feeding the generated prototype bundle.
- **113 `windows_*.py` files exist under `python/glaurung/llm/tools/`** (241 tool files total in that directory) — this is the number to cite anywhere a doc claims "12-15" or "not started."
- No generator script exists anywhere in the repo for the `glaurung_vs_ghidra_vendor_windows*` benchmark files — they cannot be regenerated without reconstructing that pipeline from scratch.
- `glaurung types sync` flags verified: `--source-lock`, `--overlay`, `--output`, `--generated-dir`, `--cache-dir`, `--header`, `--clang`, `--clang-arg`, `--offline`, `--no-overlays`, `--format`.

## Proposed new structure (windows-port)

```
docs/windows-port/
  README.md                        rewrite of README.md — capability index; fix the "tools" status row
  windows-analysis-config.md       keep — verified-current operator reference
  windows-api-type-sync.md         keep — verified-current generation guide
  capability-history.md            merge of atomic-tools.md, pdb-ingestion-design.md,
                                    pe-hardening-design.md, bsim-similarity-design.md —
                                    one section per shipped capability's design origin,
                                    stale line-number citations removed
  roadmap-archive.md               merge of roadmap.md, agentic-ai-functionality-roadmap.md —
                                    dated campaign backlog, kept for provenance
  co-investment-policy.md          rewrite of co-investment-policy.md — add the maturity
                                    banner its siblings already carry
  archive/2026-05-19-ghidra-comparison/
    regression-review.md           archived, rewrite of glaurung-vs-ghidra-regression-review.md
    full-debug-review.md           archived, rewrite of glaurung-vs-ghidra-full-debug-review.md
    vendor-windows.{md,json}                          archived, unchanged
    vendor-windows-30.{md,json}                        archived, unchanged
    vendor-windows-30-diagnostics.json                 archived, unchanged
    vendor-windows-30-after-tiny-stub-gate.{md,json}   archived, unchanged
```

---

# Part 2: `docs/llm/` (10 files)

## Per-file table

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---|---|---|---|---|---|
| README.md | 60 | c902c115, 2026-08-11 | index | current | Correctly defers to CLAUDE.md + `config.py` for model policy; points to `TOOLS.md` as the current contributor guide; linked pages exist. | keep |
| TOOLS.md | 278 | c902c115, 2026-08-11 | reference | mostly-current | Describes real architecture: router (`tool_routing.py`) → `agents/memory_agent.py` → `tool_to_pyd_ai` → `MemoryTool`. `register_analysis_tools`/`tool_filter` confirmed real at `memory_agent.py:580,627`. Has a "Tool addition checklist" but doesn't enumerate the ~239 tool files now under `llm/tools/` — acceptable, it's a contract doc, not a catalog. | keep |
| ROADMAP.md | 1111 | fcca960b, 2026-08-05 | roadmap/plan | mostly-current (header) / stale (body) | Header banner (lines 3-14) correctly says model policy is `config.py`/CLAUDE.md-authoritative and the §5.1 config sketch is not implemented. But the "Built" status table itself (line 25) says **"Atomic tools (22)"** — actual `llm/tools/` has **239 `.py` files** (~67 defining a `MemoryTool` class). Even the "source of truth" status table is far out of date. Body (§1+, line 60+) is the original 2025 design sketch with `agents/binary.py`, `models/analysis.py`, `openai:gpt-4o-mini`/`gpt-4o` examples — all superseded per the doc's own "Not built" table. | revise: refresh the "Built" status table (tool count, current agent/tool inventory); fence off the stale §1-§7 design sketch into a clearly historical appendix |
| AGENT_ITERATION.md | 260 | c902c115, 2026-08-11 | record | historical | Self-labeled "Historical design note," correctly redirects to README/TOOLS/`agents/`. Content (single-pass-only limitation) predates `agents/{single_pass,iterative,iterative_refinement}.py`, which exist today. | keep as archived record (banner already does the job) |
| AGENT_REFACTOR_GUIDE.md | 344 | c902c115, 2026-08-11 | record | historical | Self-labeled "Refactor-era record." Describes `ModelHyperparameters`, `AnalysisResult`, `ExecutionState` in `agents/base.py`, which exists. | archive (move to a `docs/llm/history/` area) |
| ITERATION_SUMMARY.md | 151 | c902c115, 2026-08-11 | record | historical | Self-labeled "Historical pre-refactor assessment," redirects correctly. Duplicates AGENT_ITERATION.md's premise (single-pass-only) almost entirely — genuinely redundant. | merge-into AGENT_ITERATION.md (or delete — both say the same thing and both are already superseded) |
| RE_TOOLS_OVERVIEW.md | 223 | c902c115, 2026-08-11 | record | superseded | Self-labeled "Superseded first-generation overview." Uses `openai:gpt-4.1-mini` (lines 58, 114) — an older model name than the current `gpt-5.4-mini` default; references `tools.py`/`re_tools_simple.py`, files that do not exist in the current flat `llm/tools/` layout. | archive |
| EMBEDDED_CONTENT_TOOLS.md | 246 | c902c115, 2026-08-11 | design-proposal | mostly-current | Self-labeled "Design and implementation record." All 6 spot-checked tool names (`find_embedded_executables`, `find_encoded_blobs`, `find_structured_blobs`, `extract_archive`, `scan_until_byte`, `search_byte_pattern`) exist as real files in `llm/tools/`. `register_analysis_tools` and `analyze_recursively` also confirmed real. | revise: fold the banner's caveat into a short "shipped tools" list at the top |
| SOURCE_RECOVERY_TOOLS.md | 373 | c902c115, 2026-08-11 | design-proposal | mostly-current | Self-labeled "Design ladder, not a current command reference." Describes a 25-tool recovery ladder; at least 14 matching tool files exist (`recover_struct_layout.py`, `recover_enum.py`, `recover_cli_grammar.py`, `recover_error_model.py`, `audit_recovered_source.py`, `verify_recovery_tool.py`, `reconcile_function_identity.py`, `reconcile_global_naming.py`, `rewrite_function_idiomatic.py`, `synthesize_docstring.py`, `propose_types_for_function.py`, `infer_function_signature.py`, `infer_build_system.py`, `write_readme_and_manpage.py`). Substantially shipped, not just a plan — the banner undersells how much landed. | revise: update banner to say most of the ladder shipped; verify count against `llm/tools/` |
| FEATURES-001.md | 347 | f897ce76, 2025-09-07 | design-proposal | superseded | "Status: Draft, Last updated: 2025-09-04" — a year-old, pre-memory-first design (per-agent output models via `models/analysis.py`), which ROADMAP.md's own "Diverged from plan" section says was abandoned in favor of KB nodes/edges. **The one doc in scope without any maturity banner.** | archive |

## Directory summary

`docs/llm/` is mostly a well-curated history museum: 6 of 10 files are explicitly self-labeled historical/superseded/design-record documents with correct redirect banners pointing to the two living docs (`README.md`, `TOOLS.md`). The actual current, load-bearing documentation is thin: an index plus a tool contract. Two overlapping "old assessment" files (`AGENT_ITERATION.md`, `ITERATION_SUMMARY.md`) say the same thing and should be merged. `FEATURES-001.md` is the one orphan without a banner and is over a year stale. The two "tool ladder" design docs (`EMBEDDED_CONTENT_TOOLS.md`, `SOURCE_RECOVERY_TOOLS.md`) undersell how much of their content has actually shipped.

## Ground truth established (llm)

- **Model defaults** (`python/glaurung/llm/config.py`): `default_model = "openai:gpt-5.4-mini"`, `fallback_model = "anthropic:claude-haiku-4-5"`, `summarizer_model`/`risk_scorer_model`/`ioc_model` all `"openai:gpt-5.4-mini"`, `openai_service_tier = "flex"`. Matches CLAUDE.md exactly. Env overrides confirmed real: `GLAURUNG_LLM_MODEL`, `GLAURUNG_OPENAI_SERVICE_TIER`, plus budget envs `GLAURUNG_REQUEST_LIMIT`, `GLAURUNG_INPUT_TOKENS_LIMIT`, `GLAURUNG_TOTAL_TOKENS_LIMIT`, `GLAURUNG_MAX_OUTPUT_TOKENS`.
- **`GLAURUNG_AGENT_ROUTE` does not exist in code.** Named in CLAUDE.md as an alternative to `--route`, but a repo-wide search found zero occurrences outside CLAUDE.md itself. The real, working mechanism is the `--route` CLI flag in `cli/commands/ask.py` (calls `select_tools_for_question()` in `tool_routing.py`). **This is a CLAUDE.md-level inaccuracy**, not a `docs/llm/` one — flag to whoever owns CLAUDE.md or the plan.
- **L1-L5 and F1-F7 terminology is real, used in code comments** (not doc invention): L2/L3/L4/L5 appear in `findings.py`, `findings_runner.py`, `finding_critic.py`, `finding_verifier.py`, `tool_routing.py`; F1-F7 appear in `config.py`, `cwe_sweep.py`, `finding_critic.py`, `findings_runner.py`, `usage_limits.py`, `usage_tracker.py`, `kb/binary_diff.py`, `agents/{iterative,iterative_refinement,single_pass}.py`. **No doc in `docs/llm/` scope documents the L1-L5/F1-F7 scheme itself as a named, explained system** — a gap; it exists only in inline code comments and CLAUDE.md.
- **Module inventory**: `python/glaurung/llm/` has ~239 files under `tools/` (~67 defining a `MemoryTool` class), ~28 files under `agents/`, ~20 under `kb/`, plus top-level `config.py`, `context.py`, `coverage.py`, `cwe_sweep.py`, `evidence.py`, `findings.py`, `findings_runner.py`, `finding_critic.py`, `finding_verifier.py`, `logging.py`, `runtime_classifier.py`, `tool_routing.py`, `usage_limits.py`, `usage_tracker.py`. A large fraction of tool files are `windows_*` (~90+, overlapping with `docs/windows-port/`'s 113-file count) and `java_*` (~70+) families — neither family is covered by any doc in `docs/llm/` scope.
- **`sweep_binary`/`max_parallel`**: confirmed in `cwe_sweep.py:170,176` — default `max_parallel: int = 1`, matches CLAUDE.md.
- **`register_analysis_tools`/`tool_filter`**: both real, defined in `agents/memory_agent.py:580-664`, consumed by `findings_runner.py`, `cli/commands/ask.py`, and `agents/specialized.py`/`factory.py`.

## Proposed new structure (llm)

```
docs/llm/
├── README.md                          rewrite of README.md — index, keep as-is mostly
├── TOOLS.md                           keep — current tool contract
├── ROUTING_AND_BUDGETS.md             new — document L1-L5 routing tiers + F1-F7 cost guards as a
                                        named system; currently only in code comments/CLAUDE.md
├── EMBEDDED_CONTENT_TOOLS.md          revise of EMBEDDED_CONTENT_TOOLS.md — banner reflects shipped status
├── SOURCE_RECOVERY_TOOLS.md           revise of SOURCE_RECOVERY_TOOLS.md — banner + shipped-step count
└── history/
    ├── ROADMAP.md                     archive of ROADMAP.md — freeze design-sketch body after one
                                        refresh of the Built/Not-built/Diverged tables
    ├── AGENT_ITERATION_AND_SUMMARY.md merge of AGENT_ITERATION.md + ITERATION_SUMMARY.md
    ├── AGENT_REFACTOR_GUIDE.md        archive of AGENT_REFACTOR_GUIDE.md
    ├── RE_TOOLS_OVERVIEW.md           archive of RE_TOOLS_OVERVIEW.md
    └── FEATURES-001.md                archive of FEATURES-001.md — add missing banner before archiving
```

---

# Part 3: `docs/agentic-glaurung/` (20 files)

## Per-file table

| path | lines | last commit | kind | verdict | evidence | recommendation |
|---|---|---|---|---|---|---|
| README.md | 134 | db5cbe47, 2026-08-03 | index | current | Explicitly states "This document does not claim that the autonomous agent exists." Lists the three product identities (`glaurung-raw`, `glaurung-llm-pipeline`, `glaurung-agent`); the fixed-pipeline description matches `tools/decbench_external_agentic.py`'s `REQUIRED_LLM_STAGES`/`ROLE_STAGE` exactly. Document map lists all 19 other files, all of which exist. | keep |
| PLAN.md | 307 | db5cbe47, 2026-08-03 | roadmap/plan | current | 64 unique task IDs (F/V/T/A/O/R/E/H-prefixed), matching `implementation/02-work-breakdown.md`'s 64 count exactly. Only 6 of 99 checklist lines checked (all `P0x` control-plane items); first unchecked item is `F01`, matching STATUS.md's "Current task: F01." | keep |
| STATUS.md | 196 | c902c115, 2026-08-11 (real content edit: 0ec35a2e, 2026-08-07 — `c902c115` is a repo-wide snapshot commit, not a real edit) | record | current | Verified live: `python/glaurung/llm/agents/source_recovery.py` absent, `tools/decbench_external_agent.py` absent, `tools/decbench_external_agentic.py` exists and still writes `DIAGNOSTICS_NAME = "glaurung-agentic-diagnostics.json"` (unrenamed) — every "remains absent/unchanged" claim still holds. | keep, but refresh the "Refresh audit: 2026-08-07" date — 26 days stale even though content is accurate |
| 00-current-state-and-scope.md | 141 | c902c115 (0ec35a2e) | reference | current | "164-tool registry" claim cross-checks against `register_analysis_tools()`'s own docstring in `memory_agent.py:590` ("~163-tool memory surface... Anthropic caps strict-tool count at 20") — accurate. `tool_routing.py` and `IterativeRefinementAgent` (`agents/iterative_refinement.py`) both exist as claimed. | keep |
| architecture/01-runtime-and-control-loop.md | 205 | c902c115 (0ec35a2e) | design-proposal | current | Self-labeled "unimplemented design contract"; nothing has shipped to falsify. | keep |
| architecture/02-context-evidence-and-memory.md | 182 | c902c115 (0ec35a2e) | design-proposal | current | Same banner discipline; references `MemoryContext`/`Budgets` (exist in `python/glaurung/llm/context.py`) as reusable inputs only, not as shipped agent-context. | keep |
| architecture/03-tool-surface-and-contracts.md | 167 | c902c115 (0ec35a2e) | design-proposal | current | "164-tool registry" figure confirmed close to actual (~163). Explicitly flags proposed names as unshipped. | keep |
| architecture/04-output-validation-and-repair.md | 161 | c902c115 (0ec35a2e) | design-proposal | current | Self-labeled unimplemented; V1-V7 validator IDs consistent with `implementation/03`'s `source_recovery_validation.py` proposal. | keep |
| evaluation/01-test-strategy.md | 163 | c902c115 (0ec35a2e) | design-proposal | current | Self-labeled "planned evaluation contract... has not been executed." | keep |
| evaluation/02-decbench-experiment-design.md | 175 | c902c115 (0ec35a2e) | design-proposal | current | Explicit invariant against autonomous maintainer contact (line 174) — aligns with, does not contradict, CLAUDE.md's DecBench upstream-boundary rule. | keep |
| evaluation/03-baselines-ablations-and-scorecards.md | 170 | c902c115 (0ec35a2e) | design-proposal | current | Self-labeled "planned evaluation schema... empty or historical lanes are not current agent results." | keep |
| implementation/01-phased-roadmap.md | 218 | c902c115 (0ec35a2e) | roadmap/plan | current | "Update DecBench integration docs without contacting maintainers automatically" — consistent with policy, not a violation. Phase structure matches PLAN.md's phase headers. | keep |
| implementation/02-work-breakdown.md | 131 | c902c115 (0ec35a2e) | reference | current | 64 task IDs match PLAN.md 1:1 (verified by set diff). | keep |
| implementation/03-file-and-api-change-map.md | 204 | c902c115 (0ec35a2e) | design-proposal | current | Proposed new module paths (`source_recovery_models.py`, `source_recovery_context.py`, `source_recovery_tools.py`, `source_recovery_validation.py`, `source_recovery_prompt.py`) verified NOT to exist yet — consistent with self-label and STATUS.md. | keep |
| implementation/04-acceptance-gates.md | 239 | c902c115 (0ec35a2e) | design-proposal | current | Sample command `GLAURUNG_LLM_MODEL=openai:gpt-5.4-mini` matches current model default. Gate table (G0-G11) IDs match STATUS.md's "Acceptance-gate status" table 1:1. | keep |
| implementation/05-risks-and-decisions.md | 171 | c902c115 (0ec35a2e) | design-proposal | current | D10 "No automated maintainer contact" matches CLAUDE.md's DecBench boundary. Open questions Q1-Q10 referenced correctly by STATUS.md's blockers section. | keep |
| operations/01-model-configuration-and-budgets.md | 131 | c902c115 (0ec35a2e) | design-proposal | current | Model `openai:gpt-5.4-mini`, fallback `anthropic:claude-haiku-4-5` — match CLAUDE.md's live LLM policy exactly; no stale model names found anywhere in this directory. | keep |
| operations/02-security-sandbox-and-data-policy.md | 136 | c902c115 (0ec35a2e) | design-proposal | current | Self-labeled "required, unimplemented security contract." | keep |
| operations/03-observability-provenance-and-cost.md | 176 | c902c115 (0ec35a2e) | design-proposal | current | Self-labeled "unimplemented operational contract... not metadata emitted by the current fixed pipeline." | keep |
| operations/04-concurrency-checkpointing-and-recovery.md | 146 | c902c115 (0ec35a2e) | design-proposal | current | Self-labeled "unimplemented operational contract." | keep |

## Directory summary

`docs/agentic-glaurung/` is a single, internally coherent design-and-resume package for one specific unshipped feature: a `pydantic_ai.Agent` that autonomously recovers one C function from one address in a stripped binary, distinct from the existing hard-coded three-stage `glaurung explain` pipeline and from the separate whole-program `scripts/recover_source.py` pipeline. Roughly 90% of the directory (16 of 20 files) is explicit unimplemented design/plan content, each carrying a prominent, consistent "Status: unimplemented/planned/proposed" banner — unusually disciplined, and every self-description checked out true against the live tree. Only `STATUS.md` and `PLAN.md` are living resume-record documents, and both are still accurate: implementation genuinely has not started (`F01` unchecked, `source_recovery.py` absent, the fixed runner still unrenamed). A clean structure keeps exactly this shape; the only actionable change is flipping each design-proposal's status banner to "implemented" as work actually lands.

## Cross-cutting findings within this directory

- No doc-vs-code contradictions found. Every checkable claim (file existence, function/class names, model identity, tool counts, task-ID counts, gate-ID sets) verified correct as of HEAD `b8884687`.
- No doc-vs-doc contradictions found. STATUS.md, PLAN.md, and the 16 subsystem docs agree on current task (F01), phase (0), model defaults, the three product identities, and the DecBench-runner rename requirement.
- No DecBench-policy violations found. This package predates and independently arrived at the same rule CLAUDE.md later codified — README invariant #10, `00-current-state-and-scope.md`'s "out of scope" list, and risk decision D10 all forbid automated maintainer/issue/PR contact with DecBench upstream.
- Knowledge that exists ONLY in these docs: the reusable-asset mapping in `00-current-state-and-scope.md` (which existing classes/functions — `LLMConfig.create_agent()`, `build_usage_limits()`, `tool_routing.py`, `IterativeRefinementAgent` — are earmarked for reuse and what correction each needs) is not written down anywhere else. Same for the V1-V7 validator taxonomy in `architecture/04` and the D1-D10 risk register in `implementation/05-risks-and-decisions.md`.
- Adjacency worth flagging: `scripts/recover_source.py` (2,587 lines, a 25-tool Layer 0→4 whole-program C/C++ recovery pipeline) and the `verify-recovery`/`java-recovery-report` CLI commands are real, already-shipped source-recovery capability that this doc package never references (correctly out of scope per `00-current-state-and-scope.md`, but a reader of only this directory would not learn that whole-program recovery already exists elsewhere — it's documented in `docs/llm/SOURCE_RECOVERY_TOOLS.md`, Part 2 above).
- Staleness note, not a contradiction: every file's git blame lands on `c902c115` ("snapshot: preserve complete primary working tree," 2026-08-11), a repo-wide re-touch commit, not a real content edit. True last content edits are `0ec35a2e` (2026-08-07) for the 16 subsystem docs and `db5cbe47` (2026-08-03) for README/PLAN. Use the real dates, not the snapshot commit, when assessing recency — this applies throughout the audit.

## Ground truth established (agentic-glaurung)

- `python/glaurung/llm/agents/source_recovery.py` — does not exist.
- `tools/decbench_external_agent.py` — does not exist.
- `tools/decbench_external_agentic.py` — exists (25,710 bytes), still invokes `glaurung explain` with `DIAGNOSTICS_NAME = "glaurung-agentic-diagnostics.json"` (unrenamed), `DEFAULT_MODEL = "openai:gpt-5.4-mini"`, `DEFAULT_SERVICE_TIER = "flex"`, `REQUIRED_LLM_STAGES = ("infer_function_signature", "rewrite_function_idiomatic")`, `ROLE_STAGE = "classify_function_role"`.
- `tools/decbench_external_llm_pipeline.py` and `python/tests/test_decbench_external_llm_pipeline.py` (the F01-target rename) — do not exist yet.
- `scripts/recover_source.py` — exists, 2,587 lines, a separate whole-program C/C++ recovery driver, out of scope for this doc package.
- `python/glaurung/cli/commands/verify_recovery.py` (CLI: `verify-recovery`) and `java_recovery_report.py` (CLI: `java-recovery-report`) — both exist, both shipped, both outside this doc package's scope.
- `register_analysis_tools()` in `python/glaurung/llm/agents/memory_agent.py` — exists, docstring confirms "~163-tool memory surface" and "Anthropic caps strict-tool count at 20," matching the docs' "164-tool" figure and the `tool_filter`/L5 mechanism CLAUDE.md describes.
- `python/glaurung/llm/tool_routing.py` and `python/glaurung/llm/agents/iterative_refinement.py` (`IterativeRefinementAgent`) — both exist as claimed.
- PLAN.md and `implementation/02-work-breakdown.md` both contain exactly 64 unique F/V/T/A/O/R/E/H task IDs, matching 1:1.
- No DecBench-upstream-contact instructions found anywhere in this doc scope; the package's own invariants already forbid it.

## Proposed new structure (agentic-glaurung)

No structural rewrite needed — the existing tree is already the right shape:

```
docs/agentic-glaurung/
├── README.md                                    keep — refresh links only if files move
├── PLAN.md                                       keep — living checklist, update in place as F01+ land
├── STATUS.md                                     keep — living resume record, refresh "Refresh audit" date each check-in
├── 00-current-state-and-scope.md                 keep
├── architecture/{01,02,03,04}-*.md               keep — flip banner "unimplemented" → "implemented" per-file as each ships
├── evaluation/{01,02,03}-*.md                    keep
├── implementation/{01,02,03,04,05}-*.md          keep
└── operations/{01,02,03,04}-*.md                 keep
```

The only real action item: once F01 (rename `tools/decbench_external_agentic.py` → `tools/decbench_external_llm_pipeline.py`) lands, STATUS.md's "Evidence ledger" and "Exact next action" sections need updating to advance to F06 — a content-freshness task for the implementer, not a documentation-structure problem.

---

# Cross-cutting findings across all three scopes

1. **`README.md` (`docs/windows-port/`) has the sharpest doc/code contradiction found in this audit**: its own roadmap-status table says Windows atomic-tools work is "not started," while 113 `windows_*.py` tool files exist under `python/glaurung/llm/tools/` — a directory that both `docs/windows-port/` and `docs/llm/` docs reference but that neither fully catalogs.
2. **`docs/llm/ROADMAP.md`'s "Built" status table is itself stale** (claims 22 atomic tools; real count ~239 files) — the same "status table lags the codebase" failure mode as finding #1, in a sibling directory, suggesting this is a systemic pattern in how these three doc trees get maintained, not an isolated slip.
3. **CLAUDE.md-level inaccuracy** (affects readers of any of the three scopes who trust CLAUDE.md as ground truth): `GLAURUNG_AGENT_ROUTE` is named in CLAUDE.md as an alternative routing mechanism to `--route`, but does not exist anywhere in code. Only the `--route` CLI flag (`cli/commands/ask.py`) and `select_tools_for_question()` (`tool_routing.py`) are real. Worth fixing at the CLAUDE.md level, not just flagging in a subdirectory report.
4. **Model-policy consistency is a genuine strength**: across all three scopes, every doc that states a current model checked out to `openai:gpt-5.4-mini` / fallback `anthropic:claude-haiku-4-5` / service tier `flex`. Old-model references (`gpt-4o`, `gpt-4.1-mini`, `gpt-4o-mini`) exist only in explicitly-banner-labeled historical/superseded docs (`docs/llm/RE_TOOLS_OVERVIEW.md`, `docs/llm/ROADMAP.md`'s frozen body) — none present themselves as current guidance.
5. **No DecBench-upstream-contact violations found in any of the three scopes.** `docs/agentic-glaurung/evaluation/02-decbench-experiment-design.md` and `implementation/05-risks-and-decisions.md` (D10) both explicitly codify the no-autonomous-contact rule, predating and independent of CLAUDE.md's later formalization of it.
6. **`ioctl_taint` is real (`src/analysis/ioctl_taint.rs`, 1511 lines) but its only design doc (`docs/design/ioctl-taint.md`) sits outside all three audited scopes** — worth flagging to whoever covers `docs/design/`, since CLAUDE.md's "Active frontier" line cites it as windows-port-adjacent work but no `docs/windows-port/` file documents it.
7. **`docs/llm/SOURCE_RECOVERY_TOOLS.md` and `docs/agentic-glaurung/`'s source-recovery design package describe two different, non-overlapping recovery systems** that share almost no vocabulary: the former documents the shipped, tool-by-tool whole-program ladder (`scripts/recover_source.py` + 14+ `recover_*`/`reconcile_*` tools); the latter designs an unshipped, single-function autonomous agent. Neither cross-references the other. A reader who only sees one directory would not learn the other system exists — worth a one-line cross-reference in each, not a merge (they are genuinely different systems).
8. **Duplicated coverage within `docs/llm/`**: `AGENT_ITERATION.md` and `ITERATION_SUMMARY.md` are near-duplicate "pre-refactor assessment" documents and should be merged.
9. **Orphaned generated artifacts in `docs/windows-port/`**: the three `glaurung_vs_ghidra_vendor_windows*.md`/`.json` pairs have no discoverable generator script anywhere under `tools/` or `scripts/` — frozen forever unless someone reconstructs the pipeline.
10. **Knowledge that exists ONLY in docs and would be lost if deleted**:
    - `docs/windows-port/co-investment-policy.md` + `README.md`'s "Why this exists" section + `atomic-tools.md`'s bug-class table: the entire "asb" (agentic-security-bot) collaboration rationale and the tier-1/tier-2 bug-class-invariant taxonomy it targets — not reconstructible from repo code, since the referenced asb repo is external.
    - `docs/llm/SOURCE_RECOVERY_TOOLS.md`: the "why this order" dependency reasoning between the 25 recovery-ladder tools — the tools survive in code, but the pipeline narrative does not exist elsewhere.
    - `docs/agentic-glaurung/00-current-state-and-scope.md`'s reusable-asset mapping and `architecture/04`'s V1-V7 validator taxonomy and `implementation/05`'s D1-D10 risk register — none of this is written down anywhere in code comments.
    - No doc in `docs/llm/` scope names the L1-L5 routing tiers / F1-F7 cost guards as a coherent system with rationale; it exists only as scattered code comments and a compressed one-paragraph mention in CLAUDE.md.

# Combined ground truth (quick reference for the plan writer)

- **Model policy** (verified in `python/glaurung/llm/config.py`, matches everywhere checked): `default_model="openai:gpt-5.4-mini"`, `fallback_model="anthropic:claude-haiku-4-5"`, `openai_service_tier="flex"`. Env: `GLAURUNG_LLM_MODEL`, `GLAURUNG_OPENAI_SERVICE_TIER`. **`GLAURUNG_AGENT_ROUTE` (named in CLAUDE.md) does not exist** — real flag is `--route` on `cli/commands/ask.py`.
- **`python/glaurung/llm/tools/` has ~239 `.py` files** (~113 `windows_*`, ~70 `java_*`, plus the rest); `python/glaurung/llm/agents/` has ~28 files; `register_analysis_tools()` docstring says "~163-tool memory surface" (the strict-schema-exposed subset, not the raw file count).
- **`windows.py` CLI has 29 subcommands** (full list in Part 1 above); `windows_config.py`'s `WindowsAnalysisConfig` has 11 fields, all correctly documented in `windows-analysis-config.md`.
- **PDB parsing is `src/symbols/pdb.rs`** (1629 lines), not `src/debug/` (DWARF-only). `src/winmd.rs` (203 lines) is a small, real WinMD-export helper.
- **`ioctl_taint` is shipped** (`src/analysis/ioctl_taint.rs`, 1511 lines); its design doc lives in `docs/design/`, outside all three scopes here.
- **`scripts/recover_source.py`** (2,587 lines) and CLI commands `verify-recovery`/`java-recovery-report` are real, shipped, whole-program source-recovery capability — distinct from the unshipped single-function agent designed in `docs/agentic-glaurung/`.
- **`docs/agentic-glaurung/` implementation status**: task F01 (rename `tools/decbench_external_agentic.py`) has not started; nothing in the 64-task PLAN.md beyond the initial P0x control-plane items is checked off.
- **Git-blame caveat**: most files across all three scopes show `c902c115` (2026-08-11) as "last commit," but that is a repo-wide snapshot commit, not a real edit. True content-edit dates are typically `0ec35a2e` (2026-08-07, agentic-glaurung subsystem docs) or file-specific (windows-port docs mostly also land on `0ec35a2e`). Use `git log --follow -2` or diff against the snapshot commit's parent to find real edit dates, not just `-1`.
