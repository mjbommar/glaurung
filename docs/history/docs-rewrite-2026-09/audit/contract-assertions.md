# Behavioral contracts rescued from the deleted doc-classification tests

> **Kind:** record · **Date:** 2026-09-02

Phase 1 deleted ten tests from `python/tests/test_verify_tutorial.py` that
pinned banner text, refresh dates, and commit SHAs in doc prose (plan §1.2,
§6). Most of what they asserted was classification — replaced by
`python/tests/test_docs_manifest.py`. A minority were genuine **behavioral
contracts**: a maintained document had to state a fact about how the code
actually behaves, and a reader who followed the doc without that sentence
would be misled.

Those are listed below so the Phase 3–6 writers can re-assert the ones that
are still true in the rewritten tree. Each row records the claim, where it
lived, and whether it was verified as still true on 2026-09-02
(`b8884687` plus the phase-1 working tree).

**How to use this file.** When you rewrite the destination document, keep the
claim (reworded is fine — the old tests pinned literal strings, which is what
made them brittle). If a claim is no longer true, say so in your report and
delete the row instead of quietly dropping it. Nothing here should be
re-encoded as a literal-string assertion in a test; the point of the rewrite
is that documents state facts and tests check structure.

Not carried over, deliberately: every `Status: …` banner pin, the
`Refresh audit: 2026-08-07` date pin, the `fcca960b` / `02d32c9d` SHA pins,
and `axeyum-integration/README.md`'s `Current source gate: failing` — that
last one was fixed in code on 2026-08-17 (`114a5c4c`) and the test was
requiring the document to stay wrong (plan §1.1 row 14).

## Contracts to re-assert

| # | Claim the doc must keep making | Old home | New home (plan §4) | Still true? |
|---|---|---|---|---|
| C1 | `glaurung disasm`'s `--comments` currently adds no annotations | `analysis/disassembly/README.md` | `reference/disassembly.md` | verify with `rg -n "comments" python/glaurung/cli/commands/disasm.py` |
| C2 | `disasm`'s address flags do not control the mapped-VA path | `analysis/disassembly/README.md` | `reference/disassembly.md` | verify against the same command module |
| C3 | Language/compiler detection is **not** exposed as a standalone CLI command; the check is `cargo test compiler_detection` | `analysis/language-detection/README.md` | `reference/language-detection.md` | verify with `rg -n "language" python/glaurung/cli/main.py` |
| C4 | `glaurung triage` documents `--max-depth`, `--tree`, and its exit-status contract | `triage/README.md` | `guides/triage.md` | but see C5 — the two docs disagreed |
| C5 | The parser index says `--tree` "is advertised but is not currently wired" | `parsers/README.md` | `guides/parsers-and-formats.md` | **resolve against code before republishing**: the triage guide advertised `--tree` while the parser index said it does nothing |
| C6 | Triage output nests under `containers` | `parsers/README.md` | `guides/parsers-and-formats.md` | |
| C7 | There is no owned `src/formats/macho` parser module | `parsers/README.md` | `guides/parsers-and-formats.md` | ledger 06; also fix the two dead spec-file refs (`archive.h`, `golang_macho.go`) |
| C8 | Live parser entry points are `uv run glaurung {triage,classfile,luac,pe resources}` | `parsers/README.md` | `guides/parsers-and-formats.md` | |
| C9 | `PersistentKnowledgeBase.open(…)` / `MemoryContext.open_persistent(…)` are the storage entry points | `architecture/PERSISTENT_PROJECT.md` | `architecture/persistent-project.md` | |
| C10 | KB **migrations are not yet implemented**, and the schema version is currently `1` | `architecture/PERSISTENT_PROJECT.md` | `architecture/persistent-project.md` | re-check the version against `python/glaurung/llm/kb/persistent.py` before restating |
| C11 | The data model is sourced from `src/core/mod.rs`, `src/triage/`, and `python/glaurung/llm/kb/` | `architecture/data-model/README.md` | `architecture/data-model.md` | note the KB path — `python/glaurung/kb/` is the false path in `CLAUDE.md` (plan §1.1 row 1) |
| C12 | `TriageRunError` does not currently exist; errors live in `src/core/triage/errors.rs`, logging via `configure_logging` | `development/guidelines.md` | `development/guidelines.md` (kept) | |
| C13 | Setup uses `uv sync --locked --dev` and the `rust:1.88-bookworm` toolchain image | `development/setup.md` | `development/setup.md` | Phase 3 also raises 3.11 → 3.12 and adds Git LFS (plan §1.1 rows 8, 9) |
| C14 | `tools/dectest.py --list-sets` is how you find the named fixture sets | `development/decompiler-testing.md` | `development/decompiler-testing.md` | `@exceptions` in that doc is not in `sets.toml` (plan §1.1 row 25) |
| C15 | The curriculum corpus results are stated at a named commit (`1525bdf0`) | `development/decompiler-curriculum-corpus.md` | same | keeps "write the command next to the number" (plan §3.4); refresh or drop the commit, do not leave it bare |
| C16 | `formats/README.md` and `formats/compiler-artifacts.md` name `src/triage/compiler_detection.rs` as the implementation | `formats/` | `reference/formats/` | |
| C17 | Android support is **header parsing only** | `formats/android.md` | `reference/formats/android.md` | |
| C18 | The sepolicy parser "currently implements only" a subset of the format | `formats/sepolicy-policydb-format.md` | `reference/formats/` | |
| C19 | `syscalls/linux.md` states the "Current Glaurung boundary" rather than implying full syscall emulation | `syscalls/linux.md` | `reference/syscalls/linux.md` | |
| C20 | `syscalls/windows.md` names `windows_syscall_stub_atlas` and does **not** claim numbers must be resolved at runtime | `syscalls/windows.md` | `reference/syscalls/windows.md` | |
| C21 | The IOC validator doc names `python/glaurung/llm/agents/ioc_validator_v2.py` and covers "unrecognized sample kinds" | `IOC_VALIDATOR_V2.md` | `reference/ioc-validator.md` | |
| C22 | The LLM tool guide describes the real memory-tool architecture: `MemoryTool`, `MemoryContext`, `tool_to_pyd_ai`; its check command is `uv run pytest python/tests/test_tool_routing.py` | `llm/TOOLS.md` | `architecture/llm-subsystem.md` | |
| C23 | No `gpt-4` anywhere in the LLM tool guide, and no `create_binary_analysis_agent_with_tools` (the symbol does not exist) | `llm/TOOLS.md` | `architecture/llm-subsystem.md` | the model policy is `openai:gpt-5.4-mini` (`CLAUDE.md`) |
| C24 | No `unittest.mock` / `MagicMock` in user-facing doc or example code | `llm/TOOLS.md`, `examples/` | wherever the examples land | the `examples/` half is still enforced by the surviving `test_python_examples_use_real_inputs_and_current_candidate_bound_language` |
| C25 | The Windows analysis config guide names `python/glaurung/windows_config.py` | `windows-port/windows-analysis-config.md` | `reference/windows-analysis-config.md` | |
| C26 | The type-sync guide uses the repository entry point `uv run glaurung types sync --offline`, never a bare `glaurung types sync` | `windows-port/windows-api-type-sync.md` | `reference/windows-api-type-sync.md` | same "repository entry point" rule the surviving ergonomics test enforces |
| C27 | The Windows index presents "generated, revision-bound snapshots" as distinct from live guidance | `windows-port/README.md` | `guides/windows-analysis.md` | and the tools row is wrong today: 113 `windows_*.py` tool files exist (plan §1.1 row 20) |
| C28 | Similarity examples use a real corpus binary (`hello-gcc-O2`) and do not mention a `digest_list` API | `triage/similarity.md` | `reference/similarity.md` | |
| C29 | Packer config examples import the real module (`from glaurung import triage`) | `triage/packer-config.md` | `reference/packer-config.md` | |
| C30 | `docs/README.md` indexes every top-level directory and does not link records as guidance | `docs/README.md` | `docs/README.md` | today it omits three directories (plan §1.1 row 29); `test_docs_manifest.py` enforces the history half |
| C31 | The disassembly reference does not carry the 2025 competitor survey material ("Quantum computing", "Zydis") | `analysis/disassembly/README.md` | `reference/disassembly.md` | the same survey problem is why ~470 lines of `analysis/decompiler/README.md` are deleted (plan §4) |
| C32 | `axeyum-integration/README.md` records that the solver backend is **opt-in** and names `solver-axeyum` and the `LogicalAnd` history | `axeyum-integration/README.md` | `architecture/solver-backends.md` | drop `Current source gate: failing`; it was fixed in `114a5c4c` |

## Still enforced by tests, not by this file

These stayed in `test_verify_tutorial.py` and need no rescuing — only new
paths when Phase 2 moves their targets (the paths are module-level constants
at the top of that file for exactly this reason):

- `test_agent_workflow_docs_use_current_safe_cli_contract` — tier-5 chapters
  keep `kickoff --db`, `ask --route -a`, `--max-cost-usd`, the in-memory-KB
  sentence, the best-effort-logging sentence, and no `/nas4/` paths.
- `test_ask_reference_tracks_current_cli_contract` — `docs/cli/ASK_COMMAND.md`
  keeps `openai:gpt-5.4-mini`, `--route`, `--max-cost-usd`, `--findings-json`,
  the `plain` default, and no `openai:gpt-4`.
- `test_demos_are_verified_workflows_not_synthesized_agent_transcripts` —
  demos link real fixtures and contain no invented model transcript.
- `test_analyst_ergonomics_examples_use_repository_entrypoint` — every example
  is `uv run glaurung …`.
- `test_python_examples_use_real_inputs_and_current_candidate_bound_language` —
  `examples/` runs from the install against real corpus binaries.
