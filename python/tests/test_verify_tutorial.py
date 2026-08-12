"""Integration tests for the checked-in tutorial verification harness."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts import verify_tutorial

ROOT = Path(__file__).resolve().parents[2]
INSTALL_FIXTURES = ROOT / "docs" / "tutorial" / "_fixtures" / "01-install"
TIER5 = ROOT / "docs" / "tutorial" / "05-agent-workflows"
ASK_DOC = ROOT / "docs" / "cli" / "ASK_COMMAND.md"
ERGONOMICS_DOC = ROOT / "docs" / "cli" / "analyst-ergonomics.md"
DEMOS = ROOT / "docs" / "demos"
LLM_DOCS = ROOT / "docs" / "llm"
TRIAGE_DOCS = ROOT / "docs" / "triage"
PARSER_DOCS = ROOT / "docs" / "parsers"
ANALYSIS_DOCS = ROOT / "docs" / "analysis"
ARCHITECTURE_DOCS = ROOT / "docs" / "architecture"
DEVELOPMENT_DOCS = ROOT / "docs" / "development"
FORMATS_DOCS = ROOT / "docs" / "formats"
SYSCALL_DOCS = ROOT / "docs" / "syscalls"
AXEYUM_DOCS = ROOT / "docs" / "axeyum-integration"
AGENTIC_DOCS = ROOT / "docs" / "agentic-glaurung"
WINDOWS_DOCS = ROOT / "docs" / "windows-port"
EXAMPLES = ROOT / "examples"


def test_run_preserves_nonzero_exit_status() -> None:
    """Harness callers must be able to reject failed documented commands."""
    result = verify_tutorial.run(
        ["bash", "-c", "printf 'documented command failed'; exit 7"]
    )

    assert result.returncode == 7
    assert result.output == "documented command failed"


def test_stable_strips_trailing_whitespace_without_losing_lines() -> None:
    """Captured text must remain suitable for clean checked-in diffs."""
    assert verify_tutorial.stable("name  \nvalue\t\n") == "name\nvalue\n"


def test_stable_normalizes_persisted_epoch_timestamps() -> None:
    """Bookmark JSON fixtures must not drift merely because time advanced."""
    assert (
        verify_tutorial.stable('{"created_at":1786143430}\n')
        == '{"created_at":"TIMESTAMP"}\n'
    )


def test_packed_detection_requires_its_documented_signal_exit() -> None:
    """A positive packer verdict is exit 1, while normal steps require zero."""
    assert verify_tutorial.expected_return_codes("03-upx-packed", "detect-packer") == {
        1
    }
    assert verify_tutorial.expected_return_codes("03-upx-packed", "kickoff") == {0}


def test_binary_diff_requires_the_documented_changed_signal() -> None:
    """The patch-analysis fixture must keep reporting a binary difference."""
    assert verify_tutorial.expected_return_codes("04-diff", "diff") == {1}


def test_stable_normalizes_only_benchmark_table_latency() -> None:
    """Bench milliseconds drift, while unrelated numeric table cells remain."""
    bench = (
        "| binary | funcs | named | chunks>1 | cold orphans | decompiled | ms |\n"
        "|---|---:|---:|---:|---:|---:|---:|\n"
        "| `hello` | 16 | 9 | 0 | 0 | 16/16 | 1323 |\n"
    )
    assert verify_tutorial.stable(bench).endswith(
        "| `hello` | 16 | 9 | 0 | 0 | 16/16 | N |\n"
    )
    assert verify_tutorial.stable("| `fn` | 151 | 151 |\n") == (
        "| `fn` | 151 | 151 |\n"
    )


def test_check_mode_does_not_rewrite_install_fixtures() -> None:
    """Checking a real chapter must leave its evidence files byte-identical."""
    before = {path: path.read_bytes() for path in INSTALL_FIXTURES.glob("*.out")}
    assert before

    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_tutorial.py",
            "--check",
            "--chapter",
            "01-install",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert {path: path.read_bytes() for path in before} == before


def test_agent_workflow_docs_use_current_safe_cli_contract() -> None:
    """Tier 5 must distinguish persistent evidence from standalone Q&A."""
    kickoff = (TIER5 / "one-shot-kickoff.md").read_text()
    chat = (TIER5 / "chat-driven-triage.md").read_text()
    evidence = (TIER5 / "evidence-and-citations.md").read_text()

    assert 'uv run glaurung kickoff "$BIN" --db "$DB"' in kickoff
    assert 'uv run glaurung ask "$BIN" --route -a' in chat
    assert "--max-cost-usd" in chat
    assert "standalone `ask` uses an in-memory knowledge base" in chat
    assert "Persistent logging is best-effort" in evidence
    assert "/nas4/" not in f"{kickoff}\n{chat}\n{evidence}"


def test_ask_reference_tracks_current_cli_contract() -> None:
    """The maintained ask reference must not preserve the GPT-4-era interface."""
    text = ASK_DOC.read_text()

    assert "uv run glaurung ask" in text
    assert "openai:gpt-5.4-mini" in text
    assert "default output format is `plain`" in text
    assert "--route" in text
    assert "--max-cost-usd" in text
    assert "--findings-json" in text
    assert "in-memory knowledge base" in text
    assert "openai:gpt-4" not in text


def test_demos_are_verified_workflows_not_synthesized_agent_transcripts() -> None:
    """User-facing demos must link real fixtures and avoid invented model output."""
    pages = [path.read_text() for path in sorted(DEMOS.glob("*.md"))]
    text = "\n".join(pages)

    assert "uv run glaurung" in text
    assert "tutorial/_fixtures/03-c2-demo" in text
    assert "tutorial/_fixtures/03-vulnparse" in text
    assert "tutorial/_fixtures/04-diff" in text
    assert "$ glaurung" not in text
    assert "The agent's verdict" not in text
    assert "PoC input" not in text
    assert "Output (verbatim" not in text


def test_analyst_ergonomics_examples_use_repository_entrypoint() -> None:
    """Maintained CLI examples should run against the locked environment."""
    text = ERGONOMICS_DOC.read_text()

    assert not any(line.startswith("glaurung ") for line in text.splitlines())
    for command in ("kickoff", "disasm", "locks", "group"):
        assert f"uv run glaurung {command}" in text


def test_llm_tool_guide_documents_the_current_memory_tool_architecture() -> None:
    """The maintained LLM guide must use real Glaurung APIs, not old sketches."""
    index = (LLM_DOCS / "README.md").read_text()
    tools = (LLM_DOCS / "TOOLS.md").read_text()

    assert "Current operator guides" in index
    assert "Historical and design records" in index
    for name in ("MemoryTool", "MemoryContext", "tool_to_pyd_ai"):
        assert name in tools
    assert "uv run pytest python/tests/test_tool_routing.py" in tools
    assert "gpt-4" not in tools.lower()
    assert "unittest.mock" not in tools
    assert "create_binary_analysis_agent_with_tools" not in tools


def test_triage_docs_separate_current_workflows_from_design_records() -> None:
    """Triage operator guidance must use live flags and label old proposals."""
    readme = (TRIAGE_DOCS / "README.md").read_text()
    packers = (TRIAGE_DOCS / "packer-config.md").read_text()
    similarity = (TRIAGE_DOCS / "similarity.md").read_text()

    assert readme.startswith("# Binary triage")
    assert 'uv run glaurung triage "$SAMPLE"' in readme
    assert "--max-depth" in readme
    assert "--tree" in readme
    assert "Exit status" in readme
    assert "from glaurung import triage" in packers
    assert "hello-gcc-O2" in similarity
    assert "digest_list" not in similarity

    for name in (
        "ADDITIONAL_FEATURES.md",
        "ADVANCED-FEATURES.md",
        "DETAILED_IMPLEMENTATION_PLAN.md",
        "IMPLEMENTATION.md",
        "RECOMMENDATIONS.md",
        "SIGNATURE_DESIGN.md",
    ):
        text = (TRIAGE_DOCS / name).read_text()
        assert "Status: historical design" in text[:600]


def test_parser_docs_separate_live_entrypoints_from_historical_designs() -> None:
    """The parser index must not present stale parser sketches as live APIs."""
    index = (PARSER_DOCS / "README.md").read_text()
    compact_index = " ".join(index.split())

    for command in ("triage", "classfile", "luac", "pe resources"):
        assert f"uv run glaurung {command}" in index
    assert "nested `containers`" in index
    assert "`--tree` is advertised but is not currently wired" in compact_index
    assert "There is no owned `src/formats/macho` parser module" in index

    historical = (
        "android/README.md",
        "archive/README.md",
        "dotnet/README.md",
        "elf/README.md",
        "elf-consolidation-plan.md",
        "elf-migration-guide.md",
        "elf-technical-design.md",
        "macho/README.md",
        "macho-consolidation-plan.md",
        "macho-migration-guide.md",
        "macho-technical-design.md",
        "pe-coff/README.md",
        "pe-consolidation-plan.md",
        "pe-migration-guide.md",
        "pe-technical-design.md",
        "python/README.md",
        "wasm/README.md",
    )
    for name in historical:
        text = (PARSER_DOCS / name).read_text()
        assert "Status: historical design" in text[:700], name

    assert (
        "Status: living capability ledger"
        in (PARSER_DOCS / "java" / "README.md").read_text()[:700]
    )
    assert (
        "Status: living implementation diary and roadmap"
        in (PARSER_DOCS / "java" / "JVM_AGENTIC_ANALYSIS_PLAN.md").read_text()[:700]
    )
    assert (
        "Status: historical capability plan"
        in (
            PARSER_DOCS / "pe-coff" / "WINDOWS_RESOURCES_CAPABILITIES_TEST_PLAN.md"
        ).read_text()[:700]
    )


def test_analysis_docs_publish_current_entrypoints_and_label_old_plans() -> None:
    """Core analysis docs must distinguish live commands from old proposals."""
    index = (ANALYSIS_DOCS / "README.md").read_text()
    disasm = (ANALYSIS_DOCS / "disassembly" / "README.md").read_text()
    compact_disasm = " ".join(disasm.split())
    languages = (ANALYSIS_DOCS / "language-detection" / "README.md").read_text()

    assert index.startswith("# Analysis documentation")
    for target in ("disassembly/", "language-detection/", "decompiler/"):
        assert target in index

    assert disasm.startswith("# Disassembly")
    assert 'uv run glaurung disasm "$BIN"' in disasm
    assert "`--comments` currently does not add annotations" in disasm
    assert "do not control the mapped-VA path" in compact_disasm
    assert "Quantum computing" not in disasm
    assert "Zydis" not in disasm

    assert languages.startswith("# Compiler and source-language detection")
    assert "not exposed as a standalone CLI command" in languages
    assert "cargo test compiler_detection" in languages

    for name in (
        "decompiler/pipeline.md",
        "interpreted/README.md",
        "language-detection/FAILURE_ANALYSIS.md",
        "language-detection/IMPLEMENTATION_SUMMARY.md",
        "language-detection/IMPROVEMENTS.md",
        "lifting/README.md",
        "lifting/experiments/retdec-test-2025-10-20.md",
        "symbols/ENHANCEMENTS.md",
        "symbols/IMPLEMENTATION.md",
    ):
        text = (ANALYSIS_DOCS / name).read_text()
        assert "Status: historical" in text[:700], name


def test_architecture_docs_separate_current_storage_and_types_from_proposals() -> None:
    """Current project/data contracts must not be hidden in obsolete plans."""
    docs_index = (ROOT / "docs" / "README.md").read_text()
    index = (ARCHITECTURE_DOCS / "README.md").read_text()
    project = (ARCHITECTURE_DOCS / "PERSISTENT_PROJECT.md").read_text()
    model = (ARCHITECTURE_DOCS / "data-model" / "README.md").read_text()

    assert index.startswith("# Architecture documentation")
    assert "[`analysis/`](analysis/README.md)" in docs_index
    assert "[`architecture/`](architecture/README.md)" in docs_index
    assert "[lifting](analysis/lifting/README.md)" not in docs_index
    assert project.startswith("# Persistent project databases")
    assert "PersistentKnowledgeBase.open(" in project
    assert "MemoryContext.open_persistent(" in project
    assert "migrations are not yet implemented" in project
    assert "schema version is currently `1`" in project

    assert model.startswith("# Core data model")
    for source in ("src/core/mod.rs", "src/triage/", "python/glaurung/llm/kb/"):
        assert source in model

    for name in (
        "IDA_GHIDRA_PARITY.md",
        "data-model/IMPLEMENTATION.md",
        "data-model/disassembly_decompiler_foundations.md",
        "data-model/nesting.md",
        "data-model/critique/GEMINI.md",
        "data-model/critique/GPT5.md",
        "data-model/proposals/CLAUDE.md",
        "data-model/proposals/GEMINI.md",
        "data-model/proposals/GPT5.md",
        "data-model/proposals/GROK4.md",
    ):
        text = (ARCHITECTURE_DOCS / name).read_text()
        assert "Status: historical" in text[:700], name


def test_development_docs_use_live_paths_and_explicit_status() -> None:
    """Developer guides must distinguish maintained commands from snapshots."""
    setup = (DEVELOPMENT_DOCS / "setup.md").read_text()
    structure = (DEVELOPMENT_DOCS / "project-structure.md").read_text()
    guidelines = (DEVELOPMENT_DOCS / "guidelines.md").read_text()
    testing = (DEVELOPMENT_DOCS / "decompiler-testing.md").read_text()
    curriculum = (DEVELOPMENT_DOCS / "decompiler-curriculum-corpus.md").read_text()

    assert "Status: maintained setup reference" in setup[:700]
    assert "uv sync --locked --dev" in setup
    assert "rust:1.88-bookworm" in setup

    assert "Status: maintained repository map" in structure[:700]
    assert "python/glaurung/llm/kb/" in structure
    assert "`src/kb/`" not in structure
    assert "`python/glaurung/kb/`" not in structure

    assert guidelines.startswith("# Errors and logging")
    assert "src/core/triage/errors.rs" in guidelines
    assert "`TriageRunError` does not currently exist" in guidelines
    assert "configure_logging" in guidelines

    assert "Status: maintained developer guide" in testing[:700]
    assert "tools/dectest.py --list-sets" in testing
    assert "Status: maintained corpus guide" in curriculum[:700]
    assert "results at `1525bdf0`" in curriculum

    for name in ("roadmap.md", "2026-07-27-uncommitted-work-handoff.md"):
        text = (DEVELOPMENT_DOCS / name).read_text()
        assert "Status: historical" in text[:700], name


def test_format_and_syscall_docs_separate_implementation_from_reference() -> None:
    """Format and syscall references must state their executable boundary."""
    formats_index = (FORMATS_DOCS / "README.md").read_text()
    android = (FORMATS_DOCS / "android.md").read_text()
    compiler = (FORMATS_DOCS / "compiler-artifacts.md").read_text()
    sepolicy = (FORMATS_DOCS / "sepolicy-policydb-format.md").read_text()
    syscalls_index = (SYSCALL_DOCS / "README.md").read_text()
    linux = (SYSCALL_DOCS / "linux.md").read_text()
    windows = (SYSCALL_DOCS / "windows.md").read_text()

    assert "Status: maintained reference index" in formats_index[:700]
    assert "src/triage/compiler_detection.rs" in formats_index
    assert "Status: maintained capability reference" in android[:700]
    assert "header parsing only" in android

    assert "Status: maintained implementation guide" in compiler[:700]
    assert "src/triage/compiler_detection.rs" in compiler
    assert "GCC typical prologue" not in compiler

    assert "Status: maintained implementation specification" in sepolicy[:700]
    assert "parser currently implements only" in sepolicy[:1200]

    assert "Status: maintained conceptual index" in syscalls_index[:700]
    assert "Status: maintained conceptual reference" in linux[:700]
    assert "Current Glaurung boundary" in linux
    assert "Status: maintained analysis reference" in windows[:700]
    assert "windows_syscall_stub_atlas" in windows
    assert "must resolve the number at runtime" not in windows


def test_specialized_docs_mark_live_implementation_and_historical_plans() -> None:
    """Specialized design packages must not present old plans as live state."""
    ioc = (ROOT / "docs" / "IOC_VALIDATOR_V2.md").read_text()
    pyext = (ROOT / "docs" / "research" / "pyext-separation.md").read_text()
    axeyum_index = (AXEYUM_DOCS / "README.md").read_text()

    assert "Status: maintained security design" in ioc[:700]
    assert "python/glaurung/llm/agents/ioc_validator_v2.py" in ioc
    assert "from glaurung.llm.agents import" not in ioc
    assert "unrecognized sample kinds" in ioc
    assert "Status: historical separation plan" in pyext[:700]

    assert "Status: maintained integration index" in axeyum_index[:700]
    assert "solver-axeyum" in axeyum_index
    assert "opt-in" in axeyum_index[:1800]
    assert "Today the only in-process backend" not in axeyum_index
    assert "Current source gate: failing" in axeyum_index[:2200]
    assert "LogicalAnd" in axeyum_index[:2600]

    classified = (
        "00-motivation-and-goals.md",
        "01-current-state.md",
        "02-interface-mapping.md",
        "03-architecture.md",
        "04-phased-plan.md",
        "05-risks-and-open-questions.md",
        "06-validation-and-ci.md",
        "07-decision-log.md",
        "08-concretization-policy.md",
        "09-taint-provenance-and-finding-labels.md",
        "FEEDBACK-LOG.md",
        "PAPER-NOTES.md",
        "benchmark/README.md",
        "benchmark/REVIEWER-CHECKLIST.md",
        "capture/README.md",
    )
    for name in classified:
        text = (AXEYUM_DOCS / name).read_text()
        assert "status" in text[:700].lower(), name


def test_agentic_plan_docs_are_classified_and_status_is_refreshed() -> None:
    """Agentic design pages must not read as shipped autonomous behavior."""
    classified = (
        "README.md",
        "STATUS.md",
        "PLAN.md",
        "00-current-state-and-scope.md",
        "architecture/01-runtime-and-control-loop.md",
        "architecture/02-context-evidence-and-memory.md",
        "architecture/03-tool-surface-and-contracts.md",
        "architecture/04-output-validation-and-repair.md",
        "evaluation/01-test-strategy.md",
        "evaluation/02-decbench-experiment-design.md",
        "evaluation/03-baselines-ablations-and-scorecards.md",
        "implementation/01-phased-roadmap.md",
        "implementation/02-work-breakdown.md",
        "implementation/03-file-and-api-change-map.md",
        "implementation/04-acceptance-gates.md",
        "implementation/05-risks-and-decisions.md",
        "operations/01-model-configuration-and-budgets.md",
        "operations/02-security-sandbox-and-data-policy.md",
        "operations/03-observability-provenance-and-cost.md",
        "operations/04-concurrency-checkpointing-and-recovery.md",
    )
    for name in classified:
        text = (AGENTIC_DOCS / name).read_text()
        assert "status" in text[:700].lower(), name

    status = (AGENTIC_DOCS / "STATUS.md").read_text()
    assert "Refresh audit: 2026-08-07" in status[:1500]
    assert "fcca960b" in status[:1800]
    assert "02d32c9d" in status[:1800]
    assert "source_recovery.py` remains absent" in status[:2200]


def test_windows_docs_classify_live_guides_designs_and_generated_snapshots() -> None:
    """Windows documentation must distinguish live APIs from dated evidence."""
    index = (WINDOWS_DOCS / "README.md").read_text()
    config = (WINDOWS_DOCS / "windows-analysis-config.md").read_text()
    type_sync = (WINDOWS_DOCS / "windows-api-type-sync.md").read_text()

    assert "Status: maintained capability index" in index[:700]
    assert "Document map and maturity" in index[:2200]
    assert "generated, revision-bound snapshots" in index[:3200]

    assert "Status: maintained operator guide" in config[:700]
    assert "python/glaurung/windows_config.py" in config
    assert "Status: maintained generation guide" in type_sync[:700]
    assert "uv run glaurung types sync --offline" in type_sync
    assert "\nglaurung types sync" not in type_sync

    historical = (
        "agentic-ai-functionality-roadmap.md",
        "atomic-tools.md",
        "bsim-similarity-design.md",
        "glaurung-vs-ghidra-full-debug-review.md",
        "glaurung-vs-ghidra-regression-review.md",
        "pdb-ingestion-design.md",
        "pe-hardening-design.md",
        "roadmap.md",
    )
    for name in historical:
        text = (WINDOWS_DOCS / name).read_text()
        assert "Status: historical" in text[:700], name


def test_python_examples_use_real_inputs_and_current_candidate_bound_language() -> None:
    """Examples must run from the install and avoid fabricated security proof."""
    repository_index = (ROOT / "README.md").read_text()
    documentation_index = (ROOT / "docs" / "README.md").read_text()
    index = (EXAMPLES / "README.md").read_text()
    analyze = (EXAMPLES / "analyze_with_ioc_validation.py").read_text()
    demo = (EXAMPLES / "demo_ioc_validation.py").read_text()
    contract = (EXAMPLES / "test_no_hallucination.py").read_text()
    iterative = (EXAMPLES / "iterative_analysis.py").read_text()
    triage_example = (EXAMPLES / "python_triage_examples.py").read_text()

    assert "Status: maintained example index" in index[:700]
    assert "model-backed" in index
    assert "solver-axeyum" in index
    assert "not a complete IOC inventory" in index
    assert "examples/README.md" in repository_index
    assert "../examples/README.md" in documentation_index

    for text in (analyze, demo, contract, iterative):
        assert "sys.path.insert" not in text

    assert "(TypeError, Exception)" not in analyze
    assert "CONFIRMED IOCs" not in analyze
    assert "model-accepted candidates" in analyze

    assert "ioc_validator_v2" in demo
    assert "mock" not in demo.lower()
    assert "c2_demo-gcc-O0" in demo

    assert "MagicMock" not in contract
    assert "unittest.mock" not in contract
    assert "candidate-bound" in contract
    assert "c2_demo-gcc-O0" in contract

    assert 'binary_path = "/bin/ls"' not in iterative
    assert "hello-gcc-O2" in iterative
    assert "g.analyze_env" not in triage_example
