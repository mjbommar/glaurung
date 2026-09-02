"""Integration tests for the checked-in tutorial verification harness.

Two kinds of test live here, and the distinction matters.

The first seven are **harness** tests: they exercise
`scripts/verify_tutorial.py` itself -- exit-status propagation, the
normalizations `stable()` applies, the per-step expected return codes, and the
guarantee that `--check` never rewrites the evidence it is checking.

The rest are **behavioral doc** tests: a maintained document has to state
something true about how the CLI behaves, because a reader who follows the
document without it is misled. They assert contracts, not classification.

This file used to carry ten more tests that pinned banner text, a refresh
date, and two commit SHAs across roughly a hundred files under `docs/`. That
made the documentation tree unmovable and, in one case, required a document to
keep saying a build was failing after the build was fixed. Structure is now
checked by `test_docs_manifest.py` (every file declares its kind) and
`test_docs_links.py` (every path resolves); the behavioral claims worth
keeping were written down in
`docs/development/docs-audit-2026-09-02/contract-assertions.md`.

Document paths are module-level constants so the documentation reorganization
can re-point them in one place.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts import verify_tutorial

ROOT = Path(__file__).resolve().parents[2]
INSTALL_FIXTURES = ROOT / "docs" / "tutorial" / "_fixtures" / "01-install"
TIER5 = ROOT / "docs" / "tutorial" / "05-agent-workflows"
ASK_DOC = ROOT / "docs" / "guides" / "ask.md"
ERGONOMICS_DOC = ROOT / "docs" / "guides" / "analyst-workflows.md"
DEMOS = ROOT / "docs" / "guides" / "demos"
DOCS_INDEX = ROOT / "docs" / "README.md"
REPOSITORY_INDEX = ROOT / "README.md"
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


def test_python_examples_use_real_inputs_and_current_candidate_bound_language() -> None:
    """Examples must run from the install and avoid fabricated security proof."""
    repository_index = REPOSITORY_INDEX.read_text()
    documentation_index = DOCS_INDEX.read_text()
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
