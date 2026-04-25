"""Tests for write_readme_and_manpage tool — heuristic + fallback contract (Bug N)."""

from __future__ import annotations

import pytest

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.store import KnowledgeBase
from glaurung.llm.tools.write_readme_and_manpage import (
    DocumentationBundle,
    ModuleDescription,
    WriteReadmeAndManpageArgs,
    WriteReadmeAndManpageResult,
    WriteReadmeAndManpageTool,
    _heuristic,
)


def _args(**overrides) -> WriteReadmeAndManpageArgs:
    base = dict(
        project_name="test_project",
        synopsis="test_project [OPTIONS]",
        description="A recovered project for testing the docs pipeline.",
        modules=[
            ModuleDescription(path="main.c", purpose="program entry point"),
            ModuleDescription(path="src/core.c", purpose="program body"),
        ],
        flags=[],
        build_instructions="cmake -B build && cmake --build build",
        target_language="c",
        manpage_section="1",
        use_llm=False,
    )
    base.update(overrides)
    return WriteReadmeAndManpageArgs(**base)


def test_heuristic_produces_complete_readme_bundle() -> None:
    """The deterministic heuristic must produce a fully-shaped bundle —
    project name, synopsis, build steps, and module tour all present."""
    docs = _heuristic(_args())
    assert isinstance(docs, DocumentationBundle)
    assert docs.readme.startswith("# test_project")
    assert "## Synopsis" in docs.readme
    assert "test_project [OPTIONS]" in docs.readme
    assert "## Build" in docs.readme
    assert "cmake -B build" in docs.readme
    assert "## Modules" in docs.readme
    assert "main.c" in docs.readme
    assert "src/core.c" in docs.readme
    # Manpage shape: NAME / SYNOPSIS / DESCRIPTION / SEE ALSO sections.
    assert ".TH" in docs.manpage or ".SH NAME" in docs.manpage


def test_tool_returns_valid_result_with_use_llm_false(tmp_path) -> None:
    """When use_llm=False, the tool must short-circuit to the heuristic
    and still return a properly-shaped WriteReadmeAndManpageResult.
    The recover_source orchestrator's `doc.docs.readme` access must not
    fail in this path (Bug N)."""
    import glaurung as g

    fake = tmp_path / "fake.bin"
    fake.write_bytes(b"\x7fELF" + b"\x00" * 100)
    art = g.triage.analyze_path(str(fake), str_min_len=3)
    ctx = MemoryContext(file_path=str(fake), artifact=art)
    res = WriteReadmeAndManpageTool().run(ctx, KnowledgeBase(), _args())
    assert isinstance(res, WriteReadmeAndManpageResult)
    assert res.source == "heuristic"
    # The orchestrator does `doc.docs.readme` — that must work.
    assert res.docs.readme.startswith("# test_project")
    assert res.docs.manpage  # non-empty


def test_heuristic_handles_minimal_inputs() -> None:
    """Empty modules / flags / description must still produce a usable
    README — the orchestrator falls back to this on tool failure, so it
    has to survive sparse inputs."""
    docs = _heuristic(_args(modules=[], flags=[], description=""))
    # Title + synopsis still present even with no modules / no description.
    assert "# test_project" in docs.readme
    assert "test_project [OPTIONS]" in docs.readme
    # No "## Modules" section emitted when there are zero modules.
    assert "## Modules" not in docs.readme


def test_orchestrator_helper_falls_back_when_tool_raises(
    tmp_path, monkeypatch
) -> None:
    """When WriteReadmeAndManpageTool.run raises, _emit_readme_with_fallback
    must still return a fully-shaped result with a non-empty README — the
    project must never ship with a missing docs file (Bug N)."""
    import importlib.util
    import glaurung as g

    spec = importlib.util.spec_from_file_location(
        "recover_source",
        "scripts/recover_source.py",
    )
    rs = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(rs)

    # Force the tool to raise — simulates Bug I (wrong-shape return,
    # validation error, transient pydantic-ai failure, etc.).
    def _raise(*a, **kw):
        raise RuntimeError("simulated tool failure")
    monkeypatch.setattr(
        "glaurung.llm.tools.write_readme_and_manpage."
        "WriteReadmeAndManpageTool.run",
        _raise,
    )

    fake = tmp_path / "fake.bin"
    fake.write_bytes(b"\x7fELF" + b"\x00" * 100)
    art = g.triage.analyze_path(str(fake), str_min_len=3)
    ctx = MemoryContext(file_path=str(fake), artifact=art)
    doc = rs._emit_readme_with_fallback(ctx, _args(use_llm=True))
    assert doc.source == "heuristic"
    assert doc.docs.readme.startswith("# test_project")
    assert doc.docs.manpage  # non-empty


def test_orchestrator_helper_falls_back_when_tool_returns_bad_shape(
    tmp_path, monkeypatch
) -> None:
    """When WriteReadmeAndManpageTool.run returns something without a
    `.docs.readme` attr (e.g. raw string from a confused LLM that survives
    the run_structured_llm sanity check), the orchestrator must still
    emit the heuristic README rather than skip docs entirely."""
    import importlib.util
    import glaurung as g

    spec = importlib.util.spec_from_file_location(
        "recover_source",
        "scripts/recover_source.py",
    )
    rs = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(rs)

    monkeypatch.setattr(
        "glaurung.llm.tools.write_readme_and_manpage."
        "WriteReadmeAndManpageTool.run",
        lambda *a, **kw: "this is not a result object",
    )

    fake = tmp_path / "fake.bin"
    fake.write_bytes(b"\x7fELF" + b"\x00" * 100)
    art = g.triage.analyze_path(str(fake), str_min_len=3)
    ctx = MemoryContext(file_path=str(fake), artifact=art)
    doc = rs._emit_readme_with_fallback(ctx, _args(use_llm=True))
    assert doc.source == "heuristic"
    assert "# test_project" in doc.docs.readme
