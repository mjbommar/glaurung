"""Tests for generic per-tool evidence recording (#208 generic).

Every memory tool wrapped via tool_to_pyd_ai now writes an
evidence_log row when invoked from a context with a persistent KB.
The wrapper does this transparently — no per-tool changes needed.
"""

from __future__ import annotations

from pathlib import Path

import pytest


_HELLO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_summary_for_tool_picks_view_hex_shape() -> None:
    """The summary helper produces a meaningful one-liner for known
    tool result shapes (so the cite table reads cleanly)."""
    from glaurung.llm.tools.base import _summary_for_tool

    s = _summary_for_tool(
        "view_hex",
        args={"va": 0x12d0, "length": 32},
        output={"length": 32, "bytes_hex": "554889e5..."},
    )
    assert "view_hex: 32b @ 0x12d0" == s


def test_summary_for_tool_picks_scan_until_byte_shape() -> None:
    from glaurung.llm.tools.base import _summary_for_tool

    s = _summary_for_tool(
        "scan_until_byte",
        args={"file_offset": 0x100},
        output={"found": True, "sentinel_value": 0x00, "sentinel_offset": 0x150},
    )
    assert "hit 0x00" in s
    assert "off 336" in s or "0x150" in s.lower()  # implementation can pick either


def test_summary_for_tool_handles_failure_shape() -> None:
    from glaurung.llm.tools.base import _summary_for_tool

    s = _summary_for_tool(
        "scan_until_byte",
        args={"file_offset": 0},
        output={"found": False, "bytes_consumed": 4096, "sentinel_value": None},
    )
    assert "no sentinel within 4096" in s


def test_evidence_recorded_when_kb_is_persistent(tmp_path: Path) -> None:
    """Run a real memory tool through the agent wrapper against a
    persistent KB; verify an evidence_log row lands."""
    from glaurung.llm.context import Budgets, MemoryContext
    from glaurung.llm.kb.adapters import import_triage
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase
    from glaurung.llm.kb import xref_db
    from glaurung.llm.tools.base import tool_to_pyd_ai
    from glaurung.llm.tools.scan_until_byte import build_tool

    import glaurung as g

    binary = _need(_HELLO)
    db = tmp_path / "ev.glaurung"
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)

    # Build a MemoryContext that points at the persistent KB.
    art = g.triage.analyze_path(str(binary), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(
        file_path=str(binary), artifact=art, budgets=Budgets(max_read_bytes=4096),
        kb=kb,
    )
    import_triage(kb, art, str(binary))

    # Invoke the tool the way the agent does — through tool_to_pyd_ai.
    pyd_tool = tool_to_pyd_ai(build_tool())

    # Synth a RunContext-like wrapper with `.deps`. pydantic-ai's
    # RunContext is a dataclass we can construct directly.
    from pydantic_ai import RunContext

    run_ctx = RunContext[MemoryContext](
        deps=ctx, model="test", usage=None, prompt="", tool_call_id=None,
    )
    pyd_tool.function(run_ctx, file_offset=0, max_scan_bytes=128)

    # Evidence row should have landed for tool "scan_until_byte".
    rows = xref_db.list_evidence(kb, tool="scan_until_byte")
    assert rows, "expected at least one scan_until_byte evidence row"
    assert rows[0].tool == "scan_until_byte"
    assert "scan_until_byte" in rows[0].summary
    # Args round-tripped.
    assert rows[0].args.get("max_scan_bytes") == 128
    kb.close()
