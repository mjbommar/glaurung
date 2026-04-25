"""Tests for the kickoff_analysis composite tool (#206)."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from glaurung.llm.kb.kickoff import kickoff_analysis, render_kickoff_markdown


_HELLO_DEBUG = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)
_C2_DEMO = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing path {p}")
    return p


def test_kickoff_runs_full_pipeline_on_c2_demo(tmp_path: Path) -> None:
    """End-to-end: c2_demo-clang-O0 calls many libc functions with
    stack-allocated args. The kickoff pipeline should report:
      - not packed
      - several discovered functions, all named (clang -O0 has symbols)
      - prototypes auto-loaded (libc + winapi bundles)
      - stack slots discovered
      - some types propagated (libc-arg matching)
    All without the user issuing 6 separate tool calls."""
    binary = _need(_C2_DEMO)
    db = tmp_path / "kickoff.glaurung"
    summary = kickoff_analysis(str(binary), db_path=str(db))

    # Packer detection: clean.
    assert summary.packer["is_packed"] is False
    # Triage: ELF / x86_64.
    assert summary.format == "ELF"
    assert summary.arch == "x86_64"
    # Functions.
    assert summary.functions_total >= 4
    assert summary.functions_named == summary.functions_total  # all symbol-named
    # Type system.
    assert summary.stdlib_prototypes_loaded >= 100, (
        "stdlib bundles should auto-load via auto_load_stdlib=True"
    )
    assert summary.stack_slots_discovered > 0
    # Type propagation should fire on c2_demo (libc-call density).
    assert summary.types_propagated > 0


def test_kickoff_short_circuits_on_packed_binary(tmp_path: Path) -> None:
    """A binary that detect_packer flags should skip deep analysis
    (and report why) when skip_if_packed=True. We don't have a real
    packed sample, so synthesize one with UPX magic bytes."""
    fake = tmp_path / "fake-upx.bin"
    fake.write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100
        + b"$Info: This file is packed with the UPX executable packer "
        + b"http://upx.sf.net" + b"\x00" * 1024
    )
    db = tmp_path / "kickoff.glaurung"
    summary = kickoff_analysis(str(fake), db_path=str(db), skip_if_packed=True)
    assert summary.packer["is_packed"] is True
    # Deep analysis was skipped — function count stays at zero.
    assert summary.functions_total == 0
    # Should explain why.
    assert any("packed" in n.lower() for n in summary.notes)


def test_kickoff_handles_missing_file_cleanly(tmp_path: Path) -> None:
    bogus = tmp_path / "definitely-not-a-real-binary.bin"
    summary = kickoff_analysis(str(bogus), db_path=str(tmp_path / "x.glaurung"))
    assert summary.functions_total == 0
    assert any("not found" in n for n in summary.notes)


def test_kickoff_renders_markdown_summary(tmp_path: Path) -> None:
    binary = _need(_HELLO_DEBUG)
    db = tmp_path / "kickoff.glaurung"
    summary = kickoff_analysis(str(binary), db_path=str(db))
    md = render_kickoff_markdown(summary)
    assert "Kickoff analysis" in md
    assert "Functions" in md
    assert "Type system" in md
    # Latency footer.
    assert "completed in" in md


def test_kickoff_records_evidence_row(tmp_path: Path) -> None:
    """The kickoff invocation should leave a citable evidence_log row
    so the chat UI can render the first-turn summary as an
    expandable pane."""
    from glaurung.llm.kb import xref_db
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    binary = _need(_C2_DEMO)
    db = tmp_path / "kickoff-cite.glaurung"
    summary = kickoff_analysis(str(binary), db_path=str(db))
    assert summary.cite_id is not None
    assert summary.cite_id >= 1

    # Reopen the KB and pull the evidence row back.
    kb = PersistentKnowledgeBase.open(db, binary_path=binary)
    rec = xref_db.get_evidence(kb, summary.cite_id)
    assert rec is not None
    assert rec.tool == "kickoff_analysis"
    assert "kickoff:" in rec.summary
    # Output carries the same numbers the summary reports.
    assert rec.output["functions_total"] == summary.functions_total
    assert rec.output["stack_slots_discovered"] == summary.stack_slots_discovered
    kb.close()


def test_kickoff_cli_subcommand(tmp_path: Path) -> None:
    """Smoke-test `glaurung kickoff <binary>`."""
    from glaurung.cli.main import GlaurungCLI

    binary = _need(_C2_DEMO)
    db = tmp_path / "kickoff-cli.glaurung"

    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["kickoff", str(binary), "--db", str(db)])
    out = buf.getvalue()
    assert rc == 0
    assert "Kickoff analysis" in out
    assert "stack slots discovered" in out
