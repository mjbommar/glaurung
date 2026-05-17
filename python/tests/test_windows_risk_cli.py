"""Tests for the Windows risk triage CLI."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from types import SimpleNamespace

import glaurung as g


def test_windows_risk_json_reports_parser_shape(
    monkeypatch,
    tmp_path,
) -> None:
    from glaurung.cli.main import GlaurungCLI

    binary = tmp_path / "sample.dll"
    binary.write_bytes(b"MZ")

    def fake_list_symbols(
        _path: str, *_args: object
    ) -> tuple[list, list, list, list, list]:
        return (
            [],
            [],
            [
                "KERNEL32.dll!CreateFileW",
                "KERNEL32.dll!ReadFile",
                "KERNEL32.dll!LocalAlloc",
                "ADVAPI32.dll!RegSetValueExW",
            ],
            [],
            [],
        )

    def fake_analyze_path(_path: str, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            strings=SimpleNamespace(
                strings=[
                    SimpleNamespace(
                        offset=0x200,
                        encoding="ascii",
                        text="MigrateModemSettings: ReadFile failed",
                    )
                ]
            )
        )

    def fake_analyze_functions_path(
        _path: str, **_kwargs: object
    ) -> tuple[list, object]:
        func = SimpleNamespace(
            name="sub_1000",
            entry_point=SimpleNamespace(value=0x1000),
            basic_blocks=[SimpleNamespace(instruction_count=16)],
            size=0x80,
        )
        return [func], SimpleNamespace(edges=[])

    monkeypatch.setattr(g.triage, "list_symbols", fake_list_symbols)
    monkeypatch.setattr(g.triage, "analyze_path", fake_analyze_path)
    monkeypatch.setattr(
        g.analysis,
        "detect_entry_path",
        lambda *_args, **_kwargs: ("PE", "x86_64", "little", 0x1000, 0),
    )
    monkeypatch.setattr(
        g.analysis, "analyze_functions_path", fake_analyze_functions_path
    )
    monkeypatch.setattr(
        g.analysis,
        "data_xrefs_path",
        lambda *_args, **_kwargs: [(0x1010, 0x402000, 0x1000)],
    )
    monkeypatch.setattr(
        g.analysis,
        "va_to_file_offset_path",
        lambda *_args, **_kwargs: 0x200,
    )
    monkeypatch.setattr(
        g.ir,
        "decompile_at",
        lambda *_args, **_kwargs: (
            "fn sub_1000 { CreateFileW(); ReadFile(); "
            "LocalAlloc(); ReadFile(); RegSetValueExW(); }"
        ),
    )

    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["windows-risk", str(binary), "--format", "json"])

    assert rc == 0
    report = json.loads(buf.getvalue())
    assert report["summary"]["format"] == "PE"
    assert report["summary"]["function_count"] == 1
    assert "file_io" in report["risk_imports"]
    assert any(
        item["kind"] == "file-read-allocation-parser" for item in report["risk_items"]
    )
    assert any(item["kind"] == "function-string-xrefs" for item in report["risk_items"])
    assert report["functions"][0]["strings"][0]["text"].startswith(
        "MigrateModemSettings"
    )


def test_windows_risk_plain_no_decompile_still_reports_imports(
    monkeypatch,
    tmp_path,
) -> None:
    from glaurung.cli.main import GlaurungCLI

    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")

    monkeypatch.setattr(
        g.triage,
        "list_symbols",
        lambda *_args, **_kwargs: (
            [],
            [],
            ["KERNEL32.dll!LoadLibraryW", "KERNEL32.dll!GetProcAddress"],
            [],
            [],
        ),
    )
    monkeypatch.setattr(
        g.triage,
        "analyze_path",
        lambda *_args, **_kwargs: SimpleNamespace(strings=SimpleNamespace(strings=[])),
    )
    monkeypatch.setattr(
        g.analysis,
        "detect_entry_path",
        lambda *_args, **_kwargs: ("PE", "x86", "little", 0x401000, 0),
    )
    monkeypatch.setattr(
        g.analysis,
        "analyze_functions_path",
        lambda *_args, **_kwargs: ([], SimpleNamespace(edges=[])),
    )
    monkeypatch.setattr(g.analysis, "data_xrefs_path", lambda *_args, **_kwargs: [])

    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["windows-risk", str(binary), "--no-decompile"])

    assert rc == 0
    out = buf.getvalue()
    assert "Windows Risk Summary" in out
    assert "dynamic_loading" in out
    assert "LoadLibraryW" in out


def test_windows_risk_report_tool_uses_context_file(
    monkeypatch,
    tmp_path,
) -> None:
    from glaurung.llm.context import Budgets, MemoryContext
    from glaurung.llm.tools import windows_risk_report as tool_mod

    binary = tmp_path / "sample.dll"
    binary.write_bytes(b"MZ")
    seen = {}

    def fake_report(path, args):
        seen["path"] = str(path)
        seen["max_read_bytes"] = args.max_read_bytes
        seen["max_candidates"] = args.max_candidates
        return {
            "summary": {
                "path": str(path),
                "format": "PE",
                "arch": "x86_64",
                "function_count": 1,
                "function_rows": 1,
                "import_count": 1,
                "string_count": 1,
                "data_xref_count": 1,
            },
            "risk_imports": {"file_io": ["ReadFile"]},
            "risk_items": [
                {
                    "kind": "file-read-allocation-parser",
                    "severity": "high",
                    "summary": "parser shape",
                    "evidence": ["ReadFile"],
                    "function_va": 0x1000,
                }
            ],
            "functions": [
                {
                    "name": "sub_1000",
                    "entry_va": 0x1000,
                    "score": 10,
                    "api_hits": ["ReadFile"],
                    "patterns": ["file-read-allocation-parser"],
                    "strings": [],
                }
            ],
        }

    monkeypatch.setattr(tool_mod, "_build_report", fake_report)
    ctx = MemoryContext(
        file_path=str(binary),
        artifact=SimpleNamespace(),
        budgets=Budgets(max_read_bytes=1234, max_file_size=5678),
    )
    tool = tool_mod.build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(max_candidates=3, no_decompile=True),
    )

    assert seen == {
        "path": str(binary),
        "max_read_bytes": 1234,
        "max_candidates": 3,
    }
    assert result.summary["format"] == "PE"
    assert result.risk_items[0]["kind"] == "file-read-allocation-parser"


def test_memory_agent_registers_windows_risk_report() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_risk_report" in agent._function_toolset.tools
