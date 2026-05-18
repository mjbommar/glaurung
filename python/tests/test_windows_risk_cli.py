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
                "KERNEL32.dll!WriteFile",
                "KERNEL32.dll!DeleteFileW",
                "KERNEL32.dll!GetTempPathW",
                "KERNEL32.dll!GetTempFileNameW",
                "KERNEL32.dll!LocalAlloc",
                "KERNEL32.dll!FindResourceW",
                "KERNEL32.dll!SizeofResource",
                "KERNEL32.dll!LoadResource",
                "KERNEL32.dll!LockResource",
                "ADVAPI32.dll!RegSetValueExW",
                "msvcrt.dll!wcscpy",
                "msvcrt.dll!swprintf",
                "WS2_32.dll!WSAStartup",
                "WS2_32.dll!socket",
                "WS2_32.dll!connect",
                "WS2_32.dll!send",
                "WINHTTP.dll!WinHttpOpen",
                "WINHTTP.dll!WinHttpConnect",
                "WINHTTP.dll!WinHttpOpenRequest",
                "WINHTTP.dll!WinHttpSendRequest",
            ],
            ["sample_export"],
            ["KERNEL32.dll"],
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
        helper = SimpleNamespace(
            name="helper",
            entry_point=SimpleNamespace(value=0x2000),
            basic_blocks=[SimpleNamespace(instruction_count=4)],
            size=0x20,
        )
        edge = SimpleNamespace(
            caller="sub_1000",
            callee="helper",
            call_type=SimpleNamespace(value=lambda: "direct"),
            call_sites=[SimpleNamespace(value=0x1020)],
        )
        return [func, helper], SimpleNamespace(edges=[edge])

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
        g.analysis,
        "pe_list_resources_path",
        lambda *_args, **_kwargs: {
            "leaf_count": 2,
            "total_directories": 3,
            "total_entries": 5,
            "resource_bytes_total": 128,
            "resources_by_type": {"VERSIONINFO": 1, "MANIFEST": 1},
            "truncated": False,
            "warnings": [],
            "stop_reasons": [],
        },
        raising=False,
    )
    monkeypatch.setattr(
        g.analysis,
        "pe_view_resource_path",
        lambda *_args, **_kwargs: None,
        raising=False,
    )
    monkeypatch.setattr(
        g.analysis,
        "pe_tls_path",
        lambda *_args, **_kwargs: {
            "has_tls": True,
            "has_callbacks": True,
            "callback_count": 1,
            "address_of_callbacks": 0x402000,
            "callbacks": [0x401000],
            "callback_rvas": [0x1000],
            "truncated": False,
            "stop_reasons": [],
        },
        raising=False,
    )
    monkeypatch.setattr(
        g.ir,
        "decompile_at",
        lambda *_args, **_kwargs: (
            "fn sub_1000 { tmp = (rbp - 128); CreateFileW(); "
            "ReadFile(var3, (rbp - 128), 4); LocalAlloc(64, stack_9); "
            "var6 = ret; L_1010: arg2 = stack_9; arg3 = (rsp + 64); "
            "ReadFile(var3, var6); hres = FindResourceW(0, 0x401000, 10); "
            "size = SizeofResource(0, hres); loaded = LoadResource(0, hres); "
            "LockResource(loaded); wcscpy(var6, var4); "
            "swprintf((rbp - 256), 0x180050000); "
            "GetTempPathW(260, (rbp - 520)); "
            "GetTempFileNameW((rbp - 520), 0x180050010, 0, (rbp - 1040)); "
            "WriteFile(var3, var6, stack_9, (rsp + 64)); "
            "DeleteFileW((rbp - 1040)); WSAStartup(514, (rbp - 1400)); "
            "sock = socket(2, 1, 6); connect(sock, (rbp - 1600), 16); "
            "send(sock, var6, stack_9, 0); "
            "session = WinHttpOpen(0x180050020, 0, 0, 0, 0); "
            "conn = WinHttpConnect(session, 0x180050040, 443, 0); "
            "req = WinHttpOpenRequest(conn, 0x180050060, 0x180050080, 0, 0, 0, 0); "
            "WinHttpSendRequest(req, 0, 0, 0, 0, 0, 0); RegSetValueExW(); }"
        ),
    )

    cli = GlaurungCLI()
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.run(["windows-risk", str(binary), "--format", "json"])

    assert rc == 0
    report = json.loads(buf.getvalue())
    assert report["summary"]["format"] == "PE"
    assert report["summary"]["function_count"] == 2
    assert report["summary"]["export_count"] == 1
    assert report["pe_metadata"]["resources"]["resources_by_type"] == {
        "VERSIONINFO": 1,
        "MANIFEST": 1,
    }
    assert report["pe_metadata"]["tls"]["callback_count"] == 1
    assert report["functions"][0]["call_count"] == 1
    assert report["functions"][0]["calls"][0] == {
        "target": "helper",
        "target_va": 0x2000,
        "kind": "direct",
        "call_sites": [0x1020],
    }
    assert "ReadFile" in report["functions"][0]["imports"]
    assert report["functions"][0]["api_sequence"][:4] == [
        "CreateFileW",
        "ReadFile",
        "LocalAlloc",
        "ReadFile",
    ]
    read_call = next(
        call
        for call in report["functions"][0]["api_calls"]
        if call["name"] == "ReadFile"
    )
    assert read_call["return_type"] == "BOOL"
    assert read_call["args"][1] == {
        "index": 1,
        "expr": "(rbp - 128)",
        "param": "lpBuffer",
        "type": "LPVOID",
        "role": "buffer",
    }
    assert read_call["args"][2] == {
        "index": 2,
        "expr": "4",
        "param": "nNumberOfBytesToRead",
        "type": "DWORD",
        "role": "length",
        "value": 4,
        "hex": "0x4",
    }
    alloc_call = next(
        call
        for call in report["functions"][0]["api_calls"]
        if call["name"] == "LocalAlloc"
    )
    assert alloc_call["args"][1]["param"] == "uBytes"
    assert alloc_call["args"][1]["role"] == "length"
    sized_read = next(
        call
        for call in report["functions"][0]["api_calls"]
        if call["name"] == "ReadFile" and call["args"][2]["expr"] == "stack_9"
    )
    assert sized_read["args"][2]["param"] == "nNumberOfBytesToRead"
    assert sized_read["args"][2]["role"] == "length"
    assert sized_read["args"][3]["param"] == "lpNumberOfBytesRead"
    assert sized_read["args"][3]["role"] == "out_length"
    assert report["functions"][0]["flow_hints"][0]["kind"] == (
        "file-read-allocation-flow"
    )
    assert any(
        hint["kind"] == "file-read-allocation-argument-flow"
        for hint in report["functions"][0]["flow_hints"]
    )
    assert any(var["offset"] == -128 for var in report["functions"][0]["stack_vars"])
    assert report["functions"][0]["suspicious_constants"][0] == {
        "value": 4,
        "hex": "0x4",
        "context": "ReadFile",
    }
    assert "file_io" in report["risk_imports"]
    assert "GetTempPathW" in report["risk_imports"]["file_io"]
    assert "GetTempFileNameW" in report["risk_imports"]["file_io"]
    assert any(
        item["kind"] == "file-read-allocation-parser" for item in report["risk_items"]
    )
    assert any(
        item["kind"] == "file-read-allocation-flow" for item in report["risk_items"]
    )
    assert any(
        item["kind"] == "file-read-allocation-argument-flow"
        for item in report["risk_items"]
    )
    assert "resource" in report["risk_imports"]
    assert "resource-extraction" in report["functions"][0]["patterns"]
    assert any(item["kind"] == "resource-extraction" for item in report["risk_items"])
    assert "copy_format" in report["risk_imports"]
    assert "copy-or-format-sink" in report["functions"][0]["patterns"]
    assert any(item["kind"] == "copy-or-format-sink" for item in report["risk_items"])
    assert "temp-file-write-delete" in report["functions"][0]["patterns"]
    assert any(
        item["kind"] == "temp-file-write-delete" for item in report["risk_items"]
    )
    assert "network" in report["risk_imports"]
    assert "network-client" in report["functions"][0]["patterns"]
    assert any(item["kind"] == "network-client" for item in report["risk_items"])
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


def test_windows_risk_network_bucket_avoids_prefix_false_positives() -> None:
    from glaurung.cli.commands.windows_risk import _bucket_imports

    buckets = _bucket_imports(
        [
            "WSAStartup",
            "socket",
            "connect",
            "send",
            "recv",
            "SendMessageW",
            "ConnectNamedPipe",
        ]
    )

    assert buckets["network"] == [
        "WSAStartup",
        "connect",
        "recv",
        "send",
        "socket",
    ]


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
            "pe_metadata": {"tls": {"has_tls": False}},
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
    assert result.pe_metadata["tls"]["has_tls"] is False
    assert result.risk_items[0]["kind"] == "file-read-allocation-parser"


def test_memory_agent_registers_windows_risk_report() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_risk_report" in agent._function_toolset.tools


def test_pe_tls_path_binding_smoke() -> None:
    from pathlib import Path

    candidates = [
        Path(
            "samples/binaries/platforms/linux/amd64/cross/windows-x86_64/hello-c-x86_64-mingw.exe"
        ),
        Path(
            "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/hello-c-x86_64-mingw.exe"
        ),
        Path("tests/fixtures/msvc-pdb/ntdll.dll"),
    ]
    sample = next((path for path in candidates if path.exists()), None)
    if sample is None:
        return

    tls = g.analysis.pe_tls_path(str(sample))

    assert {"has_tls", "callback_count", "callbacks", "stop_reasons"} <= set(tls)
    assert isinstance(tls["callbacks"], list)
