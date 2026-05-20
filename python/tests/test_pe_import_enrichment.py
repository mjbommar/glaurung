"""Windows import enrichment tests for PE bug-hunting workflows."""

from __future__ import annotations

from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.context import Budgets, MemoryContext
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.tools.list_suspicious_imports import (
    _classify_imports,
    build_tool as build_suspicious_imports,
)
from glaurung.llm.tools.map_pe_iat import build_tool as build_pe_iat


_PE_SUSPICIOUS = Path(
    "samples/binaries/platforms/linux/amd64/export/cross/windows-x86_64/"
    "suspicious_win-c-x86_64-mingw.exe"
)


def _need_binary(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing sample {path}")
    if path.read_bytes()[:16].startswith(b"version https://"):
        pytest.skip(f"sample is a Git LFS pointer: {path}")
    return path


def _ctx_for(path: Path) -> MemoryContext:
    artifact = g.triage.analyze_path(str(path))
    ctx = MemoryContext(
        file_path=str(path),
        artifact=artifact,
        budgets=Budgets(timeout_ms=3000),
    )
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_pe_iat_maps_pe32_plus_imports_and_enriches_winapi_prototypes() -> None:
    """PE32+ MinGW fixtures should expose native IAT addresses and WinAPI metadata."""
    ctx = _ctx_for(_need_binary(_PE_SUSPICIOUS))
    tool = build_pe_iat()
    result = tool.run(ctx, ctx.kb, tool.input_model(add_to_kb=False))

    by_name = {entry.name: entry for entry in result.entries}
    assert {"CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"} <= set(
        by_name
    )

    for name in ("CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"):
        entry = by_name[name]
        assert entry.va is not None
        assert entry.import_source == "iat"
        assert entry.module == "KERNEL32.dll"
        assert entry.prototype is not None
        assert name in entry.prototype
        assert entry.params
        assert entry.calling_convention == "system"
        assert entry.source == "microsoft-win32metadata"
        assert entry.source_kind == "nuget_winmd"
        assert entry.source_package == "Microsoft.Windows.SDK.Win32Metadata"
        assert entry.confidence is not None
        assert abs(entry.confidence - 0.99) < 0.0001
        assert "process_injection" in entry.risk_tags
        assert entry.param_roles
    assert by_name["CreateRemoteThread"].api_class == "remote_thread_creation"
    assert by_name["CreateRemoteThread"].param_roles["lpStartAddress"] == "callback"
    assert by_name["VirtualAllocEx"].api_class == "process_memory_allocation"
    assert by_name["VirtualAllocEx"].param_roles["dwSize"] == "length"
    assert by_name["WriteProcessMemory"].api_class == "process_memory_write"
    assert by_name["WriteProcessMemory"].param_roles["lpBuffer"] == "source"


def test_suspicious_imports_include_prototype_metadata_for_winapi_hits() -> None:
    ctx = _ctx_for(_need_binary(_PE_SUSPICIOUS))
    tool = build_suspicious_imports()
    result = tool.run(ctx, ctx.kb, tool.input_model(add_to_kb=False))

    assert {"VirtualAllocEx", "WriteProcessMemory"} <= set(
        result.by_bucket["injection"]
    )
    assert result.by_bucket["injection"].count("VirtualAllocEx") == 1
    assert {"CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"} <= set(
        result.by_risk_tag["process_injection"]
    )

    by_name = {entry.name: entry for entry in result.tagged}
    for name in ("CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"):
        tagged = by_name[name]
        assert tagged.module == "KERNEL32.dll"
        assert tagged.prototype is not None
        assert name in tagged.prototype
        assert tagged.source_kind == "nuget_winmd"
        assert tagged.confidence is not None
        assert abs(tagged.confidence - 0.99) < 0.0001
        assert "process_injection" in tagged.risk_tags
    assert "process" in by_name["CreateRemoteThread"].buckets
    assert "injection" in by_name["VirtualAllocEx"].buckets
    assert "injection" in by_name["WriteProcessMemory"].buckets


def test_suspicious_imports_promote_semantic_risk_tags_from_winapi_catalog() -> None:
    catalog = xref_db.load_stdlib_prototype_catalog(bundles=["stdlib-winapi-protos"])
    by_bucket, by_risk_tag, tagged = _classify_imports(
        ["__imp_DeviceIoControl"],
        include_util=False,
        max_per_bucket=8,
        prototype_catalog=catalog,
    )

    assert by_bucket == {}
    assert by_risk_tag["ioctl"] == ["DeviceIoControl"]
    assert by_risk_tag["kernel_boundary"] == ["DeviceIoControl"]

    device_io = tagged[0]
    assert device_io.name == "DeviceIoControl"
    assert device_io.buckets == []
    assert device_io.api_class == "ioctl_boundary"
    assert {"attacker_input", "ioctl", "kernel_boundary"} <= set(device_io.risk_tags)
    assert device_io.module == "KERNEL32.dll"
    assert device_io.prototype is not None
    assert "DeviceIoControl(" in device_io.prototype
    assert device_io.source_kind == "nuget_winmd"
