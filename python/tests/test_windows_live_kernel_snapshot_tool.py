from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_live_kernel_snapshot import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "ntoskrnl.exe"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_live_kernel_snapshot_normalizes_live_facts(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    snapshot = {
        "kernel": {
            "version": "10.0.26100.1",
            "build_number": 26100,
            "product_name": "Windows 11",
            "architecture": "x64",
            "ntoskrnl_base": "0xfffff80000000000",
            "ntoskrnl_size": "0x2000000",
            "pdb_guid": "ABCDEF0123456789ABCDEF0123456789",
            "pdb_age": 1,
        },
        "modules": [
            {
                "name": "ntoskrnl.exe",
                "base": "0xfffff80000000000",
                "size": "0x2000000",
            },
            {
                "name": "acme.sys",
                "base": "0xfffff80510000000",
                "size": "0x30000",
            },
        ],
        "syscalls": [
            {
                "service_table": "native",
                "number": "0x36",
                "symbol": "NtQuerySystemInformation",
                "handler": "0xfffff80000123450",
                "expected_handler": "0xfffff80000123450",
                "expected_module": "ntoskrnl.exe",
            },
            {
                "service_table": "native",
                "number": "0x777",
                "symbol": "NtUnexpected",
                "handler": "0xfffff80510001000",
                "expected_module": "ntoskrnl.exe",
            },
        ],
        "callbacks": [
            {
                "kind": "process_notify",
                "routine": "0xfffff80510002000",
                "name": "AcmeProcessNotify",
                "active": "enabled",
            }
        ],
        "driver_objects": [
            {
                "name": "\\\\Driver\\\\Acme",
                "object": "0xffffb00100004000",
                "driver_start": "0xfffff80510000000",
                "driver_size": "0x30000",
                "major_functions": {
                    "IRP_MJ_CREATE": "0xfffff80510003000",
                    "IRP_MJ_DEVICE_CONTROL": {
                        "handler": "0xfffff80510004000",
                        "handler_name": "AcmeDeviceControl",
                    },
                },
            }
        ],
    }

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(snapshot_json=json.dumps(snapshot), add_to_kb=True),
    )

    assert result.kernel_identity is not None
    assert result.kernel_identity.build_number == 26100
    assert result.module_count == 2
    assert result.syscall_count == 2
    assert result.callback_count == 1
    assert result.driver_object_count == 1
    assert result.driver_dispatch_count == 2
    assert {
        "kernel_identity",
        "loaded_modules",
        "live_syscall_table",
        "kernel_callbacks",
        "driver_objects",
        "driver_dispatch_table",
    } <= set(result.coverage)
    assert "syscall_unexpected_module" in result.coverage
    by_symbol = {row.symbol: row for row in result.syscalls}
    assert by_symbol["NtQuerySystemInformation"].handler_module == "ntoskrnl.exe"
    assert by_symbol["NtQuerySystemInformation"].matches_expected_handler is True
    assert by_symbol["NtUnexpected"].handler_module == "acme.sys"
    assert by_symbol["NtUnexpected"].module_status == "unexpected_module"
    assert result.callbacks[0].module_name == "acme.sys"
    assert result.callbacks[0].active is True
    assert any(
        row.major_function == "IRP_MJ_DEVICE_CONTROL"
        and row.handler_name == "AcmeDeviceControl"
        and row.module_name == "acme.sys"
        for row in result.driver_dispatches
    )
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_live_kernel_snapshot"
        for node in ctx.kb.nodes()
    )


def test_windows_live_kernel_snapshot_reports_missing_sections(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(snapshot_json=json.dumps({"kernel": {"build": 26100}})),
    )

    assert result.kernel_identity is not None
    assert result.module_count == 0
    assert result.syscall_count == 0
    assert "kernel_identity" in result.coverage
    assert "loaded_modules" in result.missing_capabilities
    assert "live_syscall_table" in result.missing_capabilities
    assert "driver_dispatch_table" in result.missing_capabilities


def test_windows_live_kernel_snapshot_joins_expected_handler_map(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    tool = build_tool()
    snapshot = {
        "modules": [
            {
                "name": "ntoskrnl.exe",
                "base": "0xfffff80000000000",
                "size": "0x2000000",
            },
            {
                "name": "acme.sys",
                "base": "0xfffff80510000000",
                "size": "0x30000",
            },
        ],
        "syscalls": [
            {
                "service_table": "native",
                "number": "0x36",
                "symbol": "NtQuerySystemInformation",
                "handler": "0xfffff80510001000",
            }
        ],
    }
    expected = {
        "NtQuerySystemInformation": {
            "handler_va": "0xfffff80000123450",
            "handler_module": "ntoskrnl.exe",
        }
    }

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            snapshot_json=json.dumps(snapshot),
            expected_handler_map_json=json.dumps(expected),
        ),
    )

    row = result.syscalls[0]
    assert row.expected_handler_va == 0xFFFFF80000123450
    assert row.expected_module == "ntoskrnl.exe"
    assert row.handler_module == "acme.sys"
    assert row.module_status == "unexpected_module"
    assert row.matches_expected_handler is False
    assert "expected_handler_map" in row.evidence
    assert "syscall_expected_handler_mismatch" in result.coverage


def test_memory_agent_registers_windows_live_kernel_snapshot() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_live_kernel_snapshot" in agent._function_toolset.tools
