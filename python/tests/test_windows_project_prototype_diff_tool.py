from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.agents.memory_agent import create_memory_agent
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.tools.windows_project_prototype_diff import build_tool


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _project(tmp_path: Path, name: str) -> Path:
    binary = tmp_path / f"{name}.sys"
    binary.write_bytes(b"MZ" + b"\0" * 512)
    project = tmp_path / f"{name}.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=binary)
    kb.close()
    return project


def _seed_before(project: Path) -> None:
    kb = PersistentKnowledgeBase.open(project)
    try:
        xref_db.set_function_prototype(
            kb,
            "DriverDispatch",
            "NTSTATUS",
            [
                xref_db.FunctionParam("Irp", "PIRP", role="irp"),
                xref_db.FunctionParam("Length", "ULONG", role="length"),
            ],
            calling_convention="NTAPI",
            set_by="manual",
            semantics={"risk_tags": ["ioctl"], "roles": {"Length": "length"}},
        )
        xref_db.set_function_prototype(
            kb,
            "RemovedHelper",
            "void",
            [xref_db.FunctionParam("Buffer", "PVOID", role="buffer")],
            set_by="manual",
        )
    finally:
        kb.close()


def _seed_after(project: Path) -> None:
    kb = PersistentKnowledgeBase.open(project)
    try:
        xref_db.set_function_prototype(
            kb,
            "DriverDispatch",
            "NTSTATUS",
            [
                xref_db.FunctionParam("Irp", "PIRP", role="irp"),
                xref_db.FunctionParam("OutputBuffer", "PVOID", role="out_buffer"),
                xref_db.FunctionParam(
                    "OutputBufferLength",
                    "ULONG",
                    role="length",
                ),
            ],
            calling_convention="NTAPI",
            set_by="manual",
            semantics={
                "risk_tags": ["ioctl", "user_buffer"],
                "roles": {
                    "OutputBuffer": "out_buffer",
                    "OutputBufferLength": "length",
                },
            },
        )
        xref_db.set_function_prototype(
            kb,
            "AddedProbe",
            "BOOLEAN",
            [xref_db.FunctionParam("UserBuffer", "PVOID", role="user_pointer")],
            set_by="manual",
            semantics={"risk_tags": ["probe"]},
        )
    finally:
        kb.close()


def test_windows_project_prototype_diff_reports_security_relevant_deltas(
    tmp_path: Path,
) -> None:
    before = _project(tmp_path, "before")
    after = _project(tmp_path, "after")
    _seed_before(before)
    _seed_after(after)
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            before_project_path=str(before),
            after_project_path=str(after),
            add_to_kb=True,
        ),
    )

    assert result.before_prototype_count == 2
    assert result.after_prototype_count == 2
    assert result.changed_count == 1
    assert result.added_count == 1
    assert result.removed_count == 1
    assert "prototype_deltas" in result.coverage
    assert "parameter_role_deltas" in result.coverage
    assert "security_relevant_prototype_deltas" in result.coverage
    dispatch = next(
        delta for delta in result.deltas if delta.function_name == "DriverDispatch"
    )
    assert dispatch.status == "changed"
    assert "parameter_count" in dispatch.changed_fields
    assert "parameter_roles" in dispatch.changed_fields
    assert "risk_tags" in dispatch.changed_fields
    assert "pointer_or_buffer_parameter_delta" in dispatch.security_relevance
    assert "length_or_count_parameter_delta" in dispatch.security_relevance
    assert dispatch.before is not None
    assert dispatch.after is not None
    assert "Length" in dispatch.before.signature
    assert "OutputBuffer" in dispatch.after.signature
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_project_prototype_diff"
        for node in ctx.kb.nodes()
    )


def test_windows_project_prototype_diff_cli_json(tmp_path: Path, capsys) -> None:
    before = _project(tmp_path, "before")
    after = _project(tmp_path, "after")
    _seed_before(before)
    _seed_after(after)

    rc = GlaurungCLI().run(
        [
            "windows",
            "project-prototype-diff",
            "--before-project-path",
            str(before),
            "--after-project-path",
            str(after),
            "--function-name-contains",
            "dispatch",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["changed_count"] == 1
    assert output["added_count"] == 0
    assert output["removed_count"] == 0
    assert output["deltas"][0]["function_name"] == "DriverDispatch"
    assert "parameter_roles" in output["deltas"][0]["changed_fields"]


def test_memory_agent_registers_windows_project_prototype_diff() -> None:
    agent = create_memory_agent(model="test")

    assert "windows_project_prototype_diff" in agent._function_toolset.tools
