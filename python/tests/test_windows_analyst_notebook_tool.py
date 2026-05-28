from __future__ import annotations

import json
from pathlib import Path

import glaurung as g

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb import xref_db
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.kb.persistent import PersistentKnowledgeBase
from glaurung.llm.tools.windows_analyst_notebook import (
    WindowsNotebookDecision,
    build_tool,
)


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def _project(tmp_path: Path) -> tuple[Path, Path]:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ" + b"\0" * 512)
    project = tmp_path / "target.glaurung"
    kb = PersistentKnowledgeBase.open(project, binary_path=binary)
    kb.close()
    return project, binary


def test_windows_analyst_notebook_exports_project_and_scripts(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project, _binary = _project(tmp_path)
    notebook_path = tmp_path / "notebook.json"
    kb = PersistentKnowledgeBase.open(project)
    xref_db.set_function_name(kb, 0x140001000, "NtExample", set_by="manual")
    xref_db.set_function_prototype(
        kb,
        "NtExample",
        "NTSTATUS",
        [
            xref_db.FunctionParam("Irp", "PIRP", role="irp"),
            xref_db.FunctionParam("Length", "ULONG", role="length"),
        ],
        set_by="manual",
        calling_convention="NTAPI",
        confidence=0.98,
    )
    xref_db.set_comment(kb, 0x140001008, "checks caller length", set_by="manual")
    xref_db.set_data_label(
        kb,
        0x140020000,
        "g_DispatchTable",
        c_type="void *[]",
        set_by="manual",
    )
    xref_db.set_stack_var(
        kb,
        function_va=0x140001000,
        offset=-0x20,
        name="OutputBuffer",
        c_type="PVOID",
        set_by="manual",
    )
    xref_db.add_bookmark(
        kb,
        0x140001020,
        "function_start_decision: kind=demotion state=code_label reason=epilogue label",
        set_by="manual",
    )
    kb.close()

    tool = build_tool()
    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            mode="export",
            project_path=str(project),
            notebook_path=str(notebook_path),
            add_to_kb=True,
        ),
    )

    kinds = {decision.kind for decision in result.notebook.decisions}
    assert {
        "function_name",
        "function_prototype",
        "comment",
        "data_label",
        "stack_var",
        "function_start_decision",
    } <= kinds
    assert notebook_path.exists()
    assert "NtExample" in result.notebook_json
    assert "OutputBuffer" in result.notebook_json
    assert result.ida_script is not None and "NtExample" in result.ida_script
    assert result.ida_script is not None and "NTSTATUS NtExample" in result.ida_script
    assert result.ghidra_script is not None and "NtExample" in result.ghidra_script
    assert result.evidence_bundle.subject.attributes["project_path"] == str(project)
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence and node.label == "windows_analyst_notebook"
        for node in ctx.kb.nodes()
    )


def test_windows_analyst_notebook_imports_names_comments_labels_and_demotions(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    project, _binary = _project(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            mode="import",
            project_path=str(project),
            decisions=[
                WindowsNotebookDecision(
                    kind="function_name",
                    va=0x140003000,
                    name="ReviewedFunction",
                ),
                WindowsNotebookDecision(
                    kind="function_prototype",
                    va=0x140003000,
                    function_name="ReviewedFunction",
                    return_type="NTSTATUS",
                    params=[
                        {"name": "Irp", "c_type": "PIRP", "role": "irp"},
                        {
                            "name": "OutputBuffer",
                            "c_type": "PVOID",
                            "role": "out_buffer",
                        },
                    ],
                    calling_convention="NTAPI",
                    confidence=0.95,
                ),
                WindowsNotebookDecision(
                    kind="comment",
                    va=0x140003010,
                    comment="source reaches copy sink",
                ),
                WindowsNotebookDecision(
                    kind="data_label",
                    va=0x140040000,
                    name="g_Callbacks",
                    c_type="void *[]",
                ),
                WindowsNotebookDecision(
                    kind="stack_var",
                    va=0x140003000,
                    function_va=0x140003000,
                    offset=-0x20,
                    name="OutputBuffer",
                    c_type="PVOID",
                ),
                WindowsNotebookDecision(
                    kind="demotion",
                    va=0x140003020,
                    state="rejected_start",
                    reason="SIMD continuation false start",
                    confidence=0.9,
                ),
            ],
        ),
    )

    assert result.applied_count == 6
    assert result.unsupported_count == 0
    assert result.evidence_bundle.coverage.fact_coverage == [
        "function_names",
        "function_prototypes",
        "comments",
        "data_labels",
        "stack_frame_vars",
        "bookmarks",
    ]

    kb = PersistentKnowledgeBase.open(project)
    try:
        function_name = xref_db.get_function_name(kb, 0x140003000)
        assert function_name is not None
        assert function_name.canonical == "ReviewedFunction"
        prototype = xref_db.get_function_prototype(kb, "ReviewedFunction")
        assert prototype is not None
        assert prototype.return_type == "NTSTATUS"
        assert prototype.params[1].name == "OutputBuffer"
        assert prototype.params[1].role == "out_buffer"
        assert prototype.calling_convention == "NTAPI"
        assert xref_db.get_comment(kb, 0x140003010) == "source reaches copy sink"
        labels = {label.va: label for label in xref_db.list_data_labels(kb)}
        assert labels[0x140040000].name == "g_Callbacks"
        stack_var = xref_db.get_stack_var(kb, 0x140003000, -0x20)
        assert stack_var is not None
        assert stack_var.name == "OutputBuffer"
        assert stack_var.c_type == "PVOID"
        demotion_comment = xref_db.get_comment(kb, 0x140003020)
        assert demotion_comment is not None
        assert "rejected_start" in demotion_comment
        assert xref_db.list_bookmarks(kb, va=0x140003020)
    finally:
        kb.close()


def test_windows_analyst_notebook_cli_exports_json(tmp_path: Path, capsys) -> None:
    project, _binary = _project(tmp_path)
    notebook_path = tmp_path / "notebook.json"
    kb = PersistentKnowledgeBase.open(project)
    try:
        xref_db.set_function_name(kb, 0x140001000, "NtExample", set_by="manual")
        xref_db.set_stack_var(
            kb,
            function_va=0x140001000,
            offset=-0x20,
            name="OutputBuffer",
            c_type="PVOID",
            set_by="manual",
        )
    finally:
        kb.close()

    rc = GlaurungCLI().run(
        [
            "windows",
            "analyst-notebook",
            "--mode",
            "export",
            "--project-path",
            str(project),
            "--notebook-path",
            str(notebook_path),
            "--no-include-scripts",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["notebook"]["project_path"] == str(project)
    assert notebook_path.exists()
    assert output["ida_script"] is None
    assert any(
        decision["kind"] == "stack_var" and decision["name"] == "OutputBuffer"
        for decision in output["notebook"]["decisions"]
    )


def test_memory_agent_registers_windows_analyst_notebook() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_analyst_notebook" in agent._function_toolset.tools
