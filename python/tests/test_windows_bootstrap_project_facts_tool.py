from __future__ import annotations

import json
from pathlib import Path

import glaurung as g
import yaml

from glaurung.cli.main import GlaurungCLI
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.tools.windows_bootstrap_project_facts import build_tool
from glaurung.llm.tools.windows_project_fact_manifest import (
    build_tool as build_manifest_tool,
)


def _ctx(tmp_path: Path) -> MemoryContext:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ")
    artifact = g.triage.analyze_bytes(b"MZ")
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_windows_bootstrap_project_facts_composes_project_steps(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from glaurung.llm.kb import (
        cfg_db,
        pe_direct_calls,
        type_db,
        windows_boundaries,
        windows_callsite_facts,
        windows_function_chunks,
        windows_sysinfo,
        xref_db,
    )

    def fake_index_callgraph(*_args, **_kwargs) -> int:
        return 7

    def fake_index_pe_direct_calls(*_args, **_kwargs) -> int:
        return 23

    def fake_index_function_boundaries(*_args, **_kwargs) -> int:
        return 29

    def fake_index_function_chunks(*_args, **_kwargs) -> int:
        return 41

    def fake_index_data_xrefs(*_args, **_kwargs) -> int:
        return 11

    def fake_index_cfg(*_args, **_kwargs) -> int:
        return 13

    def fake_index_cfg_dominance(*_args, **_kwargs) -> int:
        return 17

    def fake_index_cfg_branch_facts(*_args, **_kwargs) -> int:
        return 19

    def fake_index_sysinfo_dispatch_facts(*_args, **_kwargs) -> int:
        return 31

    def fake_index_callsite_path_conditions(*_args, **_kwargs) -> int:
        return 37

    def fake_import_pe_pdb_types(*_args, **_kwargs) -> dict:
        return {
            "cache_hit": True,
            "imported_struct": 1,
            "imported_union": 1,
            "imported_function_proto": 3,
            "imported_function_name": 5,
            "public_symbols": 6,
            "skipped_manual_function_name": 0,
            "missing_layouts": ["_MISSING"],
        }

    monkeypatch.setattr(xref_db, "index_callgraph", fake_index_callgraph)
    monkeypatch.setattr(
        pe_direct_calls, "index_pe_direct_calls", fake_index_pe_direct_calls
    )
    monkeypatch.setattr(
        windows_boundaries,
        "index_function_boundaries",
        fake_index_function_boundaries,
    )
    monkeypatch.setattr(
        windows_function_chunks,
        "index_function_chunks",
        fake_index_function_chunks,
    )
    monkeypatch.setattr(xref_db, "index_data_xrefs", fake_index_data_xrefs)
    monkeypatch.setattr(cfg_db, "index_cfg", fake_index_cfg)
    monkeypatch.setattr(cfg_db, "index_cfg_dominance", fake_index_cfg_dominance)
    monkeypatch.setattr(cfg_db, "index_cfg_branch_facts", fake_index_cfg_branch_facts)
    monkeypatch.setattr(
        windows_sysinfo,
        "index_sysinfo_dispatch_facts",
        fake_index_sysinfo_dispatch_facts,
    )
    monkeypatch.setattr(
        windows_callsite_facts,
        "index_callsite_path_conditions",
        fake_index_callsite_path_conditions,
    )
    monkeypatch.setattr(type_db, "import_pe_pdb_types", fake_import_pe_pdb_types)

    pe = tmp_path / "driver.sys"
    pe.write_bytes(b"MZ")
    cache = tmp_path / "symbols"
    cache.mkdir()
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pe_path=str(pe),
            project_path=str(tmp_path / "driver.glaurung"),
            pdb_cache_dir=str(cache),
            struct_names=["_KNOWN", "_MISSING"],
            add_to_kb=True,
        ),
    )

    assert [(step.name, step.ok, step.count) for step in result.steps] == [
        ("import_pdb_facts", True, 10),
        ("index_pe_direct_calls", True, 23),
        ("index_function_boundaries", True, 29),
        ("index_callgraph", True, 7),
        ("index_function_chunks", True, 41),
        ("index_data_xrefs", True, 11),
        ("index_cfg", True, 13),
        ("index_cfg_dominance", True, 17),
        ("index_branch_conditions", True, 19),
        ("index_sysinfo_dispatch", True, 31),
        ("index_callsite_path_conditions", True, 37),
    ]
    assert result.pdb_counts is not None
    assert result.pdb_counts.imported_function_name == 5
    assert result.pdb_counts.missing_layouts == ["_MISSING"]
    assert "call_xrefs" in result.fact_coverage
    assert "function_boundaries" in result.fact_coverage
    assert "function_chunks" in result.fact_coverage
    assert "data_xrefs" in result.fact_coverage
    assert "persisted_cfg" in result.fact_coverage
    assert "cfg_dominance" in result.fact_coverage
    assert "branch_conditions" in result.fact_coverage
    assert "sysinfo_dispatch" in result.fact_coverage
    assert "callsite_path_conditions" in result.fact_coverage
    assert "pdb_type_layouts" in result.fact_coverage
    assert "pdb_function_prototypes" in result.fact_coverage
    assert "requested_type_layouts" in result.missing_capabilities
    assert result.evidence_node_id is not None
    assert any(
        node.kind == NodeKind.evidence
        and node.label == "windows_bootstrap_project_facts"
        for node in ctx.kb.nodes()
    )


def test_windows_bootstrap_project_facts_can_skip_steps(tmp_path: Path) -> None:
    pe = tmp_path / "driver.sys"
    pe.write_bytes(b"MZ")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pe_path=str(pe),
            project_path=str(tmp_path / "driver.glaurung"),
            index_callgraph=False,
            index_pe_direct_calls=False,
            index_function_boundaries=False,
            index_function_chunks=False,
            index_data_xrefs=False,
            index_cfg=False,
            index_cfg_dominance=False,
            index_branch_conditions=False,
            index_sysinfo_dispatch=False,
            index_callsite_path_conditions=False,
            import_pdb_facts=False,
        ),
    )

    assert [(step.name, step.ran, step.ok) for step in result.steps] == [
        ("import_pdb_facts", False, True),
        ("index_pe_direct_calls", False, True),
        ("index_function_boundaries", False, True),
        ("index_callgraph", False, True),
        ("index_function_chunks", False, True),
        ("index_data_xrefs", False, True),
        ("index_cfg", False, True),
        ("index_cfg_dominance", False, True),
        ("index_branch_conditions", False, True),
        ("index_sysinfo_dispatch", False, True),
        ("index_callsite_path_conditions", False, True),
    ]
    assert result.fact_coverage == []
    assert result.missing_capabilities == []


def test_windows_bootstrap_project_facts_writes_project_fact_manifest(
    tmp_path: Path,
) -> None:
    pe = tmp_path / "driver.sys"
    project = tmp_path / "driver.glaurung"
    manifest = tmp_path / "pe-project-facts.yaml"
    pe.write_bytes(b"MZ")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pe_path=str(pe),
            project_path=str(project),
            project_facts_output_path=str(manifest),
            project_fact_id="driver_project",
            target_id="driver",
            build_label="win11-ltsc-v4",
            build_number="26100.1742",
            architecture="x64",
            binary_filename="driver.sys",
            manifest_note="unit manifest row",
            index_callgraph=False,
            index_pe_direct_calls=False,
            index_function_boundaries=False,
            index_function_chunks=False,
            index_data_xrefs=False,
            index_cfg=False,
            index_cfg_dominance=False,
            index_branch_conditions=False,
            index_sysinfo_dispatch=False,
            index_callsite_path_conditions=False,
            import_pdb_facts=False,
        ),
    )

    assert result.project_facts_output_path == str(manifest)
    assert result.project_fact_record_id == "driver_project"
    rows = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == "driver_project"
    assert row["target_id"] == "driver"
    assert row["build_label"] == "win11-ltsc-v4"
    assert row["build_number"] == "26100.1742"
    assert row["binary_filename"] == "driver.sys"
    assert row["project_path"] == str(project)
    assert len(row["project_sha256"]) == 64
    assert row["project_size_bytes"] > 0
    assert row["fact_sources"] == ["windows_bootstrap_project_facts"]
    assert "function_names" in row["missing_facts"]
    assert row["counts"]["function_name_count"] == 0
    assert row["notes"] == "unit manifest row"
    manifest_result = build_manifest_tool().run(
        ctx,
        ctx.kb,
        build_manifest_tool().input_model(project_facts_path=str(manifest)),
    )
    assert [record.id for record in manifest_result.records] == ["driver_project"]
    assert manifest_result.records[0].counts.function_boundary_count == 0
    assert manifest_result.records[0].counts.function_chunk_fact_count == 0


def test_windows_cli_bootstrap_project_facts_json_skips_steps(
    tmp_path: Path,
    capsys,
) -> None:
    pe = tmp_path / "driver.sys"
    project = tmp_path / "driver.glaurung"
    manifest = tmp_path / "pe-project-facts.yaml"
    pe.write_bytes(b"MZ")

    rc = GlaurungCLI().run(
        [
            "windows",
            "bootstrap-project-facts",
            "--pe-path",
            str(pe),
            "--project-path",
            str(project),
            "--project-facts-output-path",
            str(manifest),
            "--project-fact-id",
            "driver_project",
            "--target-id",
            "driver",
            "--build-label",
            "win11-ltsc-v4",
            "--no-index-callgraph",
            "--no-index-pe-direct-calls",
            "--no-index-function-boundaries",
            "--no-index-function-chunks",
            "--no-index-data-xrefs",
            "--no-index-cfg",
            "--no-index-cfg-dominance",
            "--no-index-branch-conditions",
            "--no-index-sysinfo-dispatch",
            "--no-index-callsite-path-conditions",
            "--no-import-pdb-facts",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["pe_path"] == str(pe)
    assert output["project_path"] == str(project)
    assert output["project_facts_output_path"] == str(manifest)
    assert output["project_fact_record_id"] == "driver_project"
    assert output["fact_coverage"] == []
    assert output["missing_capabilities"] == []
    assert yaml.safe_load(manifest.read_text(encoding="utf-8"))[0]["id"] == (
        "driver_project"
    )
    assert [(step["name"], step["ran"], step["ok"]) for step in output["steps"]] == [
        ("import_pdb_facts", False, True),
        ("index_pe_direct_calls", False, True),
        ("index_function_boundaries", False, True),
        ("index_callgraph", False, True),
        ("index_function_chunks", False, True),
        ("index_data_xrefs", False, True),
        ("index_cfg", False, True),
        ("index_cfg_dominance", False, True),
        ("index_branch_conditions", False, True),
        ("index_sysinfo_dispatch", False, True),
        ("index_callsite_path_conditions", False, True),
    ]


def test_windows_bootstrap_project_facts_zero_count_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from glaurung.llm.kb import (
        cfg_db,
        pe_direct_calls,
        windows_boundaries,
        windows_callsite_facts,
        windows_function_chunks,
        windows_sysinfo,
        xref_db,
    )

    def fake_index_callgraph(*_args, **_kwargs) -> int:
        return 0

    def fake_index_pe_direct_calls(*_args, **_kwargs) -> int:
        return 0

    def fake_index_function_boundaries(*_args, **_kwargs) -> int:
        return 0

    def fake_index_function_chunks(*_args, **_kwargs) -> int:
        return 0

    def fake_index_data_xrefs(*_args, **_kwargs) -> int:
        return 3

    def fake_index_cfg(*_args, **_kwargs) -> int:
        return 0

    def fake_index_cfg_dominance(*_args, **_kwargs) -> int:
        return 0

    def fake_index_cfg_branch_facts(*_args, **_kwargs) -> int:
        return 0

    def fake_index_sysinfo_dispatch_facts(*_args, **_kwargs) -> int:
        return 0

    def fake_index_callsite_path_conditions(*_args, **_kwargs) -> int:
        return 0

    monkeypatch.setattr(xref_db, "index_callgraph", fake_index_callgraph)
    monkeypatch.setattr(
        pe_direct_calls, "index_pe_direct_calls", fake_index_pe_direct_calls
    )
    monkeypatch.setattr(
        windows_boundaries,
        "index_function_boundaries",
        fake_index_function_boundaries,
    )
    monkeypatch.setattr(
        windows_function_chunks,
        "index_function_chunks",
        fake_index_function_chunks,
    )
    monkeypatch.setattr(xref_db, "index_data_xrefs", fake_index_data_xrefs)
    monkeypatch.setattr(cfg_db, "index_cfg", fake_index_cfg)
    monkeypatch.setattr(cfg_db, "index_cfg_dominance", fake_index_cfg_dominance)
    monkeypatch.setattr(cfg_db, "index_cfg_branch_facts", fake_index_cfg_branch_facts)
    monkeypatch.setattr(
        windows_sysinfo,
        "index_sysinfo_dispatch_facts",
        fake_index_sysinfo_dispatch_facts,
    )
    monkeypatch.setattr(
        windows_callsite_facts,
        "index_callsite_path_conditions",
        fake_index_callsite_path_conditions,
    )

    pe = tmp_path / "driver.sys"
    pe.write_bytes(b"MZ")
    ctx = _ctx(tmp_path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(
            pe_path=str(pe),
            project_path=str(tmp_path / "driver.glaurung"),
            import_pdb_facts=False,
        ),
    )

    assert [(step.name, step.ok, step.count) for step in result.steps] == [
        ("import_pdb_facts", True, 0),
        ("index_pe_direct_calls", True, 0),
        ("index_function_boundaries", True, 0),
        ("index_callgraph", True, 0),
        ("index_function_chunks", True, 0),
        ("index_data_xrefs", True, 3),
        ("index_cfg", True, 0),
        ("index_cfg_dominance", True, 0),
        ("index_branch_conditions", True, 0),
        ("index_sysinfo_dispatch", True, 0),
        ("index_callsite_path_conditions", True, 0),
    ]
    assert "call_xrefs" not in result.fact_coverage
    assert "data_xrefs" in result.fact_coverage
    assert "call_xrefs" in result.missing_capabilities
    assert "data_xrefs" not in result.missing_capabilities
    assert "persisted_cfg" in result.missing_capabilities
    assert "function_boundaries" in result.missing_capabilities
    assert "function_chunks" in result.missing_capabilities
    assert "cfg_dominance" in result.missing_capabilities
    assert "branch_conditions" in result.missing_capabilities
    assert "sysinfo_dispatch" in result.missing_capabilities
    assert "callsite_path_conditions" in result.missing_capabilities


def test_memory_agent_registers_windows_bootstrap_project_facts() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "windows_bootstrap_project_facts" in agent._function_toolset.tools
