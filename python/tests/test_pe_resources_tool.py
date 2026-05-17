from __future__ import annotations

from pathlib import Path

import glaurung as g

from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _create_pe_with_version_resource() -> bytes:
    data = bytearray(1024)

    data[0:2] = b"MZ"
    data[60] = 0x80

    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x014C).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")

    data[0x98:0x9A] = (0x010B).to_bytes(2, "little")
    data[0xA8:0xAC] = (0x1000).to_bytes(4, "little")
    data[0xB4:0xB8] = (0x400000).to_bytes(4, "little")
    data[0xBC:0xC0] = (0x1000).to_bytes(4, "little")
    data[0xC0:0xC4] = (0x200).to_bytes(4, "little")
    data[0xF4:0xF8] = (16).to_bytes(4, "little")

    resource_dir = 0x98 + 96 + (2 * 8)
    data[resource_dir : resource_dir + 4] = (0x1000).to_bytes(4, "little")
    data[resource_dir + 4 : resource_dir + 8] = (0x90).to_bytes(4, "little")

    section_offset = 0x178
    data[section_offset : section_offset + 5] = b".rsrc"
    data[section_offset + 8 : section_offset + 12] = (0x200).to_bytes(4, "little")
    data[section_offset + 12 : section_offset + 16] = (0x1000).to_bytes(4, "little")
    data[section_offset + 16 : section_offset + 20] = (0x200).to_bytes(4, "little")
    data[section_offset + 20 : section_offset + 24] = (0x200).to_bytes(4, "little")
    data[section_offset + 36 : section_offset + 40] = (0x40000040).to_bytes(4, "little")

    base = 0x200
    data[base + 14 : base + 16] = (1).to_bytes(2, "little")
    data[base + 16 : base + 20] = (16).to_bytes(4, "little")
    data[base + 20 : base + 24] = (0x80000018).to_bytes(4, "little")

    name_dir = base + 0x18
    data[name_dir + 14 : name_dir + 16] = (1).to_bytes(2, "little")
    data[name_dir + 16 : name_dir + 20] = (1).to_bytes(4, "little")
    data[name_dir + 20 : name_dir + 24] = (0x80000030).to_bytes(4, "little")

    lang_dir = base + 0x30
    data[lang_dir + 14 : lang_dir + 16] = (1).to_bytes(2, "little")
    data[lang_dir + 16 : lang_dir + 20] = (0x0409).to_bytes(4, "little")
    data[lang_dir + 20 : lang_dir + 24] = (0x48).to_bytes(4, "little")

    data_entry = base + 0x48
    data[data_entry : data_entry + 4] = (0x1080).to_bytes(4, "little")
    data[data_entry + 4 : data_entry + 8] = (5).to_bytes(4, "little")
    data[data_entry + 8 : data_entry + 12] = (1252).to_bytes(4, "little")
    data[0x280:0x285] = b"hello"

    return bytes(data)


def _write_fixture(tmp_path: Path) -> Path:
    path = tmp_path / "version-resource.exe"
    path.write_bytes(_create_pe_with_version_resource())
    return path


def _create_pe_with_manifest_resource() -> bytes:
    data = bytearray(_create_pe_with_version_resource())
    if len(data) < 2048:
        data.extend(b"\0" * (2048 - len(data)))

    manifest = (
        b'<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
        b'<assemblyIdentity name="Glaurung.Test" version="1.0.0.0" type="win32"/>'
        b'<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security>'
        b"<requestedPrivileges>"
        b'<requestedExecutionLevel level="requireAdministrator" uiAccess="true"/>'
        b"</requestedPrivileges></security></trustInfo>"
        b"<dependency><dependentAssembly>"
        b'<assemblyIdentity name="Microsoft.Windows.Common-Controls"/>'
        b"</dependentAssembly></dependency></assembly>"
    )

    data[0x200 + 16 : 0x200 + 20] = (24).to_bytes(4, "little")
    data[0x200 + 0x48 + 4 : 0x200 + 0x48 + 8] = len(manifest).to_bytes(4, "little")
    data[0x200 + 0x48 + 8 : 0x200 + 0x48 + 12] = (65001).to_bytes(4, "little")
    data[0x280 : 0x280 + len(manifest)] = manifest

    section_offset = 0x178
    data[section_offset + 8 : section_offset + 12] = (0x400).to_bytes(4, "little")
    data[section_offset + 16 : section_offset + 20] = (0x400).to_bytes(4, "little")

    return bytes(data)


def _write_manifest_fixture(tmp_path: Path) -> Path:
    path = tmp_path / "manifest-resource.exe"
    path.write_bytes(_create_pe_with_manifest_resource())
    return path


def _align4(buf: bytearray) -> None:
    while len(buf) % 4:
        buf.append(0)


def _utf16z(value: str) -> bytes:
    return value.encode("utf-16le") + b"\0\0"


def _version_node(
    key: str,
    *,
    value: bytes = b"",
    value_length: int = 0,
    value_type: int = 1,
    children: list[bytes] | None = None,
) -> bytes:
    buf = bytearray()
    buf.extend(b"\0\0")
    buf.extend(value_length.to_bytes(2, "little"))
    buf.extend(value_type.to_bytes(2, "little"))
    buf.extend(_utf16z(key))
    _align4(buf)
    buf.extend(value)
    _align4(buf)
    for child in children or []:
        buf.extend(child)
        _align4(buf)
    buf[0:2] = len(buf).to_bytes(2, "little")
    return bytes(buf)


def _fixed_file_info() -> bytes:
    values = [
        0xFEEF04BD,
        0x00010000,
        0x00010002,
        0x00030004,
        0x00050006,
        0x00070008,
        0x0000003F,
        0x00000000,
        0x00040004,
        0x00000001,
        0x00000000,
        0x00000000,
        0x00000000,
    ]
    return b"".join(value.to_bytes(4, "little") for value in values)


def _string_value(key: str, value: str) -> bytes:
    encoded = _utf16z(value)
    return _version_node(
        key,
        value=encoded,
        value_length=len(value) + 1,
        value_type=1,
    )


def _version_info_blob() -> bytes:
    string_table = _version_node(
        "040904B0",
        children=[
            _string_value("CompanyName", "Glaurung Labs"),
            _string_value("FileDescription", "Generated PE resource fixture"),
            _string_value("ProductName", "Glaurung Fixture"),
        ],
    )
    string_file_info = _version_node("StringFileInfo", children=[string_table])
    translation = (0x0409).to_bytes(2, "little") + (1200).to_bytes(2, "little")
    var_file_info = _version_node(
        "VarFileInfo",
        children=[
            _version_node(
                "Translation",
                value=translation,
                value_length=len(translation),
                value_type=0,
            )
        ],
    )
    return _version_node(
        "VS_VERSION_INFO",
        value=_fixed_file_info(),
        value_length=52,
        value_type=0,
        children=[string_file_info, var_file_info],
    )


def _create_pe_with_version_info_resource() -> bytes:
    data = bytearray(_create_pe_with_version_resource())
    if len(data) < 2048:
        data.extend(b"\0" * (2048 - len(data)))
    blob = _version_info_blob()
    data[0x200 + 0x48 + 4 : 0x200 + 0x48 + 8] = len(blob).to_bytes(4, "little")
    data[0x200 + 0x48 + 8 : 0x200 + 0x48 + 12] = (1200).to_bytes(4, "little")
    data[0x280 : 0x280 + len(blob)] = blob
    section_offset = 0x178
    data[section_offset + 8 : section_offset + 12] = (0x500).to_bytes(4, "little")
    data[section_offset + 16 : section_offset + 20] = (0x500).to_bytes(4, "little")
    return bytes(data)


def _write_version_info_fixture(tmp_path: Path) -> Path:
    path = tmp_path / "version-info-resource.exe"
    path.write_bytes(_create_pe_with_version_info_resource())
    return path


def _ctx_for(path: Path) -> MemoryContext:
    artifact = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=artifact)
    import_triage(ctx.kb, artifact, str(path))
    return ctx


def test_native_pe_list_resources_path_reports_version_leaf(tmp_path: Path) -> None:
    path = _write_fixture(tmp_path)

    result = g.analysis.pe_list_resources_path(str(path), preview_bytes=8)

    assert result["leaf_count"] == 1
    assert result["total_directories"] == 3
    assert result["max_depth"] == 2
    assert result["warnings"] == []
    assert result["stop_reasons"] == []
    assert result["resources_by_type"] == {"VERSIONINFO": 1}
    resource = result["resources"][0]
    assert resource["type_id"] == 16
    assert resource["type_name"] == "VERSIONINFO"
    assert resource["name_id"] == 1
    assert resource["language_id"] == 0x0409
    assert resource["code_page"] == 1252
    assert resource["data_rva"] == 0x1080
    assert resource["data_offset"] == 0x280
    assert resource["section_name"] == ".rsrc"
    assert resource["size"] == 5
    assert resource["magic"] == "ascii_text"
    assert resource["preview_hex"] == "68656c6c6f"


def test_pe_list_resources_tool_filters_and_adds_kb_nodes(tmp_path: Path) -> None:
    from glaurung.llm.tools.pe_list_resources import build_tool

    path = _write_fixture(tmp_path)
    ctx = _ctx_for(path)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(type_filter="versioninfo", limit=4, preview_bytes=8),
    )

    assert result.leaf_count == 1
    assert result.matched_resource_count == 1
    assert result.resources[0].resource_type == "VERSIONINFO"
    assert result.resources[0].preview_hex == "68656c6c6f"
    assert result.resources[0].evidence == "VERSIONINFO/1/0x0409 @ .rsrc:0x280"
    assert any(
        node.kind == NodeKind.pe_resource
        and node.props.get("tool") == "pe_list_resources"
        and node.props.get("type_name") == "VERSIONINFO"
        for node in ctx.kb.nodes()
    )


def test_memory_agent_registers_pe_resource_tool() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "pe_list_resources" in agent._function_toolset.tools


def test_pe_resources_cli_outputs_json(tmp_path: Path, capsys) -> None:
    from glaurung import cli

    path = _write_fixture(tmp_path)

    rc = cli.main(["pe", "resources", str(path), "--json", "--preview-bytes", "8"])

    assert rc == 0
    out = capsys.readouterr().out.strip()
    payload = __import__("json").loads(out)
    assert payload["leaf_count"] == 1
    assert payload["resources_by_type"] == {"VERSIONINFO": 1}
    assert payload["resources"][0]["evidence"] == "VERSIONINFO/1/0x0409 @ .rsrc:0x280"


def test_pe_resources_cli_outputs_compact_human_summary(tmp_path: Path, capsys) -> None:
    from glaurung import cli

    path = _write_fixture(tmp_path)

    rc = cli.main(["pe", "resources", str(path), "--preview-bytes", "8"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "# PE resources:" in out
    assert "leaves: 1" in out
    assert "VERSIONINFO: 1" in out
    assert "VERSIONINFO/1/0x0409 @ .rsrc:0x280" in out
    assert "preview=68656c6c6f" in out


def test_native_pe_view_resource_returns_manifest_text(tmp_path: Path) -> None:
    path = _write_manifest_fixture(tmp_path)

    resource = g.analysis.pe_view_resource_path(
        str(path), type_filter="manifest", preview_bytes=32
    )

    assert resource["type_name"] == "MANIFEST"
    assert resource["magic"] == "xml"
    assert resource["text"].startswith("<assembly")
    assert resource["preview_hex"].startswith("3c617373656d626c79")


def test_pe_view_manifest_tool_decodes_security_fields(tmp_path: Path) -> None:
    from glaurung.llm.tools.pe_view_manifest import build_tool

    path = _write_manifest_fixture(tmp_path)
    ctx = _ctx_for(path)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model())

    assert result.found is True
    assert result.requested_execution_level == "requireAdministrator"
    assert result.ui_access is True
    assert result.assembly_identity["name"] == "Glaurung.Test"
    assert "Microsoft.Windows.Common-Controls" in result.dependencies
    assert result.evidence == "MANIFEST/1/0x0409 @ .rsrc:0x280"


def test_pe_manifest_cli_outputs_json(tmp_path: Path, capsys) -> None:
    from glaurung import cli

    path = _write_manifest_fixture(tmp_path)

    rc = cli.main(["pe", "manifest", str(path), "--json"])

    assert rc == 0
    payload = __import__("json").loads(capsys.readouterr().out)
    assert payload["requested_execution_level"] == "requireAdministrator"
    assert payload["ui_access"] is True
    assert payload["assembly_identity"]["name"] == "Glaurung.Test"


def test_pe_decode_version_info_tool_decodes_fixed_and_string_fields(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.pe_decode_version_info import build_tool

    path = _write_version_info_fixture(tmp_path)
    ctx = _ctx_for(path)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model())

    assert result.found is True
    assert result.file_version == "1.2.3.4"
    assert result.product_version == "5.6.7.8"
    assert result.file_type == "application"
    assert result.strings["CompanyName"] == "Glaurung Labs"
    assert result.strings["ProductName"] == "Glaurung Fixture"
    assert result.translations == [{"language_id": 0x0409, "code_page": 1200}]
    assert result.evidence == "VERSIONINFO/1/0x0409 @ .rsrc:0x280"


def test_pe_version_cli_outputs_json(tmp_path: Path, capsys) -> None:
    from glaurung import cli

    path = _write_version_info_fixture(tmp_path)

    rc = cli.main(["pe", "version", str(path), "--json"])

    assert rc == 0
    payload = __import__("json").loads(capsys.readouterr().out)
    assert payload["file_version"] == "1.2.3.4"
    assert payload["strings"]["CompanyName"] == "Glaurung Labs"
