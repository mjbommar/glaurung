from __future__ import annotations

import io
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


_HELLO_JAR = Path("samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar")


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing path {path}")
    return path


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def _compile_simple_class(tmp_path: Path) -> bytes:
    if shutil.which("javac") is None:
        pytest.skip("javac is required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    source = src / "VersionedFixture.java"
    source.write_text(
        """
package fixture;

public class VersionedFixture {
    public static String hello() {
        return "hello";
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["javac", "--release", "17", "-d", str(out), str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    return (out / "fixture" / "VersionedFixture.class").read_bytes()


def _hardened_index_fixture(tmp_path: Path) -> Path:
    class_bytes = _compile_simple_class(tmp_path)
    nested_buf = io.BytesIO()
    with zipfile.ZipFile(nested_buf, "w") as nested:
        nested.writestr("nested.txt", "nested")
    jar = tmp_path / "hardened-index.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nMain-Class: fixture.VersionedFixture\n",
        )
        zf.writestr("fixture/VersionedFixture.class", class_bytes)
        zf.writestr("META-INF/versions/17/fixture/VersionedFixture.class", class_bytes)
        zf.writestr("module-info.class", class_bytes)
        zf.writestr("META-INF/SIG.SF", "Signature-Version: 1.0\n")
        zf.writestr("META-INF/SIG.RSA", b"not-a-real-signature")
        zf.writestr(
            "META-INF/maven/com.example/demo/pom.properties",
            "groupId=com.example\nartifactId=demo\nversion=1.2.3\n",
        )
        zf.writestr(
            "META-INF/services/com.example.Service",
            "fixture.VersionedFixture\n",
        )
        zf.writestr("libs/nested.jar", nested_buf.getvalue())
        zf.writestr("../evil.txt", "zip slip")
    return jar


def test_java_index_archive_summarizes_vendored_jar() -> None:
    from glaurung.llm.tools.java_index_archive import build_tool

    jar = _need(_HELLO_JAR)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx, ctx.kb, tool.input_model(path=str(jar), include_resources=True)
    )

    assert result.archive_path == str(jar)
    assert result.archive_format == "jar"
    assert result.class_count == 1
    assert result.resource_count == 1
    assert result.manifest_main_class == "HelloWorld"
    assert not result.truncated
    assert len(result.classes) == 1
    cls = result.classes[0]
    assert cls.entry_name == "HelloWorld.class"
    assert cls.class_name == "HelloWorld"
    assert cls.major_version in {55, 61, 65}
    assert cls.method_count >= 1
    assert cls.methods_with_code >= 1

    assert any(n.kind == NodeKind.java_archive for n in ctx.kb.nodes())
    assert any(
        n.kind == NodeKind.java_class and n.label == "HelloWorld"
        for n in ctx.kb.nodes()
    )


def test_java_index_archive_respects_class_limit() -> None:
    from glaurung.llm.tools.java_index_archive import build_tool

    jar = _need(_HELLO_JAR)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar), max_classes=0))

    assert result.class_count == 1
    assert result.classes == []
    assert result.truncated


def test_java_index_archive_reports_hardened_jar_metadata(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_index_archive import build_tool

    jar = _hardened_index_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), include_resources=True),
    )

    assert result.entry_count >= 10
    assert result.nested_archive_count == 1
    assert result.nested_archives[0].entry_name == "libs/nested.jar"
    assert result.multi_release_class_count == 1
    assert result.multi_release_versions == [17]
    assert result.signed
    assert {item.entry_name for item in result.signature_files} == {
        "META-INF/SIG.SF",
        "META-INF/SIG.RSA",
    }
    assert result.maven_artifact_count == 1
    assert result.maven_artifacts[0].group_id == "com.example"
    assert result.maven_artifacts[0].artifact_id == "demo"
    assert result.maven_artifacts[0].version == "1.2.3"
    assert result.service_descriptor_count == 1
    assert result.service_descriptors[0].service_name == "com.example.Service"
    assert result.module_info_present
    assert result.zip_slip_entry_count == 1
    assert result.suspicious_entries[0].entry_name == "../evil.txt"
    assert any(
        n.kind == NodeKind.java_archive
        and n.props.get("nested_archive_count") == 1
        and n.props.get("signed") is True
        for n in ctx.kb.nodes()
    )


def test_java_index_archive_respects_entry_budget(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_index_archive import build_tool

    jar = _hardened_index_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), include_resources=True, max_entries=3),
    )

    assert result.entry_count >= 10
    assert len(result.entries) == 3
    assert result.truncated


def test_memory_agent_registers_java_index_archive() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_index_archive" in agent._function_toolset.tools
