from __future__ import annotations

import base64
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def _compile_suspicious_blob_jar(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")

    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    hidden_class_blob = b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + bytes(range(64))
    encoded_class_blob = base64.b64encode(hidden_class_blob).decode("ascii")
    encoded_text = base64.b64encode(b"normal decoded text").decode("ascii")

    (src / "SuspiciousBlobFixture.java").write_text(
        f"""
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SuspiciousBlobFixture extends ClassLoader {{
    public Class<?> loadHiddenClass() {{
        byte[] data = Base64.getDecoder().decode("{encoded_class_blob}");
        return defineClass(null, data, 0, data.length);
    }}

    public String decodeOnly() {{
        byte[] data = Base64.getDecoder().decode("{encoded_text}");
        return new String(data, StandardCharsets.UTF_8);
    }}
}}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "javac",
            "--release",
            "17",
            "-d",
            str(out),
            str(src / "SuspiciousBlobFixture.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "suspicious-blobs.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    with zipfile.ZipFile(jar_path, "a") as zf:
        zf.writestr("payload/hidden-class.bin", hidden_class_blob)
        zf.writestr("payload/nested.dat", b"PK\x03\x04" + b"\x00" * 96)
        zf.writestr(
            "META-INF/libraries/example-dependency.jar", b"PK\x03\x04" + b"\x00" * 96
        )
        zf.writestr("payload/native.dat", b"\x7fELF" + b"\x00" * 96)
        zf.writestr("payload/macho-fat.dat", b"\xca\xfe\xba\xbe\x00\x00\x00\x02")
        zf.writestr("META-INF/TESTSIGN.RSA", bytes(range(256)) * 4)
        zf.writestr(
            "assets/demo/lang/en_us.json",
            '{"message":"This is a long ordinary localization string, not a payload."}\n',
        )
        zf.writestr(
            "data/demo/storage/a.json",
            (
                '{"stored":"AAECAwQFBgcICQoLDA0ODw==",'
                '"data":"CxBXXqXsswI5QIdOFSzjEig/Zs20u4rZeA/mDXS7isE="}\n'
            ),
        )
        zf.writestr("data/demo/structures/room.nbt", b"\x1f\x8b" + b"\x00" * 96)
    return jar_path


def test_java_detect_suspicious_blobs_reports_encoded_and_resource_anomalies(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_detect_suspicious_blobs import build_tool

    jar = _compile_suspicious_blob_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.finding_count >= 5
    assert result.summary_by_state["encoded_constant"] >= 1
    assert result.summary_by_state["decoder_nearby"] >= 1
    assert result.summary_by_state["decoded_to_classloader"] >= 2
    assert result.summary_by_state["compressed_blob"] >= 1
    assert result.summary_by_state["encrypted_or_random_blob"] >= 1
    assert result.summary_by_state["decoded_to_native_load"] >= 1
    assert result.summary_by_category["archive_resource_anomaly"] >= 3
    assert result.summary_by_category["encoded_resource_secret_blob"] >= 1
    assert all(f.value is None for f in result.findings)
    assert all(f.redacted_value_hash for f in result.findings if f.value_length)
    assert any(
        f.class_name == "SuspiciousBlobFixture"
        and f.method_name == "loadHiddenClass"
        and f.state == "decoded_to_classloader"
        for f in result.findings
    )
    assert any(
        f.path == "payload/macho-fat.dat" and f.state == "decoded_to_native_load"
        for f in result.findings
    )
    assert not any("example-dependency.jar" in f.path for f in result.findings)
    assert not any("lang/en_us.json" in f.path for f in result.findings)
    assert not any("structures/room.nbt" in f.path for f in result.findings)
    assert not any("META-INF/TESTSIGN.RSA" in f.path for f in result.findings)
    assert any(
        f.path == "data/demo/storage/a.json"
        and f.state == "encrypted_or_random_blob"
        and f.category == "encoded_resource_secret_blob"
        for f in result.findings
    )
    assert any(n.kind == NodeKind.java_suspicious_blob for n in ctx.kb.nodes())


def test_java_detect_suspicious_blobs_ignores_non_zip_inputs(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_detect_suspicious_blobs import build_tool

    sample = tmp_path / "native.bin"
    sample.write_bytes(b"\x7fELFnot-a-jar")
    ctx = _ctx(sample)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(sample)))

    assert result.finding_count == 0
    assert result.stop_reasons == ["input_not_zip"]


def test_memory_agent_registers_java_detect_suspicious_blobs() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_detect_suspicious_blobs" in agent._function_toolset.tools
