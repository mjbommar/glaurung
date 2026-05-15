from __future__ import annotations

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


def _unsigned_jar(tmp_path: Path) -> Path:
    jar = tmp_path / "unsigned.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("fixture.txt", "hello\n")
    return jar


def _signed_jar(tmp_path: Path) -> Path:
    if shutil.which("keytool") is None or shutil.which("jarsigner") is None:
        pytest.skip("keytool and jarsigner are required for signed JAR fixture")

    jar = _unsigned_jar(tmp_path)
    keystore = tmp_path / "fixture-keystore.p12"
    storepass = "changeit"
    alias = "fixture"
    subprocess.run(
        [
            "keytool",
            "-genkeypair",
            "-alias",
            alias,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "1",
            "-keystore",
            str(keystore),
            "-storetype",
            "PKCS12",
            "-storepass",
            storepass,
            "-keypass",
            storepass,
            "-dname",
            "CN=Glaurung Test, OU=Tests, O=Glaurung, L=Test, ST=Test, C=US",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "jarsigner",
            "-keystore",
            str(keystore),
            "-storepass",
            storepass,
            "-keypass",
            storepass,
            str(jar),
            alias,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar


def test_java_verify_signatures_reports_unsigned_jar(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_verify_signatures import build_tool

    jar = _unsigned_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    if not result.jarsigner_available:
        assert result.state == "tool_missing"
    else:
        assert result.state == "unsigned"
        assert result.verification_attempted
    assert not result.signed_metadata_present
    assert any(
        node.kind == NodeKind.evidence
        and node.props.get("tool") == "java_verify_signatures"
        for node in ctx.kb.nodes()
    )


def test_java_verify_signatures_reports_signed_jar(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_verify_signatures import build_tool

    jar = _signed_jar(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(jar)))

    assert result.jarsigner_available
    assert result.verification_attempted
    assert result.signed_metadata_present
    assert result.state in {"verified", "verified_with_warnings"}
    assert result.signed_entry_count >= 1
    assert {entry.entry_name for entry in result.signature_entries} >= {
        "META-INF/FIXTURE.SF",
        "META-INF/FIXTURE.RSA",
    }
    assert result.output_excerpt


def test_memory_agent_registers_java_verify_signatures() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_verify_signatures" in agent._function_toolset.tools
