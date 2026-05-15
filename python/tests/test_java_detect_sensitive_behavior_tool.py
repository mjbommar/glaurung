from __future__ import annotations

import shutil
import subprocess
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


def _compile_sensitive_fixture(tmp_path: Path) -> Path:
    if shutil.which("javac") is None or shutil.which("jar") is None:
        pytest.skip("javac and jar are required for generated Java fixture")
    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "SensitiveFixture.java").write_text(
        """
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.lang.reflect.Method;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;

public class SensitiveFixture {
    public void process() throws Exception {
        new ProcessBuilder("sh", "-c", "echo no").start();
        Runtime.getRuntime().exec("echo no");
    }

    public void network() throws Exception {
        HttpClient.newHttpClient();
        URI.create("https://example.invalid/ping");
        new Socket("127.0.0.1", 65535).close();
    }

    public void files(Path p) throws Exception {
        Files.writeString(p.resolve("x"), "no");
        Files.deleteIfExists(p.resolve("x"));
    }

    public void reflect() throws Exception {
        Class<?> cls = Class.forName("java.lang.String");
        Method method = cls.getDeclaredMethod("trim");
        method.setAccessible(true);
    }

    public Object deserialize(InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();
    }

    public void crypto() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
        KeyStore.getInstance("JKS");
    }

    public void schedule(ScheduledExecutorService service) {
        service.scheduleAtFixedRate(() -> {}, 1, 1, TimeUnit.SECONDS);
    }

    public void configuration() {
        System.getenv("SENSITIVE_FIXTURE_TOKEN");
        System.getProperty("sensitive.fixture.enabled");
    }
}
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
            str(src / "SensitiveFixture.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar_path = tmp_path / "sensitive.jar"
    subprocess.run(
        ["jar", "--create", "--file", str(jar_path), "-C", str(out), "."],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def _mapping_file(tmp_path: Path) -> Path:
    path = tmp_path / "mappings.txt"
    path.write_text(
        """
com.example.SensitiveFixture -> SensitiveFixture:
    void launchProcess() -> process
    void network() -> network
    void files(java.nio.file.Path) -> files
    void reflect() -> reflect
    java.lang.Object deserialize(java.io.InputStream) -> deserialize
    void crypto() -> crypto
    void schedule(java.util.concurrent.ScheduledExecutorService) -> schedule
    void configuration() -> configuration
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return path


def test_java_detect_sensitive_behavior_reports_static_sinks(tmp_path: Path) -> None:
    from glaurung.llm.tools.java_detect_security_sensitive_behavior import build_tool

    jar = _compile_sensitive_fixture(tmp_path)
    mapping = _mapping_file(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), mapping_path=str(mapping)),
    )

    categories = {finding.category for finding in result.findings}
    assert {
        "process",
        "network",
        "filesystem",
        "reflection",
        "serialization",
        "crypto",
        "scheduler",
        "environment",
    } <= categories
    assert result.class_count == 1
    assert result.finding_count == len(result.findings)
    assert any(
        finding.class_name == "SensitiveFixture"
        and finding.mapped_class_name == "com.example.SensitiveFixture"
        and finding.mapped_method_names == ["launchProcess"]
        and finding.method_name == "process"
        and finding.owner == "java/lang/ProcessBuilder"
        and finding.bci is not None
        for finding in result.findings
    )
    assert any(
        finding.category == "network"
        and finding.owner in {"java/net/http/HttpClient", "java/net/Socket"}
        for finding in result.findings
    )
    assert any(n.kind == NodeKind.java_sensitive_sink for n in ctx.kb.nodes())


def test_java_detect_sensitive_behavior_ignores_non_zip_inputs(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_detect_security_sensitive_behavior import build_tool

    sample = tmp_path / "native.bin"
    sample.write_bytes(b"\x7fELFnot-a-jar")
    ctx = _ctx(sample)
    tool = build_tool()

    result = tool.run(ctx, ctx.kb, tool.input_model(path=str(sample)))

    assert result.class_count == 0
    assert result.finding_count == 0
    assert result.parse_error_count == 1
    assert result.findings == []


def test_memory_agent_registers_java_detect_sensitive_behavior() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_detect_security_sensitive_behavior" in agent._function_toolset.tools
