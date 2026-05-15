from __future__ import annotations

import zipfile
from pathlib import Path

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.kb.models import NodeKind


def _ctx(path: Path) -> MemoryContext:
    art = g.triage.analyze_path(str(path), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(path), artifact=art)
    import_triage(ctx.kb, art, str(path))
    return ctx


def _config_fixture(tmp_path: Path) -> tuple[Path, Path]:
    jar_path = tmp_path / "config-fixture.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        zf.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nMain-Class: demo.App\nImplementation-Version: 1.2.3\n",
        )
        zf.writestr("META-INF/services/java.lang.Runnable", "demo.ServiceImpl\n")
        zf.writestr(
            "config/default.properties",
            "telemetry.enabled=true\napi.token=secret-token-value-1234567890\n",
        )
        zf.writestr(
            "assets/demo/config.json",
            '{"endpoint": "https://example.invalid/api", "enabled": false, "limit": 3}',
        )
    config_root = tmp_path / "config"
    config_root.mkdir()
    (config_root / "demo.toml").write_text(
        'network.enabled = false\nname = "demo"\n',
        encoding="utf-8",
    )
    return jar_path, config_root


def test_java_extract_config_surface_reports_resources_and_redacts_secrets(
    tmp_path: Path,
) -> None:
    from glaurung.llm.tools.java_extract_config_surface import build_tool

    jar, config_root = _config_fixture(tmp_path)
    ctx = _ctx(jar)
    tool = build_tool()

    result = tool.run(
        ctx,
        ctx.kb,
        tool.input_model(path=str(jar), config_roots=[str(config_root)]),
    )

    by_key = {(binding.path, binding.key): binding for binding in result.bindings}
    assert ("META-INF/MANIFEST.MF", "Main-Class") in by_key
    assert (
        "META-INF/services/java.lang.Runnable",
        "service:java.lang.Runnable",
    ) in by_key
    assert ("config/default.properties", "telemetry.enabled") in by_key
    assert ("assets/demo/config.json", "endpoint") in by_key
    assert (str(config_root / "demo.toml"), "network.enabled") in by_key

    token = by_key[("config/default.properties", "api.token")]
    assert token.value is None
    assert token.redacted_value_hash is not None
    assert token.value_kind == "redacted"
    assert result.binding_count == len(result.bindings)
    assert any(n.kind == NodeKind.java_config_key for n in ctx.kb.nodes())


def test_memory_agent_registers_java_extract_config_surface() -> None:
    from glaurung.llm.agents.memory_agent import create_memory_agent

    agent = create_memory_agent(model="test")

    assert "java_extract_config_surface" in agent._function_toolset.tools
