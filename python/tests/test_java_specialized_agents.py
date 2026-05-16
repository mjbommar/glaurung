from __future__ import annotations


def test_java_specialized_agents_register_context_tool() -> None:
    from glaurung.llm.agents.java import (
        JavaSecurityAssessment,
        JavaTriageAssessment,
        build_java_recovery_agent,
        build_java_security_agent,
        build_java_triage_agent,
    )

    triage = build_java_triage_agent(model="test")
    security = build_java_security_agent(model="test")
    recovery = build_java_recovery_agent(model="test")

    assert triage.output_type is JavaTriageAssessment
    assert security.output_type is JavaSecurityAssessment
    assert "java_agent_context" in triage._function_toolset.tools
    assert "java_agent_context" in security._function_toolset.tools
    assert "java_recovery_report" in recovery._function_toolset.tools


def test_java_specialized_agents_use_focused_provider_safe_toolsets() -> None:
    from glaurung.llm.agents.java import (
        build_java_recovery_agent,
        build_java_security_agent,
        build_java_triage_agent,
    )
    from glaurung.llm.agents.memory_agent import create_memory_agent

    triage_tools = build_java_triage_agent(model="test")._function_toolset.tools
    security_tools = build_java_security_agent(model="test")._function_toolset.tools
    recovery_tools = build_java_recovery_agent(model="test")._function_toolset.tools

    assert len(triage_tools) <= 20
    assert len(security_tools) <= 20
    assert len(recovery_tools) <= 20
    assert all(tool.strict is True for tool in triage_tools.values())
    assert all(tool.strict is True for tool in security_tools.values())
    assert all(tool.strict is True for tool in recovery_tools.values())

    assert {
        "java_agent_context",
        "java_risk_report",
        "java_trace_to_sink",
        "java_reachability",
        "java_detect_security_sensitive_behavior",
        "java_detect_suspicious_blobs",
    }.issubset(security_tools)
    assert "java_recover_project" not in security_tools
    assert "view_hex" not in security_tools

    assert {
        "java_agent_context",
        "java_recover_project",
        "java_recovery_report",
        "java_decompile_archive",
        "java_compile_recovered_project",
        "java_validate_recovered_application",
    }.issubset(recovery_tools)
    assert "java_risk_report" not in recovery_tools

    full_agent_tools = create_memory_agent(model="test")._function_toolset.tools
    assert "view_hex" in full_agent_tools
    assert "java_recover_project" in full_agent_tools
    assert "java_risk_report" in full_agent_tools


def test_java_specialized_agents_relax_strict_tools_for_anthropic(monkeypatch) -> None:
    from glaurung.llm.agents.java import build_java_security_agent

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    anthropic_tools = build_java_security_agent(
        model="anthropic:claude-opus-4-7"
    )._function_toolset.tools
    openai_tools = build_java_security_agent(
        model="openai:gpt-5.5"
    )._function_toolset.tools

    assert anthropic_tools
    assert all(tool.strict is False for tool in anthropic_tools.values())
    assert all(tool.strict is True for tool in openai_tools.values())


def test_java_agent_context_is_seeded_with_specialized_profile(tmp_path) -> None:
    import shutil
    import subprocess

    import glaurung as g
    from glaurung.llm.agents.java import prime_java_agent_context
    from glaurung.llm.context import MemoryContext
    from glaurung.llm.kb.adapters import import_triage

    if shutil.which("javac") is None or shutil.which("jar") is None:
        import pytest

        pytest.skip("javac and jar are required for generated Java fixture")

    src = tmp_path / "src"
    out = tmp_path / "classes"
    src.mkdir()
    out.mkdir()
    (src / "AgentSeedFixture.java").write_text(
        """
public class AgentSeedFixture {
    public static void main(String[] args) throws Exception {
        new ProcessBuilder(args).start();
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
            str(src / "AgentSeedFixture.java"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    jar = tmp_path / "agent-seed-fixture.jar"
    subprocess.run(
        [
            "jar",
            "--create",
            "--file",
            str(jar),
            "--main-class",
            "AgentSeedFixture",
            "-C",
            str(out),
            ".",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    art = g.triage.analyze_path(str(jar), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(jar), artifact=art)
    import_triage(ctx.kb, art, str(jar))

    result = prime_java_agent_context(ctx, profile="security")

    assert result.profile == "security"
    assert result.security is not None
    assert result.security.sensitive_finding_count >= 1
    assert getattr(ctx, "_java_agent_context_seeded_profiles") == {"security"}
    assert getattr(ctx, "_tool_calls")[-1]["args"]["profile"] == "security"


def test_java_agent_output_models_capture_evidence_and_next_steps() -> None:
    from glaurung.llm.agents.java import JavaFinding, JavaSecurityAssessment

    finding = JavaFinding(
        title="Runtime exec reachable from main",
        severity="high",
        confidence=0.8,
        evidence=["java_risk_report:risk-1"],
        next_action="Trace the call path to Runtime.exec.",
    )
    report = JavaSecurityAssessment(
        summary="One high-risk process execution path needs review.",
        findings=[finding],
        recommended_next_tools=["java_trace_to_sink"],
        confidence=0.75,
    )

    assert report.findings[0].severity == "high"
    assert report.recommended_next_tools == ["java_trace_to_sink"]
