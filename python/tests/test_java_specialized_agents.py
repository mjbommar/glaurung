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
