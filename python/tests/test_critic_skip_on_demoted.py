"""F6: critic must skip findings already demoted by L4 verifier."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from glaurung.llm.finding_critic import critique_report
from glaurung.llm.finding_verifier import _AnalysedFunction, _BinaryContext
from glaurung.llm.findings import (
    Evidence, FindingsReport, FunctionRef, VulnerabilityFinding,
)


pytestmark = pytest.mark.asyncio


def _ctx() -> _BinaryContext:
    f = _AnalysedFunction("vuln", 0x100, 0x200)
    return _BinaryContext(
        binary_path="/fake",
        functions_by_va={0x100: f},
        functions_by_name={"vuln": [f]},
        imports={"strcpy"},
        decompile_cache={0x100: "fn vuln { call strcpy }"},
    )


def _ev():
    return [Evidence(kind="disasm", location="0x140001500",
                     text="call strcpy")]


def _healthy_finding():
    return VulnerabilityFinding(
        cwe="CWE-121",
        function=FunctionRef(name="vuln", va=0x100),
        root_cause="strcpy of caller-controlled buffer into stack array",
        evidence=_ev(),
        confidence="high",
    )


def _demoted_finding():
    """A finding L4 has flagged: confidence=low, verification_issues
    non-empty. Critic should skip this without an LLM call."""
    f = VulnerabilityFinding(
        cwe="CWE-121",
        function=FunctionRef(name="ghost", va=0xdeadbeef),
        root_cause="strcpy of caller-controlled buffer into stack array",
        evidence=_ev(),
        confidence="low",
    )
    f.verification_issues = [
        "function 'ghost' not found in analysis",
    ]
    return f


async def test_critic_skips_demoted_finding_no_llm_call():
    """A finding L4 already demoted must NOT trigger a critic API call."""
    report = FindingsReport(
        binary_path="/fake",
        findings=[_demoted_finding()],
    )
    with patch("glaurung.llm.finding_critic.critique_finding",
               new_callable=AsyncMock) as mock_crit:
        await critique_report(report, model_name="openai:gpt-5.4-mini",
                              binary_ctx=_ctx())

    # Zero LLM calls.
    mock_crit.assert_not_called()
    # Verdict + critique synthesized locally from the L4 issue.
    f = report.findings[0]
    assert f.evidence_supports_claim == "false"
    assert f.critique.startswith("skipped (L4 verifier already flagged):")
    assert "function 'ghost' not found in analysis" in f.critique


async def test_critic_runs_on_healthy_finding():
    """A finding L4 did NOT demote must still go through the critic."""
    report = FindingsReport(
        binary_path="/fake",
        findings=[_healthy_finding()],
    )
    with patch("glaurung.llm.finding_critic.critique_finding",
               new_callable=AsyncMock) as mock_crit:
        await critique_report(report, model_name="openai:gpt-5.4-mini",
                              binary_ctx=_ctx())

    mock_crit.assert_called_once()


async def test_critic_skips_demoted_runs_healthy_in_same_report():
    """Mixed report: critic runs exactly once (on the healthy finding),
    the demoted one is short-circuited."""
    report = FindingsReport(
        binary_path="/fake",
        findings=[_demoted_finding(), _healthy_finding()],
    )
    with patch("glaurung.llm.finding_critic.critique_finding",
               new_callable=AsyncMock) as mock_crit:
        await critique_report(report, model_name="openai:gpt-5.4-mini",
                              binary_ctx=_ctx())

    assert mock_crit.call_count == 1
    # The healthy finding was the one critiqued.
    called_with = mock_crit.call_args.args[0]
    assert called_with.function.name == "vuln"


async def test_force_critique_overrides_skip():
    """force_critique=True must run the critic even on a demoted finding."""
    report = FindingsReport(
        binary_path="/fake",
        findings=[_demoted_finding()],
    )
    with patch("glaurung.llm.finding_critic.critique_finding",
               new_callable=AsyncMock) as mock_crit:
        await critique_report(report, model_name="openai:gpt-5.4-mini",
                              binary_ctx=_ctx(), force_critique=True)

    mock_crit.assert_called_once()


async def test_critic_doesnt_skip_low_confidence_without_verifier_issues():
    """Finding with confidence='low' but EMPTY verification_issues
    (operator-tagged low confidence, not L4-flagged) should still go
    through the critic."""
    f = VulnerabilityFinding(
        cwe="CWE-121",
        function=FunctionRef(name="vuln", va=0x100),
        root_cause="strcpy of caller-controlled buffer into stack array",
        evidence=_ev(),
        confidence="low",
        # verification_issues left default-empty
    )
    report = FindingsReport(binary_path="/fake", findings=[f])
    with patch("glaurung.llm.finding_critic.critique_finding",
               new_callable=AsyncMock) as mock_crit:
        await critique_report(report, model_name="openai:gpt-5.4-mini",
                              binary_ctx=_ctx())
    mock_crit.assert_called_once()
