"""Tests for L2: self-critique evidence-grading pass.

The critic is an LLM call so we mock it; the focus is on the wiring
(prompt construction, verdict parsing, confidence demotion).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from glaurung.llm.finding_critic import (
    _resolve_evidence_for_prompt,
    critique_finding,
    _CriticVerdict,
)
from glaurung.llm.finding_verifier import _AnalysedFunction, _BinaryContext
from glaurung.llm.findings import (
    AddressRef,
    Evidence,
    FunctionRef,
    VulnerabilityFinding,
)


pytestmark = pytest.mark.asyncio


def _fake_ctx() -> _BinaryContext:
    fns_by_va = {
        0x140001480: _AnalysedFunction("vuln", 0x140001480, 0x140001500),
        0x140002000: _AnalysedFunction("__pei386_runtime_relocator",
                                       0x140002000, 0x140002100),
    }
    fns_by_name = {fn.name: [fn] for fn in fns_by_va.values()}
    return _BinaryContext(
        binary_path="/fake/path",
        functions_by_va=fns_by_va,
        functions_by_name=fns_by_name,
        imports={"strcpy", "printf", "malloc"},
        decompile_cache={
            0x140001480: "fn vuln {\n  call strcpy\n  call __mingw_printf\n}\n",
            0x140002000: "fn pei386 {\n  reloc table walk\n}\n",
        },
    )


def _strcpy_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        cwe="CWE-121",
        function=FunctionRef(name="vuln", va=0x140001480),
        bug_site=AddressRef(va=0x140001488),
        root_cause="strcpy of caller-controlled argv[1] into 32-byte stack buffer",
        evidence=[
            Evidence(kind="import", location="strcpy", text="strcpy imported"),
            Evidence(kind="disasm", location="0x140001488",
                     text="call strcpy"),
        ],
        confidence="high",
    )


# ---- evidence resolution for the prompt ----

async def test_resolve_evidence_includes_each_evidence_line():
    f = _strcpy_finding()
    ctx = _fake_ctx()
    block = _resolve_evidence_for_prompt(f, ctx)
    # Each evidence entry has a header + agent quote + resolution line
    assert "kind=import" in block
    assert "kind=disasm" in block
    assert "strcpy" in block  # import sym
    assert "present in PE import table" in block
    assert "inside function vuln" in block


async def test_resolve_evidence_flags_va_outside_any_function():
    f = _strcpy_finding()
    f.evidence = [Evidence(kind="disasm", location="0xffffff00",
                           text="bogus")]
    ctx = _fake_ctx()
    block = _resolve_evidence_for_prompt(f, ctx)
    assert "NOT inside any" in block


async def test_resolve_evidence_includes_verifier_issues():
    f = _strcpy_finding()
    f.verification_issues = ["disasm evidence at 0xffffff00 is not inside any analyzed function"]
    ctx = _fake_ctx()
    block = _resolve_evidence_for_prompt(f, ctx)
    assert "verifier_issues:" in block
    assert "0xffffff00" in block


# ---- critique_finding: wiring with mocked critic ----

async def test_critique_finding_true_keeps_confidence():
    f = _strcpy_finding()
    ctx = _fake_ctx()

    mock_result = SimpleNamespace(
        output=_CriticVerdict(
            evidence_supports_claim="true",
            critique="strcpy at 0x140001488 inside vuln matches a stack-overflow claim",
        )
    )
    with patch("pydantic_ai.Agent") as MockAgent:
        instance = MockAgent.return_value
        instance.run = AsyncMock(return_value=mock_result)
        await critique_finding(f, ctx, model_name="anthropic:claude-haiku-4-5")

    assert f.evidence_supports_claim == "true"
    assert f.confidence == "high"
    assert "strcpy" in f.critique


async def test_critique_finding_partial_demotes_high_to_medium():
    f = _strcpy_finding()
    assert f.confidence == "high"
    ctx = _fake_ctx()

    mock_result = SimpleNamespace(
        output=_CriticVerdict(
            evidence_supports_claim="partial",
            critique="the cited copy is a bounded strncpy(., ., 63), not an unbounded strcpy",
        )
    )
    with patch("pydantic_ai.Agent") as MockAgent:
        instance = MockAgent.return_value
        instance.run = AsyncMock(return_value=mock_result)
        await critique_finding(f, ctx, model_name="anthropic:claude-haiku-4-5")

    assert f.evidence_supports_claim == "partial"
    assert f.confidence == "medium"
    assert "bounded" in f.critique


async def test_critique_finding_false_demotes_to_low():
    """The kilo.exe failure mode: agent claimed CWE-190 in a function that
    turned out to be mingw __pei386_runtime_relocator (CRT helper).
    Critic should mark this 'false' and demote to low."""
    f = VulnerabilityFinding(
        cwe="CWE-190",
        function=FunctionRef(name="__pei386_runtime_relocator", va=0x140002000),
        bug_site=AddressRef(va=0x140002010),
        root_cause="multiplication of count by element size before allocator wraps on 32-bit",
        evidence=[
            Evidence(kind="disasm", location="0x140002010",
                     text="imul edx, ecx ; no overflow check"),
        ],
        confidence="high",
    )
    ctx = _fake_ctx()

    mock_result = SimpleNamespace(
        output=_CriticVerdict(
            evidence_supports_claim="false",
            critique="cited function is the mingw __pei386_runtime_relocator runtime helper, not application code",
        )
    )
    with patch("pydantic_ai.Agent") as MockAgent:
        instance = MockAgent.return_value
        instance.run = AsyncMock(return_value=mock_result)
        await critique_finding(f, ctx, model_name="anthropic:claude-haiku-4-5")

    assert f.evidence_supports_claim == "false"
    assert f.confidence == "low"
    assert "runtime helper" in f.critique


async def test_critique_finding_unknown_verdict_treated_as_partial():
    """Defensive: if the model emits something unexpected, default to 'partial'
    rather than raising or trusting it."""
    f = _strcpy_finding()
    ctx = _fake_ctx()
    mock_result = SimpleNamespace(
        output=_CriticVerdict(
            evidence_supports_claim="unsure-but-maybe",
            critique="ambiguous evidence; further analysis recommended",
        )
    )
    with patch("pydantic_ai.Agent") as MockAgent:
        instance = MockAgent.return_value
        instance.run = AsyncMock(return_value=mock_result)
        await critique_finding(f, ctx, model_name="anthropic:claude-haiku-4-5")
    assert f.evidence_supports_claim == "partial"
