"""F3: ensure findings_runner + critic emit reasonable max_tokens
budgets sourced from LLMConfig defaults (May-2026 model capacity)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest


pytestmark = pytest.mark.asyncio


class _FakeAgent:
    def __init__(self):
        self.run = AsyncMock(return_value=SimpleNamespace(output=None))


async def test_findings_runner_passes_default_max_output_tokens():
    pytest.importorskip("pydantic_ai")
    from glaurung.llm.findings import FindingsReport
    from glaurung.llm.usage_limits import default_max_output_tokens

    fake = _FakeAgent()
    fake.run.return_value = SimpleNamespace(
        output=FindingsReport(binary_path="/x", findings=[])
    )

    with patch("glaurung.llm.agents.memory_foundation.create_foundation_agent",
               return_value=fake), \
         patch("glaurung.llm.agents.memory_agent.register_analysis_tools",
               side_effect=lambda a, **kw: a), \
         patch("glaurung.triage.analyze_path",
               return_value=SimpleNamespace()), \
         patch("glaurung.llm.kb.adapters.import_triage",
               return_value=None), \
         patch("glaurung.llm.finding_verifier._BinaryContext.build",
               return_value=None), \
         patch("glaurung.llm.finding_verifier.verify_report",
               return_value=None):
        from glaurung.llm.findings_runner import run_findings_pass
        args = SimpleNamespace(
            model="openai:gpt-5.4-mini", max_read_bytes=1024,
            max_file_size=1024, max_functions=1, max_instructions=100,
            disasm_window=512, skip_critique=True,
        )
        await run_findings_pass("/nonexistent.exe", args)

    ms = fake.run.await_args.kwargs.get("model_settings")
    assert ms is not None
    # ModelSettings is a TypedDict; check by key.
    assert ms["max_tokens"] == default_max_output_tokens()
    assert ms["max_tokens"] >= 16_384, (
        "May-2026 models can do 64K out; <=4K is the old bug"
    )


async def test_finding_critic_passes_4k_max_tokens_not_512():
    pytest.importorskip("pydantic_ai")
    from glaurung.llm.findings import (
        VulnerabilityFinding, FunctionRef, Evidence,
    )
    from glaurung.llm.finding_verifier import _AnalysedFunction, _BinaryContext

    ctx = _BinaryContext(
        binary_path="/fake",
        functions_by_va={0x100: _AnalysedFunction("f", 0x100, 0x200)},
        functions_by_name={"f": [_AnalysedFunction("f", 0x100, 0x200)]},
        imports={"strcpy"},
        decompile_cache={0x100: "fn f { call strcpy }"},
    )
    finding = VulnerabilityFinding(
        cwe="CWE-121",
        function=FunctionRef(name="f", va=0x100),
        root_cause="strcpy of caller-controlled buffer with no length cap",
        evidence=[Evidence(kind="import", location="strcpy",
                           text="strcpy imported")],
    )

    fake = _FakeAgent()
    from glaurung.llm.finding_critic import _CriticVerdict
    fake.run.return_value = SimpleNamespace(
        output=_CriticVerdict(
            evidence_supports_claim="true",
            critique="cited evidence supports claim",
        )
    )
    with patch("pydantic_ai.Agent", return_value=fake):
        from glaurung.llm.finding_critic import critique_finding
        await critique_finding(finding, ctx, model_name="openai:gpt-5.4-mini")

    ms = fake.run.await_args.kwargs.get("model_settings")
    assert ms is not None
    assert ms["max_tokens"] >= 2048, (
        f"critic max_tokens too tight: {ms.get('max_tokens')}; "
        "Opus 4.7 with extended thinking burns ~2-8K just thinking"
    )
