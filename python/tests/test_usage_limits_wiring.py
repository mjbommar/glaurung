"""F2 regression: every LLM-firing ``Agent.run()`` site must pass
``usage_limits=`` so pydantic-ai's 50-request default never silently
takes effect."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from glaurung.llm.agents.base import ExecutionState, ModelHyperparameters


pytestmark = pytest.mark.asyncio


class _FakeAgent:
    def __init__(self):
        self.run = AsyncMock(return_value=SimpleNamespace(output="ok"))


def _params():
    return ModelHyperparameters(temperature=0.5, max_tokens=2048)


async def test_single_pass_forwards_usage_limits():
    pytest.importorskip("pydantic_ai")
    from glaurung.llm.agents.single_pass import SinglePassAgent, SinglePassConfig

    fake = _FakeAgent()
    sp = SinglePassAgent(
        base_agent=fake,
        config=SinglePassConfig(optimize_context=False, pre_populate_kb=False),
        model="openai:gpt-5.4-mini",
    )

    from unittest.mock import MagicMock
    context = SimpleNamespace(kb=MagicMock())
    state = ExecutionState()

    await sp._execute_with_monitoring("q", context, state, _params())

    fake.run.assert_awaited_once()
    call = fake.run.await_args
    assert "usage_limits" in call.kwargs, (
        f"single_pass missed usage_limits; got {list(call.kwargs.keys())}"
    )
    ul = call.kwargs["usage_limits"]
    # Default request_limit is 12 per LLMConfig.
    assert ul.request_limit == 12


async def test_iterative_refinement_forwards_usage_limits():
    pytest.importorskip("pydantic_ai")
    from glaurung.llm.agents.iterative_refinement import (
        IterativeRefinementAgent, IterativeConfig,
    )

    fake = _FakeAgent()
    it = IterativeRefinementAgent(
        base_agent=fake, config=IterativeConfig(),
        model="openai:gpt-5.4-mini",
    )

    from unittest.mock import MagicMock
    context = SimpleNamespace(kb=MagicMock())
    state = ExecutionState()
    await it._execute_iteration("prompt", context, _params(), state)

    fake.run.assert_awaited_once()
    ul = fake.run.await_args.kwargs.get("usage_limits")
    assert ul is not None
    assert ul.request_limit == 12


async def test_iterative_agents_iterative_forwards_usage_limits():
    """Also covers the simpler `agents/iterative.py` path (the older
    IterativeAgent wrapper distinct from IterativeRefinementAgent)."""
    pytest.importorskip("pydantic_ai")
    from glaurung.llm.agents.iterative import (
        IterativeAgent, RefinementStrategy,
    )

    fake = _FakeAgent()
    strategy = RefinementStrategy(max_iterations=1)
    it = IterativeAgent(base_agent=fake, strategy=strategy)

    # Stub _evaluate_confidence so the loop exits after one iteration
    # without inspecting result content.
    with patch.object(it, "_evaluate_confidence",
                      AsyncMock(return_value=1.0)):
        # run_with_refinement is the public entry point; pass a
        # MemoryContext-shaped object that won't be inspected.
        ctx = SimpleNamespace(kb=SimpleNamespace(), file_path="/x")
        await it.run_with_refinement("q", ctx)

    fake.run.assert_awaited()
    ul = fake.run.await_args.kwargs.get("usage_limits")
    assert ul is not None, (
        "iterative.py agent.run() missed usage_limits"
    )


async def test_findings_runner_forwards_usage_limits():
    """run_findings_pass must pass usage_limits with request_limit=8."""
    pytest.importorskip("pydantic_ai")

    fake = _FakeAgent()
    fake.run.return_value = SimpleNamespace(
        output=_make_empty_findings_report()
    )

    # findings_runner imports lazily; patch the source modules.
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

    fake.run.assert_awaited()
    ul = fake.run.await_args.kwargs.get("usage_limits")
    assert ul is not None
    # findings_runner overrides request_limit to 8 (tighter than the
    # config default of 12).
    assert ul.request_limit == 8


def _make_empty_findings_report():
    from glaurung.llm.findings import FindingsReport
    return FindingsReport(binary_path="/nonexistent.exe", findings=[])


async def test_finding_critic_forwards_usage_limits():
    """critique_finding must pass usage_limits=2/tool_calls_limit=0."""
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
    f = VulnerabilityFinding(
        cwe="CWE-121",
        function=FunctionRef(name="f", va=0x100),
        root_cause="strcpy of caller-controlled buffer; no length check",
        evidence=[Evidence(kind="import", location="strcpy",
                           text="strcpy imported")],
    )

    fake = _FakeAgent()
    from glaurung.llm.finding_critic import _CriticVerdict
    fake.run.return_value = SimpleNamespace(
        output=_CriticVerdict(
            evidence_supports_claim="true",
            critique="evidence resolves cleanly; claim supported",
        )
    )
    with patch("pydantic_ai.Agent", return_value=fake):
        from glaurung.llm.finding_critic import critique_finding
        await critique_finding(f, ctx, model_name="openai:gpt-5.4-mini")

    fake.run.assert_awaited()
    ul = fake.run.await_args.kwargs.get("usage_limits")
    assert ul is not None
    assert ul.request_limit == 2
    assert ul.tool_calls_limit == 0  # critic must not call tools
