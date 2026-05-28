"""Tests for F5: --max-cost-usd circuit breaker + partial-findings preservation."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from glaurung.llm.cwe_sweep import (
    CWEClassSpec,
    sweep_binary,
)
from glaurung.llm.findings import (
    Evidence, FindingsReport, FunctionRef, VulnerabilityFinding,
)
from glaurung.llm.usage_tracker import (
    CostBudgetExceeded, UsageTracker, get_tracker, reset_tracker,
)


pytestmark = pytest.mark.asyncio


def _ev():
    return [Evidence(kind="disasm", location="0x140001500", text="call strcpy")]


def _finding(cwe="CWE-121", fn="vuln", va=0x140001480):
    return VulnerabilityFinding(
        cwe=cwe, function=FunctionRef(name=fn, va=va),
        root_cause="strcpy of caller-controlled input into stack buffer",
        evidence=_ev(),
    )


async def test_sweep_returns_partial_findings_when_budget_exceeded():
    """When CostBudgetExceeded fires mid-sweep, the merged report must
    contain findings from already-completed classes."""
    classes = [
        CWEClassSpec(id="CWE-121", title="A", prompt="p1"),
        CWEClassSpec(id="CWE-134", title="B", prompt="p2"),
        CWEClassSpec(id="CWE-190", title="C", prompt="p3"),
    ]

    call_count = {"n": 0}

    async def fake_run(path, args):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return FindingsReport(
                binary_path=path,
                findings=[_finding(cwe="CWE-121")],
            )
        if call_count["n"] == 2:
            return FindingsReport(
                binary_path=path,
                findings=[_finding(cwe="CWE-134", fn="log_user_msg",
                                   va=0x140002000)],
            )
        # Third class hits the budget.
        raise CostBudgetExceeded("running cost $0.50 exceeds budget $0.40")

    with patch("glaurung.llm.cwe_sweep.run_findings_pass",
               side_effect=fake_run):
        merged = await sweep_binary(
            "/tmp/x.exe", SimpleNamespace(), classes=classes,
            max_parallel=1,
        )

    # Two classes ran, both produced a finding.
    cwes = sorted(f.cwe for f in merged.findings)
    assert cwes == ["CWE-121", "CWE-134"]
    # The merged report records the abort.
    assert merged.notes and "cost-budget" in merged.notes


async def test_sweep_no_budget_runs_all_classes():
    """With no budget set, sweep_binary fires every class."""
    classes = [
        CWEClassSpec(id="CWE-121", title="A", prompt="p1"),
        CWEClassSpec(id="CWE-134", title="B", prompt="p2"),
    ]

    async def fake_run(path, args):
        return FindingsReport(binary_path=path, findings=[])

    with patch("glaurung.llm.cwe_sweep.run_findings_pass",
               side_effect=fake_run) as m:
        await sweep_binary(
            "/tmp/x.exe", SimpleNamespace(), classes=classes,
            max_parallel=1,
        )

    assert m.call_count == 2


async def test_sweep_class_other_exception_recorded_does_not_kill_sweep():
    """Pre-existing behaviour: non-budget exception in one class becomes
    a [sweep-class-error] note; other classes still complete."""
    classes = [
        CWEClassSpec(id="CWE-121", title="A", prompt="p1"),
        CWEClassSpec(id="CWE-134", title="B", prompt="p2"),
    ]

    async def fake_run(path, args):
        if "CWE-121" in getattr(args, "cwe_class_prompt", ""):
            raise RuntimeError("rate limit")
        return FindingsReport(
            binary_path=path,
            findings=[_finding(cwe="CWE-134", fn="x", va=0x100)],
        )

    with patch("glaurung.llm.cwe_sweep.run_findings_pass",
               side_effect=fake_run):
        merged = await sweep_binary(
            "/tmp/x.exe", SimpleNamespace(), classes=classes,
            max_parallel=1,
        )

    # The successful class's finding survives.
    assert any(f.cwe == "CWE-134" for f in merged.findings)
    # The failure is noted.
    assert merged.notes and "rate limit" in merged.notes
    # But this WASN'T a cost-budget abort.
    assert "cost-budget" not in (merged.notes or "")


# ---- UsageTracker.set_budget_usd wiring ----

def test_tracker_set_budget_then_record_raises_at_threshold():
    t = UsageTracker(quiet=True)
    t.set_budget_usd(0.001)  # very tight
    # First small call: under budget.
    t.record(
        SimpleNamespace(usage=SimpleNamespace(
            input_tokens=1_000, output_tokens=0, requests=1,
        )),
        model="openai:gpt-5.4-mini", source="test",
    )
    # Second large call: pushes total over budget.
    with pytest.raises(CostBudgetExceeded):
        t.record(
            SimpleNamespace(usage=SimpleNamespace(
                input_tokens=10_000_000, output_tokens=0, requests=1,
            )),
            model="openai:gpt-5.4-mini", source="test",
        )


def test_tracker_set_budget_then_unset_clears():
    """set_budget_usd(None) must clear the prior budget so subsequent
    calls don't raise."""
    t = UsageTracker(quiet=True)
    t.set_budget_usd(0.00001)
    t.set_budget_usd(None)
    # Should NOT raise.
    t.record(
        SimpleNamespace(usage=SimpleNamespace(
            input_tokens=10_000_000, output_tokens=0, requests=1,
        )),
        model="openai:gpt-5.4-mini", source="test",
    )
    assert t.call_count() == 1
