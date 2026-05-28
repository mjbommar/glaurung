"""Tests for F4: UsageTracker session-wide cost aggregation."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from glaurung.llm.usage_tracker import (
    CostBudgetExceeded,
    PRICE_PER_MILLION_USD,
    UsageRecord,
    UsageTracker,
    estimate_cost_usd,
    get_tracker,
    reset_tracker,
)


# ---- estimate_cost_usd ----

def test_estimate_cost_usd_known_model():
    """gpt-5.4-mini at 1M input + 0.5M output should be predictable."""
    # 1M * $0.15/M + 0.5M * $0.60/M = 0.15 + 0.30 = $0.45
    cost = estimate_cost_usd("openai:gpt-5.4-mini",
                             input_tokens=1_000_000,
                             output_tokens=500_000)
    assert cost == pytest.approx(0.45, abs=1e-9)


def test_estimate_cost_usd_opus_expensive():
    """Confirm Opus 4.7 is priced ~10-100x mini -- catches accidental
    swaps between price-table rows."""
    mini = estimate_cost_usd("openai:gpt-5.4-mini",
                             input_tokens=100_000, output_tokens=2_000)
    opus = estimate_cost_usd("anthropic:claude-opus-4-7",
                             input_tokens=100_000, output_tokens=2_000)
    assert opus is not None and mini is not None
    assert opus > 10 * mini, (
        f"Opus should be much more expensive than mini "
        f"({opus} vs {mini}); price table drift?"
    )


def test_estimate_cost_usd_unknown_model_returns_none():
    assert estimate_cost_usd("openai:nonexistent-future", 100, 100) is None


def test_estimate_cost_usd_prefix_match():
    """A versioned model name like 'openai:gpt-5.4-mini-2025-01-01'
    should match the 'openai:gpt-5.4-mini' price entry."""
    cost = estimate_cost_usd(
        "openai:gpt-5.4-mini-2025-01-01",
        input_tokens=1_000_000, output_tokens=0,
    )
    assert cost == pytest.approx(0.15, abs=1e-9)


def test_price_table_includes_session_required_models():
    """Defensive: the models we standardize on must always be priced.
    Catches accidental removal during refactor."""
    required = {
        "openai:gpt-5.4-mini",
        "anthropic:claude-haiku-4-5",
        "anthropic:claude-opus-4-7",
    }
    assert required <= set(PRICE_PER_MILLION_USD.keys())


# ---- UsageTracker ----

def _fake_result(input_tokens=10_000, output_tokens=2_000, requests=3):
    usage = SimpleNamespace(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        requests=requests,
    )
    return SimpleNamespace(usage=usage, output="ok")


def test_tracker_records_a_call():
    t = UsageTracker(quiet=True)
    rec = t.record(_fake_result(), model="openai:gpt-5.4-mini",
                   source="test")
    assert isinstance(rec, UsageRecord)
    assert rec.input_tokens == 10_000
    assert rec.output_tokens == 2_000
    assert rec.cost_usd is not None
    assert t.call_count() == 1


def test_tracker_aggregates_across_calls():
    t = UsageTracker(quiet=True)
    for _ in range(3):
        t.record(_fake_result(input_tokens=1_000, output_tokens=500),
                 model="openai:gpt-5.4-mini", source="test")
    assert t.call_count() == 3
    assert t.total_input_tokens() == 3_000
    assert t.total_output_tokens() == 1_500
    # 3 * (1000 * $0.15/M + 500 * $0.60/M) = 3 * (0.00015 + 0.0003) = $0.00135
    assert t.total_cost_usd() == pytest.approx(0.00135, abs=1e-9)


def test_tracker_per_model_breakdown():
    t = UsageTracker(quiet=True)
    t.record(_fake_result(input_tokens=2_000),
             model="openai:gpt-5.4-mini", source="findings_runner")
    t.record(_fake_result(input_tokens=1_000),
             model="anthropic:claude-haiku-4-5", source="finding_critic")
    breakdown = t.per_model_breakdown()
    assert "openai:gpt-5.4-mini" in breakdown
    assert "anthropic:claude-haiku-4-5" in breakdown
    assert breakdown["openai:gpt-5.4-mini"]["calls"] == 1
    assert breakdown["openai:gpt-5.4-mini"]["input_tokens"] == 2_000


def test_tracker_unknown_model_records_null_cost_no_crash():
    t = UsageTracker(quiet=True)
    rec = t.record(_fake_result(), model="nonexistent:future-model",
                   source="test")
    assert rec.cost_usd is None
    # Total cost stays None (no priced records yet) rather than crashing.
    assert t.total_cost_usd() is None


def test_tracker_legacy_usage_field_names():
    """pydantic-ai older versions used request_tokens / response_tokens.
    The extractor must accept both."""
    legacy = SimpleNamespace(
        request_tokens=5_000, response_tokens=1_000, requests=2,
    )
    legacy_result = SimpleNamespace(usage=legacy, output="ok")
    t = UsageTracker(quiet=True)
    rec = t.record(legacy_result, model="openai:gpt-5.4-mini",
                   source="test")
    assert rec.input_tokens == 5_000
    assert rec.output_tokens == 1_000


def test_tracker_usage_callable():
    """pydantic-ai 1.x exposes usage as a method that returns RunUsage."""
    usage = SimpleNamespace(input_tokens=3_000, output_tokens=600,
                            requests=2)
    callable_result = SimpleNamespace(
        usage=lambda: usage, output="ok",
    )
    t = UsageTracker(quiet=True)
    rec = t.record(callable_result, model="openai:gpt-5.4-mini",
                   source="test")
    assert rec.input_tokens == 3_000
    assert rec.output_tokens == 600


def test_tracker_missing_usage_doesnt_crash():
    """If pydantic-ai's result shape changes and no usage is found,
    the tracker must still produce a zero record."""
    bare = SimpleNamespace(output="ok")
    t = UsageTracker(quiet=True)
    rec = t.record(bare, model="openai:gpt-5.4-mini", source="test")
    assert rec.input_tokens == 0
    assert rec.output_tokens == 0
    assert rec.cost_usd == pytest.approx(0.0, abs=1e-9)


# ---- JSONL persistence ----

def test_tracker_writes_jsonl(tmp_path):
    log = tmp_path / "usage.jsonl"
    t = UsageTracker(quiet=True)
    t.set_jsonl_path(log)
    t.record(_fake_result(input_tokens=100),
             model="openai:gpt-5.4-mini", source="x")
    t.record(_fake_result(input_tokens=200),
             model="openai:gpt-5.4-mini", source="y")

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    parsed = [json.loads(l) for l in lines]
    assert parsed[0]["input_tokens"] == 100
    assert parsed[1]["input_tokens"] == 200
    assert parsed[0]["source"] == "x"
    assert parsed[1]["source"] == "y"


# ---- Budget / circuit breaker (F5 hook lives here) ----

def test_tracker_budget_raises_when_exceeded():
    t = UsageTracker(quiet=True)
    t.set_budget_usd(0.0001)  # ~100 input tokens of mini
    with pytest.raises(CostBudgetExceeded):
        t.record(_fake_result(input_tokens=1_000_000, output_tokens=0),
                 model="openai:gpt-5.4-mini", source="test")


def test_tracker_no_budget_never_raises():
    t = UsageTracker(quiet=True)
    # No budget set; even a huge call should not raise.
    rec = t.record(_fake_result(input_tokens=10_000_000),
                   model="openai:gpt-5.4-mini", source="test")
    assert rec is not None


# ---- Singleton ----

def test_get_tracker_returns_singleton():
    reset_tracker()
    a = get_tracker()
    b = get_tracker()
    assert a is b
    reset_tracker()


def test_reset_tracker_creates_new_session():
    reset_tracker()
    a = get_tracker()
    sid_a = a.session_id
    reset_tracker()
    b = get_tracker()
    sid_b = b.session_id
    assert sid_a != sid_b


# ---- Integration: confirm Agent.run wrappers call tracker.record ----

pytestmark_async = pytest.mark.asyncio


@pytest.mark.asyncio
async def test_single_pass_records_usage():
    pytest.importorskip("pydantic_ai")
    from glaurung.llm.agents.base import ExecutionState, ModelHyperparameters
    from glaurung.llm.agents.single_pass import SinglePassAgent, SinglePassConfig

    reset_tracker()
    fake = SimpleNamespace(run=AsyncMock(
        return_value=_fake_result(input_tokens=4_000, output_tokens=800)
    ))
    sp = SinglePassAgent(
        base_agent=fake,
        config=SinglePassConfig(optimize_context=False, pre_populate_kb=False),
        model="openai:gpt-5.4-mini",
    )
    context = SimpleNamespace(kb=MagicMock())
    await sp._execute_with_monitoring(
        "q", context, ExecutionState(),
        ModelHyperparameters(max_tokens=1000),
    )
    t = get_tracker()
    assert t.call_count() == 1
    rec = t.records[0]
    assert rec.source == "single_pass"
    assert rec.input_tokens == 4_000
    assert rec.output_tokens == 800
    reset_tracker()
