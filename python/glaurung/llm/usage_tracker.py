"""Session-wide LLM usage + cost aggregation (F4).

Wraps the ``RunUsage`` pydantic-ai exposes on every ``AgentRunResult``
into a thread-local session tracker. Records {input_tokens,
output_tokens, cost_estimate, model, source-label, ts} per call;
exposes running totals; flushes to a JSONL the operator can inspect
or pipe into cost analysis.

Usage:

    from glaurung.llm.usage_tracker import get_tracker

    tracker = get_tracker()
    result = await agent.run(...)
    tracker.record(result, model=..., source="findings_runner")

    print(tracker.total_cost_usd())

The tracker is opt-in for now: code paths that want cost telemetry
must call ``tracker.record(...)``. F5's cost-budget circuit breaker
hooks into the same tracker to abort mid-run when the running total
exceeds an operator-set cap.

Prices below are USD per million tokens as of May 2026. They are
intentionally conservative -- the tracker over-estimates when prices
shift downward rather than silently under-reporting. Update when
provider price tables change; missing models record ``cost_usd=None``
without crashing.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional


logger = logging.getLogger(__name__)


# USD per million tokens. (input, output) tuples.
# Source: provider pricing pages, May 2026. Conservative when uncertain.
PRICE_PER_MILLION_USD: dict[str, tuple[float, float]] = {
    # OpenAI
    "openai:gpt-5.4-mini":         (0.15, 0.60),
    "openai:gpt-5.5":              (5.00, 15.00),
    "openai:gpt-5.5-mini":         (0.25, 1.00),
    # Anthropic
    "anthropic:claude-haiku-4-5":  (1.00, 5.00),
    "anthropic:claude-sonnet-4-6": (3.00, 15.00),
    "anthropic:claude-opus-4-7":   (15.00, 75.00),
    # Test / unknown -- log zero so totals don't lie.
    "test":                        (0.0, 0.0),
}


def estimate_cost_usd(
    model: str, input_tokens: int, output_tokens: int,
) -> Optional[float]:
    """Compute USD for a single call. Returns ``None`` if the model
    isn't in the price table (operator should add it)."""
    price = PRICE_PER_MILLION_USD.get(model)
    if price is None:
        # Try a prefix match (e.g. 'openai:gpt-5.4-mini-2024-...').
        for key, val in PRICE_PER_MILLION_USD.items():
            if model.startswith(key):
                price = val
                break
    if price is None:
        return None
    in_per_m, out_per_m = price
    return (input_tokens * in_per_m + output_tokens * out_per_m) / 1_000_000.0


@dataclass
class UsageRecord:
    """One LLM call's usage."""
    call_id: str
    ts: float            # unix epoch
    model: str
    input_tokens: int
    output_tokens: int
    request_count: int   # how many tool round-trips this run did
    cost_usd: Optional[float]
    source: str          # 'single_pass' | 'findings_runner' | 'finding_critic' | ...

    def as_dict(self) -> dict[str, Any]:
        return {
            "call_id":        self.call_id,
            "ts":             self.ts,
            "model":          self.model,
            "input_tokens":   self.input_tokens,
            "output_tokens":  self.output_tokens,
            "request_count":  self.request_count,
            "cost_usd":       self.cost_usd,
            "source":         self.source,
        }


class CostBudgetExceeded(RuntimeError):
    """Raised by UsageTracker.record() when a configured budget is hit."""


@dataclass
class UsageTracker:
    """Thread-local session-wide aggregator.

    Acquire with :func:`get_tracker`. Single-process singleton; tests
    can reset via :func:`reset_tracker`.
    """

    session_id: str = field(
        default_factory=lambda: time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6],
    )
    records: list[UsageRecord] = field(default_factory=list)
    budget_usd: Optional[float] = None
    jsonl_path: Optional[Path] = None
    # Set to True to suppress the print-every-call running total.
    quiet: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set_budget_usd(self, budget: Optional[float]) -> None:
        with self._lock:
            self.budget_usd = budget

    def set_jsonl_path(self, path: Optional[Path]) -> None:
        with self._lock:
            self.jsonl_path = path
            if path is not None:
                path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _extract_usage(result: Any) -> tuple[int, int, int]:
        """Best-effort extraction of ``(input_tokens, output_tokens,
        requests)`` from a pydantic-ai run result.

        pydantic-ai exposes usage via ``result.usage()`` (callable) on
        the AgentRunResult; the older shape was a property
        ``result.usage``. Handle both. Fallback returns zeros so the
        record is still written.
        """
        usage = None
        for attr in ("usage",):
            if hasattr(result, attr):
                u = getattr(result, attr)
                # Could be a method or a property.
                if callable(u):
                    try:
                        usage = u()
                    except Exception:
                        usage = None
                else:
                    usage = u
                if usage is not None:
                    break
        if usage is None:
            return (0, 0, 0)
        # pydantic-ai 1.x RunUsage fields.
        inp = (
            getattr(usage, "input_tokens", None)
            or getattr(usage, "request_tokens", None)  # legacy name
            or 0
        )
        out = (
            getattr(usage, "output_tokens", None)
            or getattr(usage, "response_tokens", None)  # legacy
            or 0
        )
        req = getattr(usage, "requests", None) or 0
        return (int(inp), int(out), int(req))

    def record(
        self,
        result: Any,
        *,
        model: str,
        source: str,
    ) -> UsageRecord:
        """Record one call. Raises :class:`CostBudgetExceeded` if the
        running total exceeds the configured budget AFTER this call."""
        inp, out, req = self._extract_usage(result)
        cost = estimate_cost_usd(model, inp, out)
        rec = UsageRecord(
            call_id=uuid.uuid4().hex[:12],
            ts=time.time(),
            model=model,
            input_tokens=inp,
            output_tokens=out,
            request_count=req,
            cost_usd=cost,
            source=source,
        )
        with self._lock:
            self.records.append(rec)
            if self.jsonl_path is not None:
                with self.jsonl_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec.as_dict()))
                    f.write("\n")
            running_cost = self._running_cost_unsafe()
            if (
                not self.quiet
                and running_cost is not None
                and len(self.records) % 5 == 0
            ):
                logger.info(
                    "[usage] session=%s calls=%d running=$%.4f",
                    self.session_id, len(self.records), running_cost,
                )
            if (
                self.budget_usd is not None
                and running_cost is not None
                and running_cost > self.budget_usd
            ):
                raise CostBudgetExceeded(
                    f"running cost ${running_cost:.4f} exceeds "
                    f"--max-cost-usd ${self.budget_usd:.4f}; "
                    f"aborting after {len(self.records)} calls"
                )
        return rec

    def _running_cost_unsafe(self) -> Optional[float]:
        total = 0.0
        any_priced = False
        for r in self.records:
            if r.cost_usd is None:
                continue
            total += r.cost_usd
            any_priced = True
        return total if any_priced else None

    def total_cost_usd(self) -> Optional[float]:
        with self._lock:
            return self._running_cost_unsafe()

    def total_input_tokens(self) -> int:
        with self._lock:
            return sum(r.input_tokens for r in self.records)

    def total_output_tokens(self) -> int:
        with self._lock:
            return sum(r.output_tokens for r in self.records)

    def call_count(self) -> int:
        with self._lock:
            return len(self.records)

    def per_model_breakdown(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        with self._lock:
            for r in self.records:
                bucket = out.setdefault(
                    r.model,
                    {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
                )
                bucket["calls"] += 1
                bucket["input_tokens"] += r.input_tokens
                bucket["output_tokens"] += r.output_tokens
                if r.cost_usd is not None:
                    bucket["cost_usd"] += r.cost_usd
        return out


# --- Singleton accessors (process-wide) ---

_TRACKER: Optional[UsageTracker] = None
_TRACKER_LOCK = threading.Lock()


def get_tracker() -> UsageTracker:
    """Return the process-wide tracker, creating it on first use.

    The default tracker writes JSONL to
    ``~/.cache/glaurung/usage/<session>.jsonl`` when the cache dir
    exists, else stays in-memory only.
    """
    global _TRACKER
    with _TRACKER_LOCK:
        if _TRACKER is None:
            _TRACKER = UsageTracker()
            home = os.path.expanduser("~")
            cache_dir = Path(home) / ".cache" / "glaurung" / "usage"
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                _TRACKER.jsonl_path = cache_dir / f"{_TRACKER.session_id}.jsonl"
            except Exception:
                # Read-only home or similar; stay in-memory.
                _TRACKER.jsonl_path = None
        return _TRACKER


def reset_tracker() -> None:
    """Tests use this to clear the singleton."""
    global _TRACKER
    with _TRACKER_LOCK:
        _TRACKER = None
