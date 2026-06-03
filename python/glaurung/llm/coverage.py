"""Coverage / assumptions footer for analyses.

Every analysis that can be *partially* correct should say so. The
motivating failure (agentic-security-bot, 2026-06-01): a lock tracer that
modeled only one of several locking primitives produced a confident
"wrong-lock double-free" finding that was false. The fix is not just to
model more primitives but to make any analysis declare, in-band, what it
did and did NOT account for -- so a partial result reads as partial.

A ``CoverageFooter`` is a small, render-anywhere block:

    --- coverage (lock-state) ---
    instructions: 412
    lock primitives modeled: KeAcquireInStackQueuedSpinLock, AcquireSpinLock::Acquire
    indirect calls unresolved: 3
    lifted-C disasm-verified: no
    caveats:
      - 2 call targets via register were not resolved
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class CoverageFooter:
    """Structured, renderable statement of an analysis's coverage limits."""

    analysis: str
    facts: Dict[str, Any] = field(default_factory=dict)
    caveats: List[str] = field(default_factory=list)

    def fact(self, key: str, value: Any) -> "CoverageFooter":
        self.facts[key] = value
        return self

    def caveat(self, text: str) -> "CoverageFooter":
        if text:
            self.caveats.append(text)
        return self

    def is_complete(self) -> bool:
        """True when nothing was left unmodeled/unresolved (no caveats)."""
        return not self.caveats

    def render_lines(self) -> List[str]:
        out = [f"--- coverage ({self.analysis}) ---"]
        for k, v in self.facts.items():
            if isinstance(v, (list, tuple, set)):
                v = ", ".join(map(str, v)) if v else "(none)"
            out.append(f"{k}: {v}")
        if self.caveats:
            out.append("caveats:")
            out.extend(f"  - {c}" for c in self.caveats)
        else:
            out.append("caveats: none (full coverage for the modeled scope)")
        return out

    def render(self) -> str:
        return "\n".join(self.render_lines())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis": self.analysis,
            "facts": dict(self.facts),
            "caveats": list(self.caveats),
            "complete": self.is_complete(),
        }
