"""Function naming assistant (memory-first compatible).

Produces concise, descriptive function names using available evidence
and an LLM when configured. Falls back to heuristics if no model is
available. Always appends a short uniqueness suffix based on the
function address (or a short uuid) to avoid collisions.
"""

from __future__ import annotations

from typing import Optional, Iterable
from pydantic import BaseModel, Field
from pydantic_ai import Agent
import re
import uuid


def _short_suffix(entry_va: Optional[int]) -> str:
    if isinstance(entry_va, int) and entry_va >= 0:
        return f"_{entry_va:x}"
    return f"_{uuid.uuid4().hex[:6]}"


def _slugify(name: str) -> str:
    # Keep alnum and underscores; convert separators to underscores; lower-case
    n = name.strip()
    # Drop template args and trailing parens common in demangled names
    n = re.sub(r"\(.*\)$", "", n)
    n = re.sub(r"[<>]", "", n)
    # Replace separators with underscore
    n = re.sub(r"[\s:/\\\-]+", "_", n)
    # Keep only [A-Za-z0-9_]
    n = re.sub(r"[^A-Za-z0-9_]", "", n)
    # Collapse multiple underscores
    n = re.sub(r"_+", "_", n)
    return n.strip("_").lower() or "func"


class SuggestedFunctionName(BaseModel):
    name: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.6)
    summary: Optional[str] = None


def _heuristic_name(fe) -> SuggestedFunctionName:
    """Heuristic naming from FunctionEvidence-like object."""
    hints = [str(h).lower() for h in (getattr(fe, "hints", []) or [])]
    entry_va = getattr(fe, "entry_va", None)
    calls = [str(getattr(c, "target_name", "")) for c in getattr(fe, "calls", [])]
    strings = [str(getattr(s, "text", "")) for s in getattr(fe, "strings", [])]

    base = None
    if any("print" in h for h in hints) or any(
        any(x in c.lower() for x in ("puts", "printf", "print")) for c in calls
    ):
        # Derive a more specific print_* name from first printable string
        s = next((t for t in strings if len(t) >= 3), None)
        if s:
            # pick words; keep alnum; truncate
            words = re.findall(r"[A-Za-z0-9]+", s.lower())[:3]
            if words:
                base = "print_" + "_".join(words)
        base = base or "print_message"
    elif any("network" in h for h in hints) or any(
        any(x in c.lower() for x in ("socket", "connect", "send", "recv"))
        for c in calls
    ):
        base = "network_handler"
    elif any("sort" in s.lower() for s in strings):
        base = "sort_list"
    elif any("encrypt" in s.lower() or "aes" in s.lower() for s in strings):
        base = "encrypt_data"
    elif any("decrypt" in s.lower() for s in strings):
        base = "decrypt_data"

    # Fall back to original name if present and non-generic
    name = str(getattr(fe, "name", "") or "")
    if name and not re.fullmatch(
        r"(sub_.*|func.*|function|unknown)", name, flags=re.IGNORECASE
    ):
        nm = _slugify(name) + _short_suffix(entry_va)
        return SuggestedFunctionName(name=nm, confidence=0.7)

    if base is None:
        base = "func"
    nm = _slugify(base) + _short_suffix(entry_va)
    return SuggestedFunctionName(name=nm, confidence=0.55, summary=None)


def _llm_name(fe) -> Optional[SuggestedFunctionName]:
    """Use LLM (if available) to propose a name based on evidence."""
    # Avoid import at module import time to keep CLI snappy
    try:
        from ..config import get_config
    except Exception:
        return None

    cfg = get_config()
    if not any(cfg.available_models().values()):
        return None

    # Collect compact context
    entry_va = getattr(fe, "entry_va", None)
    orig = str(getattr(fe, "name", "") or "")
    calls: list[str] = [
        str(getattr(c, "target_name", ""))
        for c in (getattr(fe, "calls", []) or [])
        if getattr(c, "target_name", None)
    ]
    strings: list[str] = [
        str(getattr(s, "text", ""))
        for s in (getattr(fe, "strings", []) or [])
        if getattr(s, "text", None)
    ]
    hints: Iterable[str] = [str(h) for h in (getattr(fe, "hints", []) or [])]
    instrs: list[str] = [
        str(getattr(i, "text", "")) for i in (getattr(fe, "instructions", []) or [])
    ][:24]

    # Agent over plain string input, typed output
    agent = Agent[str, SuggestedFunctionName](
        model=cfg.default_model,
        output_type=SuggestedFunctionName,
        system_prompt=(
            "You are a reverse engineering assistant.\n"
            "Suggest a concise, meaningful function name based on calls, strings, and first instructions.\n"
            "Prefer snake_case. Include verb + object when clear (e.g., print_hello_world, sort_list).\n"
            "Avoid long names; 2-4 words max. Return name, confidence, and a short summary."
        ),
    )

    ctx_lines = []
    if orig:
        ctx_lines.append(f"original: {orig}")
    if hints:
        ctx_lines.append("hints: " + ", ".join(hints))
    if calls:
        ctx_lines.append("calls: " + ", ".join(calls[:6]))
    if strings:
        samp = ", ".join(repr(s) for s in strings[:3])
        ctx_lines.append(f"strings: {samp}")
    if instrs:
        ctx_lines.append("instr:\n" + "\n".join(instrs[:10]))

    prompt = (
        "Propose a function name strictly as identifier (no spaces).\n"
        + "\n".join(ctx_lines)
    )

    try:
        res = agent.run_sync(prompt)
        out = res.output
        # Sanitize name and append uniqueness suffix
        nm = _slugify(out.name) + _short_suffix(entry_va)
        return SuggestedFunctionName(
            name=nm, confidence=out.confidence, summary=out.summary
        )
    except Exception:
        return None


def suggest_name_from_evidence_sync(
    function_evidence, symbols_summary=None
) -> SuggestedFunctionName:
    # Do not blindly trust original names; treat them only as weak hints.
    # Try LLM-backed suggestion; fall back to heuristics derived from code behavior.
    out = _llm_name(function_evidence)
    if out is not None and out.name:
        return out
    return _heuristic_name(function_evidence)
