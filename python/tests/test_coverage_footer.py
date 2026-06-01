"""Unit tests for the coverage/assumptions footer."""
from __future__ import annotations

from glaurung.llm.coverage import CoverageFooter


def test_complete_footer_has_no_caveats() -> None:
    cov = CoverageFooter("lock-state")
    cov.fact("instructions", 412).fact("lock primitives modeled", ["KeAcquire", "AcquireSpinLock::Acquire"])
    assert cov.is_complete() is True
    text = cov.render()
    assert "coverage (lock-state)" in text
    assert "instructions: 412" in text
    assert "KeAcquire, AcquireSpinLock::Acquire" in text
    assert "caveats: none" in text


def test_caveats_make_it_incomplete_and_visible() -> None:
    cov = CoverageFooter("function-disasm")
    cov.fact("indirect calls unresolved", 3)
    cov.caveat("3 indirect call(s) not statically resolved")
    assert cov.is_complete() is False
    lines = cov.render_lines()
    assert "caveats:" in lines
    assert any("3 indirect call" in ln for ln in lines)
    d = cov.to_dict()
    assert d["complete"] is False
    assert d["facts"]["indirect calls unresolved"] == 3
    assert d["caveats"] == ["3 indirect call(s) not statically resolved"]


def test_empty_list_fact_renders_none() -> None:
    cov = CoverageFooter("x").fact("modeled", [])
    assert "modeled: (none)" in cov.render()
