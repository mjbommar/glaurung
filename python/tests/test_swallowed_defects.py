"""Three defects that a bare ``except`` kept invisible.

Each test here fails without the corresponding fix:

1. ``IterativeAgent._add_refinement_feedback`` called
   ``kb.add_node(id=..., type=..., properties=...)`` against a
   ``KnowledgeBase.add_node(node: Node)`` signature.  Every low-confidence
   iteration raised ``TypeError`` and the caller's
   ``except Exception: state.failed_attempts.append(str(e))`` recorded the
   crash as an ordinary failed attempt.

2. ``symbol_address_map`` is registered on the root ``_native`` module by
   ``src/lib.rs``, not on the ``symbols`` submodule, and was not re-exported
   from ``glaurung/__init__.py``.  Five call sites spelled it
   ``g.symbols.symbol_address_map`` inside ``except Exception: pairs = []``.

3. ``glaurung/triage.py`` re-exported 59 PE/ELF/Mach-O names from
   ``_native.triage`` inside ``try: ... except AttributeError: pass``.  None
   of the 59 exists, so each block died on its first line.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import glaurung as g
import glaurung._native as _native
import glaurung.triage as gtriage
from glaurung.llm.kb.models import NodeKind
from glaurung.llm.kb.store import KnowledgeBase


REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE = (
    REPO_ROOT
    / "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0"
)


# --------------------------------------------------------------------------
# 1. iterative refinement feedback reaches the KB
# --------------------------------------------------------------------------


def test_refinement_feedback_node_is_actually_stored() -> None:
    from glaurung.llm.agents.iterative import (
        IterationState,
        IterativeAgent,
        RefinementStrategy,
    )

    agent = IterativeAgent.__new__(IterativeAgent)
    agent.strategy = RefinementStrategy()

    kb = KnowledgeBase()
    ctx = SimpleNamespace(kb=kb)
    state = IterationState(iteration=2, tools_used=["disassemble"])

    # Before the fix this raised TypeError: add_node() got an unexpected
    # keyword argument 'id'.
    agent._add_refinement_feedback(ctx, state, 0.25)

    node = kb.get_node("feedback_2")
    assert node is not None, "refinement feedback never reached the KB"
    assert node.kind is NodeKind.note
    assert node.props["iteration"] == 2
    assert node.props["confidence"] == pytest.approx(0.25)
    assert "refinement_feedback" in node.tags


def test_iteration_feedback_node_is_actually_stored() -> None:
    """Same defect, second site: ``IterativeRefinementAgent``."""
    pytest.importorskip("pydantic_ai")
    from glaurung.llm.agents.base import ExecutionState
    from glaurung.llm.agents.iterative_refinement import (
        IterativeConfig,
        IterativeRefinementAgent,
    )

    agent = IterativeRefinementAgent.__new__(IterativeRefinementAgent)
    agent.config = IterativeConfig()

    kb = KnowledgeBase()
    ctx = SimpleNamespace(kb=kb)
    state = ExecutionState()

    agent._inject_iteration_feedback(ctx, state, 0.2, 1)

    node = kb.get_node("iteration_feedback_1")
    assert node is not None, "iteration feedback never reached the KB"
    assert node.props["confidence"] == pytest.approx(0.2)


# --------------------------------------------------------------------------
# 2. symbol_address_map is reachable from Python
# --------------------------------------------------------------------------


def test_symbol_address_map_is_reachable() -> None:
    """The bare ``hasattr`` guard that was missing.

    ``src/lib.rs`` registers the helper on the root ``_native`` module; the
    package re-exports it.  If either link breaks the LLM tools silently fall
    back to an empty symbol map.
    """
    assert hasattr(_native, "symbol_address_map"), (
        "src/lib.rs no longer registers symbol_address_map on _native"
    )
    assert hasattr(g, "symbol_address_map"), (
        "glaurung/__init__.py no longer re-exports symbol_address_map"
    )
    assert "symbol_address_map" in g.__all__


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample binary not built")
def test_symbol_address_map_returns_symbols_for_a_real_binary() -> None:
    pairs = g.symbol_address_map(str(SAMPLE))
    assert len(pairs) > 50, f"expected a populated symbol map, got {len(pairs)}"
    names = {n for (_a, n) in pairs}
    assert "main" in names


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample binary not built")
def test_map_symbol_addresses_tool_is_no_longer_empty() -> None:
    """The blast radius: this tool reported "no symbols" for every binary."""
    from glaurung.llm.context import MemoryContext
    from glaurung.llm.tools.map_symbol_addresses import (
        MapSymbolAddressesArgs,
        build_tool,
    )

    art = g.triage.analyze_path(str(SAMPLE), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(SAMPLE), artifact=art)
    result = build_tool().run(ctx, ctx.kb, MapSymbolAddressesArgs(add_to_kb=False))
    assert len(result.symbols) > 50, (
        f"map_symbol_addresses returned {len(result.symbols)} symbols"
    )


@pytest.mark.skipif(not SAMPLE.exists(), reason="sample binary not built")
def test_import_data_symbols_from_binary_is_no_longer_a_no_op(tmp_path: Path) -> None:
    """Second blast-radius site: ``xref_db.import_data_symbols_from_binary``
    returned 0 for every binary because its ``g.symbol_address_map`` lookup
    raised ``AttributeError`` inside ``except Exception: return 0``.
    """
    from glaurung.llm.kb import xref_db
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase

    kb = PersistentKnowledgeBase.open(tmp_path / "labels.glaurung", binary_path=SAMPLE)
    try:
        n = xref_db.import_data_symbols_from_binary(kb, str(SAMPLE))
    finally:
        kb.close()
    assert n > 50, f"import_data_symbols_from_binary imported {n} labels"


# --------------------------------------------------------------------------
# 3. glaurung.triage exports only names that exist
# --------------------------------------------------------------------------


def test_triage_exports_all_resolve() -> None:
    missing = sorted(n for n in gtriage.__all__ if not hasattr(gtriage, n))
    assert missing == [], f"glaurung.triage.__all__ names nothing: {missing}"


def test_triage_has_no_silent_attributeerror_reexport_block() -> None:
    """The structural fix.

    Three ``try: ... except AttributeError: pass`` blocks each tried to
    re-export ~20 names; each died on its own first line, so ``__all__``
    silently gained none of them and nothing anywhere reported it.  A missing
    name must now be loud, so no such swallowing block may return.
    """
    assert gtriage.__file__ is not None
    source = Path(gtriage.__file__).read_text()
    # An `except AttributeError:` that only falls back to a value is fine (the
    # SymbolSummary shim does this).  One whose entire body is `pass` is not.
    offenders = []
    lines = source.splitlines()
    for i, line in enumerate(lines):
        if line.strip() != "except AttributeError:":
            continue
        body = [
            b.strip()
            for b in lines[i + 1 : i + 4]
            if b.strip() and not b.strip().startswith("#")
        ]
        if body[:1] == ["pass"]:
            offenders.append(i + 1)
    assert offenders == [], (
        f"glaurung/triage.py swallows AttributeError at lines {offenders}; "
        "a name the native module does not export must fail loudly"
    )
    assert "raise ImportError(" in source, (
        "the import-time __all__ completeness check is gone"
    )


def test_triage_does_not_advertise_absent_format_types() -> None:
    """The 59 names the old ``except AttributeError: pass`` block promised."""
    for name in (
        "PeTriageInfo",
        "PeSubsystem",
        "ElfHeaderFlags",
        "ElfTriageInfo",
        "MachOHeader",
        "MachOChainedFixup",
        "PeRichHeader",
    ):
        assert name not in gtriage.__all__, (
            f"{name} is advertised but _native.triage does not export it"
        )
        assert not hasattr(_native.triage, name)
