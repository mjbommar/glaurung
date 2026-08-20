"""Measure what Glaurung recovers from each realistic-binary variant.

The corpus is built by `tools/realistic_corpus.py` from our own fixture sources,
so the ground-truth function list is known exactly rather than inferred: it is
the address table the generated driver holds.

Two numbers are tracked per variant, and they are deliberately separate because
they fail independently:

``discovered``
    how many functions the analysis finds at all. Falling here means the
    *seeding* is weaker on this shape.
``named``
    how many of those carry a real name rather than a `sub_<addr>` placeholder,
    and ``truth_hit`` is how many of the ground-truth names came back. Falling
    here while ``discovered`` holds means seeding is fine and symbolication is
    not — the distinction the `O2strip` differential already showed matters.

Keeping them apart is the point: on a stripped build, discovery stays near the
control while naming goes to exactly zero, and one aggregate score would hide
that completely.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import realistic_corpus  # noqa: E402


def measure(variant: str) -> dict[str, int]:
    """Discovery and naming counts for one built variant.

    Args:
        variant: One of `realistic_corpus.VARIANTS`.

    Returns:
        Mapping with `discovered`, `named` and `truth_hit`.
    """
    import glaurung

    path = realistic_corpus.variant_path(variant)
    functions, _call_graph = glaurung.analysis.analyze_functions_path(str(path))

    names = {getattr(f, "name", "") or "" for f in functions}
    named = {n for n in names if n and not n.startswith("sub_")}
    truth = set(realistic_corpus.build()["ground_truth"])
    return {
        "discovered": len(functions),
        "named": len(named),
        "truth_hit": len(truth & names),
    }


def report() -> dict[str, dict[str, int]]:
    """Measure every variant."""
    return {v: measure(v) for v in realistic_corpus.VARIANTS}
