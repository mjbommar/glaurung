"""Glaurung benchmark harness (#159).

Deterministic, no-LLM regression harness for Glaurung's analysis
pipeline. Given a sample binary with a metadata sidecar pointing at its
source, runs Glaurung's analyzer and emits a per-binary scorecard plus
a summary across the sample matrix.

The metrics tracked here are exactly the ones future Tier-A work
(#157 DWARF, #158 FLIRT, #160 indirect calls, #161 decompiler polish)
should *move*. Run before and after a change to see if the change
actually improved the signal you thought it would.

Usage:

    python -m glaurung.bench --root samples/binaries/platforms/linux/amd64 \\
        --output bench-results.json --markdown bench-results.md

The JSON scorecard is the source of truth; the Markdown is for humans.
Stable schema is documented in :class:`scorecards.Scorecard`.
"""

from .harness import BenchSummary, BinaryScorecard, run_harness, run_one_binary

__all__ = [
    "BenchSummary",
    "BinaryScorecard",
    "run_harness",
    "run_one_binary",
]
