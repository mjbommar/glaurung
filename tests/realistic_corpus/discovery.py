"""Measure what Glaurung recovers from each realistic-binary variant.

The corpus is built by `tools/realistic_corpus.py` from our own fixture sources,
so the ground-truth function list is known exactly rather than inferred: it is
the address table the generated driver holds, and the addresses come out of the
symbol table of that variant's own control build.

Counts, not scores, and they are deliberately separate because they fail
independently:

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

Addresses, because counts can be right for the wrong reasons
------------------------------------------------------------

A count answers "how many", never "which". Anti-disassembly does not usually
cost a reader functions; it makes it *invent* them, at addresses that are inside
some other function or inside data, and a discovery count holds perfectly while
that happens. So each variant also gets three ratios over function entry
ADDRESSES:

``truth_recall_pct``
    of the functions we linked in ourselves, what fraction did we find at the
    right address. This is the primary number and it never touches our own
    analysis of anything — the denominator is `nm` on the control.
``control_recall_pct`` / ``control_precision_pct``
    against the set of addresses recovered from that variant's symbol-bearing
    control. Precision is the half anti-disassembly attacks, and the half a
    count cannot see.

For `upx` and `upxg` the ground-truth addresses are those of the program inside
the compressed blob. Nothing static can be expected to hit them, and the ~0%
that results is the honest report of what a packed file gives up, not a defect
in the measurement.
"""

from __future__ import annotations

import argparse
import json
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import realistic_corpus  # noqa: E402

BASELINE = Path(__file__).resolve().parent / "discovery_baseline.json"


def _pct(hit: int, total: int) -> float:
    """A percentage rounded to one place, and 0.0 rather than a ZeroDivisionError."""
    return round(100.0 * hit / total, 1) if total else 0.0


@lru_cache(maxsize=None)
def _entry_addresses(build_name: str) -> frozenset[int]:
    """Every function entry address the analysis recovers from one build.

    Cached: the controls are analysed once each and then reused as the reference
    for every variant that points at them.
    """
    import glaurung

    path = realistic_corpus.variant_path(build_name)
    functions, _call_graph = glaurung.analysis.analyze_functions_path(str(path))
    return frozenset(int(f.entry_point.value) for f in functions)


def measure(variant: str) -> dict[str, float]:
    """Discovery, naming and address-level precision/recall for one built variant.

    Args:
        variant: One of `realistic_corpus.VARIANTS`.

    Returns:
        Mapping with `discovered`, `named`, `truth_hit`, the ground-truth
        address counts and the three percentages described in the module
        docstring.
    """
    import glaurung

    path = realistic_corpus.variant_path(variant)
    functions, _call_graph = glaurung.analysis.analyze_functions_path(str(path))

    names = {getattr(f, "name", "") or "" for f in functions}
    named = {n for n in names if n and not n.startswith("sub_")}
    found = {int(f.entry_point.value) for f in functions}

    manifest = realistic_corpus.build()
    truth_names = set(manifest["ground_truth"])
    truth = realistic_corpus.truth_addresses(variant)
    control = _entry_addresses(manifest["control_of"][variant])

    return {
        "discovered": len(functions),
        "named": len(named),
        "truth_hit": len(truth_names & names),
        "truth_addr_hit": len(truth & found),
        "truth_addr_total": len(truth),
        "truth_recall_pct": _pct(len(truth & found), len(truth)),
        "control_recall_pct": _pct(len(found & control), len(control)),
        "control_precision_pct": _pct(len(found & control), len(found)),
    }


def report() -> dict[str, dict[str, float]]:
    """Measure every variant."""
    return {v: measure(v) for v in realistic_corpus.VARIANTS}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--write-baseline",
        action="store_true",
        help="overwrite discovery_baseline.json with what is measured now",
    )
    args = ap.parse_args(argv)

    manifest = realistic_corpus.build()
    measured = report()

    head = f"{'variant':<10} {'found':>6} {'named':>6} {'truth':>9} {'recall':>8} {'prec':>7}"
    print(head)
    print("-" * len(head))
    for variant, m in measured.items():
        truth = f"{m['truth_addr_hit']}/{m['truth_addr_total']}"
        print(
            f"{variant:<10} {m['discovered']:>6} {m['named']:>6} {truth:>9} "
            f"{m['truth_recall_pct']:>7}% {m['control_precision_pct']:>6}%"
        )

    if args.write_baseline:
        BASELINE.write_text(
            json.dumps(
                {
                    "schema": 2,
                    "toolchain": manifest["toolchain"],
                    "ground_truth_count": len(manifest["ground_truth"]),
                    "variants": measured,
                },
                indent=2,
            )
            + "\n"
        )
        print(f"\nwrote {BASELINE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
