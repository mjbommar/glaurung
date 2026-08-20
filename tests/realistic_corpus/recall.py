"""Address-level recall of the corpus functions, per realistic-binary variant.

`discovery.py` counts how many functions came back and how many carried a name.
Neither number says whether the functions we found are *the functions we built*.
On a packed image that distinction is the whole story: the analysis returns a
handful of functions, all of them real code, and none of them the program — the
count looks merely low when the result is actually wrong.

So this module measures against addresses. Ground truth is the entry VA of each
of the corpus functions, read out of the control build's own symbol table, and
every variant is scored against that same set:

``true_positive``
    a discovered function whose entry VA is one of ours.
``false_positive``
    a discovered function inside the corpus's own text that is *not* one of
    ours. Library and runtime code linked in by the toolchain (`_start`,
    `frame_dummy`, PLT thunks) is excluded by construction because it is scored
    only against the control's symbol table — see `_scored`.
``missed``
    one of ours that came back from nothing.

Precision and recall are reported separately because they fail separately: a
packer stub yields high-confidence functions that are all false positives, and
a discovery regression yields misses with precision untouched.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import realistic_corpus  # noqa: E402


def ground_truth_addresses() -> dict[str, int]:
    """Entry VA of every corpus function, from the control build's symbol table.

    The control (`dwarf`) is the only variant that still has a `.symtab`, and it
    is the same link as every other variant, so its addresses are the addresses
    in all of them.

    Returns:
        Mapping of function name to entry virtual address.
    """
    control = realistic_corpus.variant_path("dwarf")
    wanted = set(realistic_corpus.build()["ground_truth"])
    out: dict[str, int] = {}
    r = subprocess.run(
        ["nm", "--defined-only", str(control)], capture_output=True, text=True
    )
    if r.returncode != 0:
        raise RuntimeError(f"nm on the control build failed: {r.stderr.strip()}")
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "T" and parts[2] in wanted:
            out[parts[2]] = int(parts[0], 16)
    missing = wanted - set(out)
    if missing:
        raise RuntimeError(
            f"{len(missing)} ground-truth symbols have no address in the control "
            f"build: {sorted(missing)[:5]}"
        )
    return out


def _scored(found: set[int], truth: set[int]) -> dict[str, float | int]:
    """Score one variant's discovered entry VAs against the truth set.

    False positives are counted only within the address span the ground-truth
    functions occupy. Outside it lives code we never claimed to have built —
    CRT startup, PLT thunks, the packer's own stub — and counting that as a
    false positive would score the toolchain rather than the analysis.
    """
    lo, hi = min(truth), max(truth)
    in_span = {a for a in found if lo <= a <= hi}
    tp = len(in_span & truth)
    fp = len(in_span - truth)
    missed = len(truth - found)
    return {
        "found": len(found),
        "true_positive": tp,
        "false_positive": fp,
        "missed": missed,
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
        "recall": round(tp / len(truth), 4) if truth else 0.0,
    }


def measure(variant: str, truth: dict[str, int] | None = None) -> dict:
    """Address-level scores for one built variant.

    Args:
        variant: One of `realistic_corpus.VARIANTS`.
        truth: Ground-truth addresses; read from the control build if omitted.

    Returns:
        The scores from `_scored`, plus `packer`/`unpacked` if the analysis
        reported that the image was packed.
    """
    import glaurung

    truth = truth or ground_truth_addresses()
    path = realistic_corpus.variant_path(variant)
    functions, _cg, stats = glaurung.analysis.analyze_functions_path_with_stats(
        str(path)
    )
    found = {int(f.entry_point.value) for f in functions if f.entry_point is not None}
    out = _scored(found, set(truth.values()))
    for key in ("packer", "unpacked", "unpack_error", "original_entry"):
        if key in stats:
            out[key] = stats[key]
    return out


def report() -> dict[str, dict]:
    """Measure every variant against one shared ground-truth read."""
    truth = ground_truth_addresses()
    return {v: measure(v, truth) for v in realistic_corpus.VARIANTS}


def main() -> int:
    rows = report()
    print(
        f"{'variant':<8} {'found':>6} {'true+':>6} {'false+':>7} {'missed':>7} {'prec':>8} {'recall':>8}  packer"
    )
    for variant, r in rows.items():
        packer = r.get("packer") or ""
        if packer and r.get("unpacked"):
            packer += " (unpacked)"
        elif packer:
            packer += f" (NOT unpacked: {r.get('unpack_error')})"
        print(
            f"{variant:<8} {r['found']:>6} {r['true_positive']:>6} "
            f"{r['false_positive']:>7} {r['missed']:>7} "
            f"{r['precision']:>8.1%} {r['recall']:>8.1%}  {packer}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
