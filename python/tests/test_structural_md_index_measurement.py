"""How often does an MD-index survive `-O0` -> `-O2`? Measured, not assumed.

`docs/reference/function-identity-structural.md` reports one number for
the L1 rung's stability across an optimisation level, and this is the
code that produces it. It is `slow`-marked and reads the gitignored
matched-build corpus at `tests/decompiler_fixtures/build/`, so an
ordinary run skips it -- with a reason, because pytest.ini's `-ra` prints
every skip and a silent one reads exactly like a pass.

The measurement is deliberately reported rather than thresholded. The
number moves whenever discovery changes what it finds, and a threshold
that has to be re-pinned every time discovery improves is a threshold
nobody will believe. What IS asserted is the two structural facts the
ranking depends on and that cannot drift: an MD-index that agrees
implies the block, edge and back-edge counts agree, and the shape gate
is never looser than the count gate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

import glaurung as g

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"

#: Discovery's placeholder names encode the address they were generated
#: at, so pairing two builds on them would pair by address, which is the
#: one thing the whole module exists not to do.
PLACEHOLDER_PREFIXES = ("sub_", "loc_", "fn_", "func_")


def _signatures(path: Path) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for sig in g.analysis.structural_signatures_path(str(path)):
        name = str(sig.name)
        if name.startswith(PLACEHOLDER_PREFIXES):
            continue
        out.setdefault(name, sig)
    return out


def _key(sig: Any) -> Tuple[float, float, float]:
    return (
        round(sig.md_index_top_down, 12),
        round(sig.md_index_bottom_up, 12),
        round(sig.md_index_relaxed, 12),
    )


@pytest.mark.slow
def test_md_index_agreement_across_optimisation_levels(
    capsys: pytest.CaptureFixture[str],
) -> None:
    if not BUILD.is_dir():
        pytest.skip(
            f"matched-build corpus missing at {BUILD} -- it is gitignored and "
            "takes ~40 min to build; see docs/development/decompiler-testing.md"
        )
    pairs = []
    for o0 in sorted(BUILD.glob("*-gcc-O0.so")):
        o2 = BUILD / o0.name.replace("-gcc-O0.so", "-gcc-O2.so")
        if o2.exists():
            pairs.append((o0, o2))
    if not pairs:
        pytest.skip(f"no <fixture>-gcc-O0.so / -gcc-O2.so pairs under {BUILD}")

    compared = 0
    md_equal = 0
    counts_equal = 0
    counts_equal_and_md_equal = 0
    for o0, o2 in pairs:
        a = _signatures(o0)
        b = _signatures(o2)
        for name in sorted(set(a) & set(b)):
            sa, sb = a[name], b[name]
            compared += 1
            same_md = _key(sa) == _key(sb)
            same_counts = (
                sa.basic_blocks == sb.basic_blocks
                and sa.edges == sb.edges
                and sa.back_edges == sb.back_edges
            )
            md_equal += same_md
            counts_equal += same_counts
            counts_equal_and_md_equal += same_md and same_counts
            # An MD-index is a sum over the degree sequence and the BFS
            # levels, so two graphs with different block or edge counts
            # agreeing on all three variants is a collision, not a match.
            # Measured 0 times over 2,131 pairs on 2026-09-02; asserted so
            # that a change which makes collisions common is a failure and
            # not a silently better-looking number.
            assert not (same_md and not same_counts), (
                f"{name} in {o0.name}: MD-index agreed while the counts did "
                f"not ({sa.basic_blocks}/{sa.edges} vs {sb.basic_blocks}/{sb.edges})"
            )

    assert compared > 0, "no same-name function pairs found"
    # Equal counts are necessary but not sufficient for an equal index --
    # that gap is exactly the discrimination the MD-index adds over the
    # three integers angr's bindiff uses.
    assert counts_equal >= md_equal

    report = {
        "fixture_pairs": len(pairs),
        "same_name_pairs": compared,
        "identical_md_index_triple": md_equal,
        "differing_md_index_triple": compared - md_equal,
        "identical_block_edge_backedge_counts": counts_equal,
        "counts_equal_but_md_differs": counts_equal - counts_equal_and_md_equal,
    }
    with capsys.disabled():
        print("\nL1 MD-index across -O0 -> -O2 (gcc):")
        print(json.dumps(report, indent=2))
