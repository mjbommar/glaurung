"""The reason a jump-table dispatch was declined must reach Python.

`analysis::dispatch` has recorded a typed reason for every declined indirect
transfer since it was written, and `FunctionDiscoveryStats` stored it — but
`function_discovery_stats_to_py` emitted some sixty other counters and dropped
this one at the FFI boundary. The reason was computed and then existed nowhere a
consumer could reach it.
"""

import pathlib

import glaurung as g
import pytest

SAMPLE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
)

#: Reasons the Rust side can currently produce. A new one is fine; a typo is not.
KNOWN_PREFIXES = ("unknown_base", "no_bound", "no_table_at:")


def _stats() -> dict:
    if not SAMPLE.exists():
        pytest.skip("checked-in gcc -O2 sample not present")
    _funcs, _cg, stats = g.analysis.analyze_functions_path_with_stats(  # ty: ignore[unresolved-attribute]
        str(SAMPLE),
        104_857_600,
        104_857_600,
        0,
        2048,
        50_000,
        2_000,
        0,
    )
    return stats


def test_declined_dispatches_are_reported_with_a_reason():
    stats = _stats()
    declines = stats["unresolved_indirect"]
    # Every gcc ELF carries the crtstuff TM-clone pair, whose `jmp *%rax` after
    # a GOT load this pass declines.
    assert declines, "expected at least one declined indirect transfer"
    for item in declines:
        assert isinstance(item["va"], int)
        assert item["reason"].startswith(KNOWN_PREFIXES), item
        assert item["detail"]
        # Only `unknown_base` names no table.
        assert (item["table_va"] is None) == (item["reason"] == "unknown_base"), item


def test_the_reason_histogram_totals_the_site_list():
    stats = _stats()
    counts = stats["unresolved_indirect_counts"]
    assert counts, "the pre-aggregated histogram must not be empty"
    assert sum(counts.values()) == len(stats["unresolved_indirect"])
    for reason, count in counts.items():
        observed = sum(
            1 for item in stats["unresolved_indirect"] if item["reason"] == reason
        )
        assert observed == count, reason


def test_resolved_dispatches_give_the_histogram_a_denominator():
    stats = s = _stats()
    assert isinstance(s["resolved_dispatches"], list)
    for item in stats["resolved_dispatches"]:
        assert isinstance(item["va"], int)
        assert item["arms"] >= 0


def test_a_declined_dispatch_block_is_not_reported_as_a_function_exit():
    if not SAMPLE.exists():
        pytest.skip("checked-in gcc -O2 sample not present")
    funcs, _cg, stats = g.analysis.analyze_functions_path_with_stats(  # ty: ignore[unresolved-attribute]
        str(SAMPLE),
        104_857_600,
        104_857_600,
        0,
        2048,
        50_000,
        2_000,
        0,
    )
    sites = [item["va"] for item in stats["unresolved_indirect"]]
    assert sites
    checked = 0
    for func in funcs:
        for block in func.basic_blocks:
            lo, hi = block.start_address.value, block.end_address.value
            if not any(lo <= site < hi for site in sites):
                continue
            checked += 1
            assert not block.successor_ids
            assert not block.is_exit_block(), (
                f"{block.id} ends in an unfollowed indirect transfer"
            )
    assert checked, "no block owned a declined dispatch site"
