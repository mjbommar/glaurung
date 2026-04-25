"""Tests for the benchmark harness (#159)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glaurung.bench import run_one_binary
from glaurung.bench.harness import to_json, to_markdown
from glaurung.bench.metrics import (
    discovery_metrics,
    language_from_source_path,
)


# Single-binary smoke targets. Both must exist for the bench package to
# claim it works at all; if either is missing the suite skips.
_HELLO_C_O2 = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-c-gcc-O2"
)
_HELLO_CPP_O2 = Path(
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing sample binary {p}")
    return p


def test_language_from_source_path() -> None:
    assert language_from_source_path("samples/source/cpp/hello.cpp") == "cpp"
    assert language_from_source_path("/workspace/source/c/hello.c") == "c"
    assert language_from_source_path("hello.f90") == "fortran"
    assert language_from_source_path("hello.rs") == "rust"
    assert language_from_source_path(None) is None
    assert language_from_source_path("hello.unknown") is None


def test_discovery_metrics_counts_chunks() -> None:
    """Synthetic Function-like objects so we test the metric without a binary."""
    class _Range:
        def __init__(self, start: int, size: int) -> None:
            class _A: pass
            self.start = _A(); self.start.value = start
            self.size = size

    class _Fn:
        def __init__(self, name, blocks, chunks):
            self.name = name
            self.basic_blocks = blocks
            self.chunks = chunks

    funcs = [
        _Fn("main", [object()], [_Range(0x1000, 0x80), _Range(0x2000, 0x10)]),  # multi-chunk
        _Fn("helper", [object()], [_Range(0x3000, 0x40)]),
        _Fn("sub_4000", [object()], [_Range(0x4000, 0x20)]),                     # placeholder
        _Fn("widget.cold", [object()], [_Range(0x5000, 0x10)]),                  # orphan: parent missing
    ]
    m = discovery_metrics(funcs)
    assert m.total == 4
    assert m.named_from_symbols == 3       # main, helper, widget.cold (not sub_*)
    assert m.auto_named_sub == 1
    assert m.with_chunks_gt_one == 1
    assert m.cold_orphans == 1             # `widget.cold` survived → orphan
    assert 0.0 < m.name_match_rate <= 1.0


def test_run_one_binary_against_real_elf() -> None:
    binary = _need(_HELLO_C_O2)
    card = run_one_binary(binary, max_decompile_functions=8)
    assert card.error is None, f"unexpected error: {card.error}"
    assert card.discovery, "discovery metrics empty"
    assert card.discovery["total"] >= 1
    # GCC -O2 hello-c emits at least main + a few CRT funcs.
    assert card.discovery["named_from_symbols"] >= 1
    # Decompile should land at least one non-empty result.
    assert card.decompile["succeeded"] >= 1
    assert card.decompile["attempted"] >= 1
    # Source path should resolve via metadata sidecar.
    assert card.source_path is not None
    assert "hello.c" in card.source_path
    # Language detection should hit `c`.
    assert card.triage["expected_language"] == "c"
    assert card.triage["language_match"] is True


def test_run_one_binary_detects_main_cold_chunk() -> None:
    """The g++ -O2 hello binary has a real `main.cold` split — the
    benchmark must record it as a chunk merge with zero cold orphans.
    Regression guard for #156 → #159 integration."""
    binary = _need(_HELLO_CPP_O2)
    card = run_one_binary(binary, max_decompile_functions=12)
    assert card.error is None
    assert card.discovery["with_chunks_gt_one"] >= 1, (
        f"expected at least one multi-chunk function (main + .cold); "
        f"discovery={card.discovery}"
    )
    assert card.discovery["cold_orphans"] == 0


def test_summary_serialization_round_trip(tmp_path: Path) -> None:
    binary = _need(_HELLO_C_O2)
    card = run_one_binary(binary, max_decompile_functions=4)

    from glaurung.bench.harness import BenchSummary
    summ = BenchSummary(
        schema_version="1",
        glaurung_commit=None,
        timestamp="2026-04-25T00:00:00+00:00",
        scorecards=[card],
    )
    payload = to_json(summ)
    parsed = json.loads(payload)
    assert parsed["schema_version"] == "1"
    assert parsed["scorecards"][0]["binary_path"] == str(binary)
    assert "summary" in parsed and "totals" in parsed["summary"]

    md = to_markdown(summ)
    assert "Glaurung benchmark" in md
    assert binary.name in md
