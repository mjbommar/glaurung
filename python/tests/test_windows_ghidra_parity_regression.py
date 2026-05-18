"""Windows corpus regression checks against the current Ghidra parity targets."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

import glaurung as g
from glaurung.cli.commands.windows_risk import build_windows_risk_report


_WINDOWS_CORPUS = Path("/nas4/data/binary-analysis/glaurung/binaries/windows-10-x64")


@dataclass(frozen=True)
class GhidraFunctionReference:
    path: Path
    ghidra_function_count: int
    min_glaurung_function_count: int
    must_find_vas: tuple[int, ...]
    must_name_vas: tuple[int, ...] = ()


_MIGSTORE = GhidraFunctionReference(
    path=_WINDOWS_CORPUS / "migstore.dll",
    # Captured from the Glaurung-vs-Ghidra Windows comparison campaign.
    ghidra_function_count=3339,
    # Keep this below the current 3,136 count so the test catches major
    # regressions without pretending Glaurung has exact Ghidra parity yet.
    min_glaurung_function_count=3100,
    must_find_vas=(
        # These are catalog functions Ghidra identified and the old CFG pass
        # missed when INT3 padding let an earlier function swallow .pdata starts.
        0x180004900,
        0x180004640,
        0x18000B0C0,
    ),
    must_name_vas=(
        0x180004900,
        0x180004640,
        0x18000B0C0,
    ),
)

_RASMIGPLUGIN = _WINDOWS_CORPUS / "rasmigplugin.dll"


def _need(path: Path) -> Path:
    if not path.exists():
        pytest.skip(f"missing Windows corpus sample {path}")
    return path


def _analyze(path: Path) -> list:
    funcs, _cg = g.analysis.analyze_functions_path(
        str(path),
        max_functions=10_000,
        max_blocks=1_000_000,
        max_instructions=30_000_000,
        timeout_ms=120_000,
    )
    return funcs


def _risk_args() -> SimpleNamespace:
    return SimpleNamespace(
        max_read_bytes=104_857_600,
        max_file_size=1_073_741_824,
        max_functions=4096,
        max_candidates=5,
        max_decompile=3,
        timeout_ms=30_000,
        str_min_len=6,
        str_max_samples=10_000,
        max_xrefs=500_000,
        pdb_cache="",
        no_decompile=False,
    )


@pytest.mark.skipif(not _MIGSTORE.path.exists(), reason="migstore corpus missing")
def test_migstore_function_discovery_tracks_ghidra_reference() -> None:
    ref = GhidraFunctionReference(
        path=_need(_MIGSTORE.path),
        ghidra_function_count=_MIGSTORE.ghidra_function_count,
        min_glaurung_function_count=_MIGSTORE.min_glaurung_function_count,
        must_find_vas=_MIGSTORE.must_find_vas,
        must_name_vas=_MIGSTORE.must_name_vas,
    )
    funcs = _analyze(ref.path)
    by_va = {int(func.entry_point.value): str(func.name) for func in funcs}

    assert len(funcs) >= ref.min_glaurung_function_count, (
        f"{ref.path.name}: discovered {len(funcs)} functions, below "
        f"regression floor {ref.min_glaurung_function_count}; Ghidra reference "
        f"count is {ref.ghidra_function_count}"
    )
    for va in ref.must_find_vas:
        assert va in by_va, f"{ref.path.name}: missing Ghidra target VA {va:#x}"
    for va in ref.must_name_vas:
        assert not by_va[va].startswith("sub_"), (
            f"{ref.path.name}: Ghidra target {va:#x} lost its non-generic name"
        )


@pytest.mark.skipif(not _RASMIGPLUGIN.exists(), reason="rasmigplugin corpus missing")
def test_rasmigplugin_windows_risk_tracks_buffer_length_flow() -> None:
    report = build_windows_risk_report(_need(_RASMIGPLUGIN), _risk_args())

    assert report["summary"]["function_count"] >= 800
    risk_kinds = {str(item["kind"]) for item in report["risk_items"]}
    assert "file-read-allocation-flow" in risk_kinds
    assert "file-read-allocation-argument-flow" in risk_kinds

    row = next(
        (
            candidate
            for candidate in report["functions"]
            if "file-read-allocation-argument-flow"
            in (candidate.get("function_summary") or {}).get("risk_signals", [])
        ),
        None,
    )
    assert row is not None, "no candidate summary retained the buffer/length flow"
    assert row.get("decompile_error") is None
    summary = row["function_summary"]
    assert {"buffer", "length"} <= set(summary["argument_roles"])
    assert any(
        flow["kind"] == "file-read-allocation-argument-flow"
        for flow in summary["data_flows"]
    )
    assert summary["call_summary"]["total"] >= 1
