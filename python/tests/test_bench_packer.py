"""Tests for packer-detection signal in bench harness (#213)."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.bench.harness import run_one_binary, run_harness, to_markdown


_UPX_SAMPLE = Path("samples/packed/hello-gfortran-O2.upx9")
_NORMAL_SAMPLE = Path(
    "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug"
)


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"missing {p}")
    return p


def test_scorecard_packer_field_populated_for_upx() -> None:
    binary = _need(_UPX_SAMPLE)
    card = run_one_binary(binary)
    assert card.packer
    assert card.packer.get("is_packed") is True
    assert card.packer.get("packer_name") == "UPX"
    assert card.packer.get("overall_entropy", 0) > 7.0


def test_scorecard_packer_field_clean_for_normal() -> None:
    binary = _need(_NORMAL_SAMPLE)
    card = run_one_binary(binary)
    assert card.packer is not None
    assert card.packer.get("is_packed") is False


def test_markdown_summary_surfaces_packed_count() -> None:
    binary = _need(_UPX_SAMPLE)
    summary = run_harness([binary], progress=False)
    md = to_markdown(summary)
    assert "Packed binaries: **1**" in md
    # Per-binary table should include the packer column.
    assert "| packer |" in md
    assert "UPX" in md


def test_markdown_summary_omits_packed_line_when_clean() -> None:
    binary = _need(_NORMAL_SAMPLE)
    summary = run_harness([binary], progress=False)
    md = to_markdown(summary)
    assert "Packed binaries:" not in md
    # No packer column when nothing in this run is packed.
    assert "| packer |" not in md
