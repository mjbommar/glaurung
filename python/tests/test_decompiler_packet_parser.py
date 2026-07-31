"""Behavioral round-trip coverage for packet-parser instruction idioms."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
sys.path.insert(0, str(ROOT / "tools"))

import fixture_harness as H  # ty: ignore[unresolved-import]  # added above
import manifest as M  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow  # ty: ignore[unresolved-attribute]


def test_clang_bswap_header_validation_round_trips() -> None:
    """BSWAP must preserve the big-endian payload-length comparison."""
    observed = H.run_lanes(
        [("07_packet_parser", "clang", "O2", ("validate_header",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["07_packet_parser:clang:O2"]
    assert lane == {"validate_header": "pass"}, lane


def test_gcc_bswap_payload_summary_round_trips() -> None:
    """BSWAP must preserve every byte used by the payload-head summary."""
    observed = H.run_lanes(
        [("07_packet_parser", "gcc", "O2", ("parse_packet",))],
        fuzz=M.FIXTURE_FUZZ,
        jobs=1,
    )

    lane = observed["07_packet_parser:gcc:O2"]
    assert lane == {"parse_packet": "pass"}, lane
