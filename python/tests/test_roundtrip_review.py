"""Focused tests for the human-readable round-trip report."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import roundtrip_review as review  # ty: ignore[unresolved-import]  # added above


def test_source_of_prefers_definition_over_recursive_calls(tmp_path: Path) -> None:
    """A recursive call later on the signature line must not hide the function."""
    source = tmp_path / "recursion.c"
    source.write_text(
        "long ackermann(long m,long n){ if(m==0)return n+1; "
        "return ackermann(m-1, ackermann(m,n-1)); }\n"
    )

    assert review.source_of(source, "ackermann") == source.read_text().strip()
