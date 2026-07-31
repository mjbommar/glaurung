"""Focused tests for the human-readable round-trip report."""

from __future__ import annotations

import sys
import threading
import time
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


def test_review_many_runs_bounded_parallel_work_in_source_order(
    tmp_path: Path, monkeypatch
) -> None:
    """Independent programs overlap without making the Markdown nondeterministic."""
    sources = [tmp_path / "first.c", tmp_path / "second.c"]
    active = 0
    maximum = 0
    lock = threading.Lock()

    def fake_review(program, src, compiler, opt, only_broken, workdir):
        nonlocal active, maximum
        del src, compiler, opt, only_broken, workdir
        with lock:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.05 if program == "first" else 0.01)
        with lock:
            active -= 1
        return f"## {program}", {"pass": 1}

    monkeypatch.setattr(review, "review", fake_review)
    body, totals = review.review_many(sources, "gcc", "O2", False, tmp_path, jobs=2)

    assert maximum == 2
    assert body == ["## first", "## second"]
    assert totals == {"pass": 2}
