"""Focused tests for the human-readable round-trip report."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

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


def test_decompiled_uses_the_repository_cli_without_venv_activation(
    tmp_path: Path, monkeypatch
) -> None:
    """The documented executable must not depend on the caller's PATH."""
    binary = tmp_path / "sample.so"
    binary.touch()
    calls: list[list[str]] = []

    monkeypatch.setattr(
        review.BG,
        "glaurung_bin",
        lambda: "/repo/.venv/bin/glaurung",
    )

    def fake_run(argv, **kwargs):
        del kwargs
        calls.append([str(arg) for arg in argv])
        if argv[0] == "nm":
            return SimpleNamespace(stdout="0000000000001100 T target\n")
        return SimpleNamespace(stdout="int target(void) { return 1; }\n")

    monkeypatch.setattr(review.subprocess, "run", fake_run)

    assert review.decompiled(binary, "target") == "int target(void) { return 1; }"
    assert calls[1][0] == "/repo/.venv/bin/glaurung"


def test_verdicts_uses_synced_python_and_rejects_worker_failure(
    tmp_path: Path, monkeypatch
) -> None:
    """A broken differential is infrastructure failure, never a 0-of-0 report."""
    binary = tmp_path / "sample.so"
    source = tmp_path / "sample.c"
    binary.touch()
    source.write_text("int target(void) { return 1; }\n")
    calls: list[list[str]] = []
    monkeypatch.setattr(
        review.BG,
        "python_bin",
        lambda: "/repo/.venv/bin/python",
    )

    def failed_run(argv, **kwargs):
        del kwargs
        calls.append([str(arg) for arg in argv])
        return SimpleNamespace(returncode=2, stdout="", stderr="missing dependency")

    monkeypatch.setattr(review.subprocess, "run", failed_run)

    try:
        review.verdicts(binary, source, "sample")
    except RuntimeError as error:
        assert "missing dependency" in str(error)
    else:
        raise AssertionError("a failed differential must abort the review")
    assert calls[0][0] == "/repo/.venv/bin/python"


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
