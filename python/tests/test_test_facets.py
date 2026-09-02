"""The facet classification is current, complete, and applied.

`tests/test_facets.json` classifies every test file by what it needs, and
`conftest.py` applies that as markers. Both halves have to be true for a CI
job's `-m` selection to mean anything: a file the JSON does not know about
would run in every tier regardless of what it needs, and a stale JSON would
tier a file by what it used to need.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FACETS = ROOT / "tests" / "test_facets.json"
GENERATOR = ROOT / "tools" / "gen_test_facets.py"
TESTS = ROOT / "python" / "tests"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_test_facets", GENERATOR)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_test_file_is_classified():
    """A file the JSON does not know about runs in every tier, whatever it needs."""
    recorded = set(json.loads(FACETS.read_text())["files"])
    on_disk = {p.name for p in TESTS.glob("test_*.py")}
    missing = sorted(on_disk - recorded)
    assert not missing, (
        "unclassified test files -- regenerate with "
        f"`uv run python {GENERATOR.relative_to(ROOT)}`:\n  " + "\n  ".join(missing)
    )


def test_the_classification_is_current():
    """The committed JSON must equal what the generator produces from HEAD."""
    proc = subprocess.run(
        [sys.executable, str(GENERATOR)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-400:]
    drift = subprocess.run(
        ["git", "diff", "--quiet", "--", str(FACETS.relative_to(ROOT))],
        cwd=ROOT,
        check=False,
    ).returncode
    assert drift == 0, (
        f"{FACETS.name} differs from what the generator produces. A test's "
        "requirements changed; commit the regenerated file so CI tiers it "
        "correctly."
    )


def test_every_facet_in_the_json_is_a_registered_marker():
    """An unregistered marker is a typo pytest will warn about and then ignore."""
    ini = (ROOT / "pytest.ini").read_text()
    used = {
        f for names in json.loads(FACETS.read_text())["files"].values() for f in names
    }
    unregistered = sorted(f for f in used if f"\n    {f}:" not in ini)
    assert not unregistered, (
        f"facets not registered in pytest.ini markers: {unregistered}"
    )


def test_core_means_no_other_facet():
    """`core` is the absence of requirements; a file cannot be core AND need
    fixtures. That invariant is what lets `-m core` be the floor."""
    files = json.loads(FACETS.read_text())["files"]
    bad = {n: f for n, f in files.items() if "core" in f and len(f) > 1}
    assert not bad, f"core combined with another facet: {bad}"


def test_this_file_is_core():
    """A sanity check on the rules themselves: this file needs nothing."""
    assert _generator().classify(Path(__file__).read_text()) == ["core"]


def test_the_known_failure_corpus_is_fixtures():
    """The 1,162-row corpus MUST carry `fixtures`, or `-m "not fixtures"` on the
    per-push runner would collect it and produce 1,162 runtime skips instead
    of deselecting it. This is the file the facet system exists for."""
    files = json.loads(FACETS.read_text())["files"]
    assert "fixtures" in files.get("test_known_decompiler_failures.py", []), (
        "test_known_decompiler_failures.py is not classified `fixtures`"
    )


@pytest.mark.parametrize("facet", ["core", "fixtures", "toolchain", "lfs"])
def test_markers_are_actually_applied_at_collection(facet):
    """The hook must apply the JSON, not merely exist.

    Collected in a subprocess over the whole suite, because a session that
    collected only this file holds no `fixtures` items to find. And the hook
    must be `tryfirst`: pytest's `mark` plugin deselects inside its own
    collection hook, which runs before a conftest's by default -- the first
    version of this hook was ordered after it and every `-m <facet>` selected
    the same four tests.
    """
    files = json.loads(FACETS.read_text())["files"]
    expected_files = {n for n, f in files.items() if facet in f}
    if not expected_files:
        pytest.skip(f"no file is classified {facet}")
    # `-o addopts=`: pytest.ini already carries `-q`, and a second `-q` turns
    # `--co` output into `file: N` lines with no `::` in them. Counting `::`
    # lines under that format returned 4 for every facet and looked exactly
    # like the hook not working. Override the ini so the format is known.
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(TESTS),
            "-o",
            "addopts=",
            "--co",
            "-q",
            "-m",
            facet,
            "-p",
            "no:randomly",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=600,
        check=False,
    )
    # Only real node IDs, which start with the tests path. Warning lines such
    # as `  Test: python/tests/x.py::f, argvalues type: generator` also
    # contain `::` and were being counted as four collected tests under EVERY
    # facet, which looked exactly like a broken marker hook.
    collected = {
        ln.split("::")[0].rsplit("/", 1)[-1]
        for ln in proc.stdout.splitlines()
        if ln.startswith("python/tests/") and "::" in ln
    }
    assert collected, f"`-m {facet}` collected nothing:\n{proc.stdout[-400:]}"
    # Every collected file must be one the JSON says carries this facet.
    stray = sorted(collected - expected_files)
    assert not stray, (
        f"`-m {facet}` collected files the JSON does not classify {facet}: {stray[:5]}"
    )
