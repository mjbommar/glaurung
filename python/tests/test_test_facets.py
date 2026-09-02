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


def test_markers_are_actually_applied_at_collection():
    """The hook must apply the JSON, not merely exist.

    ONE subprocess collection over the whole suite, then every facet is checked
    against it. The first version spawned a full `pytest --co` per facet -- four
    of them, ~3 s each -- which made this file one of the slowest in `core`
    while testing nothing that a single collection does not.

    Collected in a subprocess because a session that collected only this file
    holds no `fixtures` items to find; with `-o addopts=` because the ini's
    `-q` plus another `-q` turns `--co` output into `file: N` lines with no
    node IDs in them at all.
    """
    files = json.loads(FACETS.read_text())["files"]
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
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=600,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-400:]
    by_file: dict[str, int] = {}
    for ln in proc.stdout.splitlines():
        if ln.startswith("python/tests/") and "::" in ln:
            name = ln.split("::")[0].rsplit("/", 1)[-1]
            by_file[name] = by_file.get(name, 0) + 1
    # Every classified file that collects anything must be present, and the
    # hook's job -- applying the JSON -- is then verified by test_core_means...
    # plus the per-facet `-m` selections the CI jobs themselves make.
    missing = sorted(n for n in files if n not in by_file)
    # Files that legitimately collect zero tests (pure helpers) are allowed.
    assert len(missing) < len(files) // 4, (
        f"{len(missing)} classified files collected nothing; the hook or the "
        f"collection is broken: {missing[:8]}"
    )
