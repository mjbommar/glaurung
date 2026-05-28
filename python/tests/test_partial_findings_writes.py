"""F7: per-class partial JSON checkpointing in cwe_sweep.sweep_binary.

Each successful class writes <partial_dir>/<cwe>.partial.json
immediately. Clean end-of-sweep deletes them. Mid-sweep abort
(CostBudgetExceeded, generic Exception) leaves them on disk for
operator recovery.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from glaurung.llm.cwe_sweep import CWEClassSpec, sweep_binary
from glaurung.llm.findings import (
    Evidence, FindingsReport, FunctionRef, VulnerabilityFinding,
)
from glaurung.llm.usage_tracker import CostBudgetExceeded


pytestmark = pytest.mark.asyncio


def _ev():
    return [Evidence(kind="disasm", location="0x140001500",
                     text="call strcpy")]


def _finding(cwe):
    return VulnerabilityFinding(
        cwe=cwe, function=FunctionRef(name="vuln", va=0x100),
        root_cause="strcpy of caller-controlled buffer into stack array",
        evidence=_ev(),
    )


async def test_clean_sweep_deletes_partials(tmp_path):
    """When every class succeeds, the partial files are cleaned up
    before sweep_binary returns."""
    classes = [
        CWEClassSpec(id="CWE-121", title="A", prompt="p1"),
        CWEClassSpec(id="CWE-134", title="B", prompt="p2"),
    ]

    async def fake_run(path, args):
        if "CWE-121" in getattr(args, "cwe_class_prompt", ""):
            return FindingsReport(
                binary_path=path, findings=[_finding("CWE-121")],
            )
        return FindingsReport(
            binary_path=path, findings=[_finding("CWE-134")],
        )

    with patch("glaurung.llm.cwe_sweep.run_findings_pass",
               side_effect=fake_run):
        merged = await sweep_binary(
            "/tmp/x.exe", SimpleNamespace(),
            classes=classes, max_parallel=1,
            partial_dir=str(tmp_path),
        )

    assert len(merged.findings) == 2
    # No partials should remain after a clean run.
    assert list(tmp_path.glob("*.partial.json")) == []


async def test_partials_survive_mid_sweep_budget_abort(tmp_path):
    """If CostBudgetExceeded fires after CWE-121 succeeds but during
    CWE-134, the CWE-121 partial must be on disk and contain the
    correct finding."""
    classes = [
        CWEClassSpec(id="CWE-121", title="A", prompt="p1"),
        CWEClassSpec(id="CWE-134", title="B", prompt="p2"),
    ]

    async def fake_run(path, args):
        if "CWE-121" in getattr(args, "cwe_class_prompt", ""):
            return FindingsReport(
                binary_path=path, findings=[_finding("CWE-121")],
            )
        raise CostBudgetExceeded("budget exceeded mid-sweep")

    with patch("glaurung.llm.cwe_sweep.run_findings_pass",
               side_effect=fake_run):
        merged = await sweep_binary(
            "/tmp/x.exe", SimpleNamespace(),
            classes=classes, max_parallel=1,
            partial_dir=str(tmp_path),
        )

    # Merged report has CWE-121 only.
    assert [f.cwe for f in merged.findings] == ["CWE-121"]
    # Note records the abort.
    assert merged.notes and "cost-budget" in merged.notes

    # Partial for the finished class survives.
    partial_121 = tmp_path / "CWE-121.partial.json"
    assert partial_121.exists(), (
        f"partial JSON for completed CWE-121 missing; "
        f"got: {list(tmp_path.iterdir())}"
    )
    parsed = json.loads(partial_121.read_text())
    assert parsed["findings"][0]["cwe"] == "CWE-121"

    # Partial for the failed class did NOT get written.
    assert not (tmp_path / "CWE-134.partial.json").exists()


async def test_partials_survive_generic_class_exception(tmp_path):
    """Non-budget exception in one class becomes a [sweep-class-error]
    note in the merged report. The successful class's partial still
    survives (its NOT a budget abort so the cleanup-then-return path
    runs)."""
    classes = [
        CWEClassSpec(id="CWE-121", title="A", prompt="p1"),
        CWEClassSpec(id="CWE-134", title="B", prompt="p2"),
    ]

    async def fake_run(path, args):
        if "CWE-121" in getattr(args, "cwe_class_prompt", ""):
            return FindingsReport(
                binary_path=path, findings=[_finding("CWE-121")],
            )
        raise RuntimeError("transient")

    with patch("glaurung.llm.cwe_sweep.run_findings_pass",
               side_effect=fake_run):
        merged = await sweep_binary(
            "/tmp/x.exe", SimpleNamespace(),
            classes=classes, max_parallel=1,
            partial_dir=str(tmp_path),
        )

    # Merged report has the CWE-121 finding, the failure is noted.
    assert [f.cwe for f in merged.findings] == ["CWE-121"]
    assert merged.notes and "transient" in merged.notes
    # In a clean (non-budget) exit, partials are deleted.
    assert list(tmp_path.glob("*.partial.json")) == []


async def test_no_partial_dir_doesnt_crash(tmp_path):
    """partial_dir=None should keep the old behaviour: no on-disk side effects."""
    classes = [CWEClassSpec(id="CWE-121", title="A", prompt="p1")]

    async def fake_run(path, args):
        return FindingsReport(
            binary_path=path, findings=[_finding("CWE-121")],
        )

    with patch("glaurung.llm.cwe_sweep.run_findings_pass",
               side_effect=fake_run):
        merged = await sweep_binary(
            "/tmp/x.exe", SimpleNamespace(),
            classes=classes, max_parallel=1,
            partial_dir=None,
        )

    assert len(merged.findings) == 1
    # The tmp_path is untouched.
    assert list(tmp_path.iterdir()) == []
