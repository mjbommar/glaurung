"""Tests for L3: CWE-class-driven discovery sweep orchestration."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from glaurung.llm.cwe_sweep import (
    CWEClassSpec,
    DEFAULT_CWE_CLASSES,
    _select_classes,
    sweep_binary,
)
from glaurung.llm.findings import (
    Evidence,
    FindingsReport,
    FunctionRef,
    VulnerabilityFinding,
)


pytestmark = pytest.mark.asyncio


# ---- catalog + class filtering ----

def _ev():
    return [Evidence(kind="disasm", location="0x140001500", text="call strcpy")]


def test_default_catalog_covers_expected_cwes():
    """Spot-check that the default catalog covers the families we built
    rules + corpus binaries around: CWE-121, CWE-134, CWE-190, CWE-416,
    CWE-476, CWE-401, CWE-787."""
    ids = {c.id for c in DEFAULT_CWE_CLASSES}
    assert {"CWE-121", "CWE-134", "CWE-190", "CWE-416",
            "CWE-476", "CWE-401", "CWE-787"} <= ids


def test_select_classes_userland_filter_excludes_kernel():
    classes = [
        CWEClassSpec(id="CWE-121", title="t", prompt="p", applies_to="any"),
        CWEClassSpec(id="CWE-476", title="t", prompt="p", applies_to="kernel"),
    ]
    out = _select_classes(classes, "userland")
    assert [c.id for c in out] == ["CWE-121"]


def test_select_classes_kernel_filter_includes_any():
    classes = [
        CWEClassSpec(id="CWE-121", title="t", prompt="p", applies_to="any"),
        CWEClassSpec(id="CWE-476", title="t", prompt="p", applies_to="kernel"),
        CWEClassSpec(id="CWE-200", title="t", prompt="p", applies_to="userland"),
    ]
    out = _select_classes(classes, "kernel")
    assert sorted([c.id for c in out]) == ["CWE-121", "CWE-476"]


def test_select_classes_any_returns_everything():
    classes = [
        CWEClassSpec(id="A", title="t", prompt="p", applies_to="kernel"),
        CWEClassSpec(id="B", title="t", prompt="p", applies_to="userland"),
    ]
    assert len(_select_classes(classes, None)) == 2
    assert len(_select_classes(classes, "any")) == 2


# ---- sweep_binary orchestration ----

async def test_sweep_invokes_one_pass_per_class():
    """Each class in the catalog -> one run_findings_pass call. The
    binary path is forwarded; the per-call args carry the class prompt."""
    classes = [
        CWEClassSpec(id="CWE-121", title="A", prompt="prompt-A"),
        CWEClassSpec(id="CWE-134", title="B", prompt="prompt-B"),
    ]
    seen_paths: list[str] = []
    seen_prompts: list[str] = []

    async def fake_run(path, args):
        seen_paths.append(path)
        seen_prompts.append(getattr(args, "cwe_class_prompt", ""))
        return FindingsReport(binary_path=path, findings=[])

    with patch("glaurung.llm.cwe_sweep.run_findings_pass", side_effect=fake_run):
        await sweep_binary(
            "/tmp/x.exe",
            SimpleNamespace(),
            classes=classes,
        )

    assert seen_paths == ["/tmp/x.exe", "/tmp/x.exe"]
    assert any("prompt-A" in p for p in seen_prompts)
    assert any("prompt-B" in p for p in seen_prompts)


async def test_sweep_merges_findings_from_each_class():
    """Findings from all class passes should land in the merged report,
    deduplicated by (cwe, function, bug_site)."""
    classes = [
        CWEClassSpec(id="CWE-121", title="A", prompt="A"),
        CWEClassSpec(id="CWE-134", title="B", prompt="B"),
    ]

    f_a = VulnerabilityFinding(
        cwe="CWE-121",
        function=FunctionRef(name="vuln", va=0x140001480),
        root_cause="strcpy of caller-controlled arg into stack buffer",
        evidence=_ev(),
    )
    f_b = VulnerabilityFinding(
        cwe="CWE-134",
        function=FunctionRef(name="log_user_msg", va=0x140002000),
        root_cause="printf called with caller-controlled first argument",
        evidence=_ev(),
    )

    async def fake_run(path, args):
        prompt = getattr(args, "cwe_class_prompt", "")
        if "CWE-121" in prompt:
            return FindingsReport(binary_path=path, findings=[f_a])
        return FindingsReport(binary_path=path, findings=[f_b])

    with patch("glaurung.llm.cwe_sweep.run_findings_pass", side_effect=fake_run):
        merged = await sweep_binary(
            "/tmp/x.exe",
            SimpleNamespace(),
            classes=classes,
        )

    cwes = sorted(f.cwe for f in merged.findings)
    assert cwes == ["CWE-121", "CWE-134"]


async def test_sweep_class_error_records_note_does_not_kill_pass():
    """An exception in one class's pass shouldn't abort the whole sweep."""
    classes = [
        CWEClassSpec(id="CWE-121", title="A", prompt="A"),
        CWEClassSpec(id="CWE-134", title="B", prompt="B"),
    ]

    async def fake_run(path, args):
        if "CWE-121" in getattr(args, "cwe_class_prompt", ""):
            raise RuntimeError("API rate limit")
        return FindingsReport(
            binary_path=path,
            findings=[VulnerabilityFinding(
                cwe="CWE-134",
                function=FunctionRef(name="x", va=0x100),
                root_cause="printf with caller-controlled format argument",
                evidence=_ev(),
            )],
        )

    with patch("glaurung.llm.cwe_sweep.run_findings_pass", side_effect=fake_run):
        merged = await sweep_binary(
            "/tmp/x.exe",
            SimpleNamespace(),
            classes=classes,
        )

    # The successful class's finding is still in the report.
    assert any(f.cwe == "CWE-134" for f in merged.findings)
    # The failure is recorded in notes.
    assert merged.notes and "rate limit" in merged.notes


async def test_sweep_force_cwe_id_overrides_agent_drift():
    """If the agent returns CWE-120 for our CWE-121 prompt, the sweep
    re-labels the finding as CWE-121 (the prompt's class) and keeps
    the original CWE in alternates."""
    classes = [
        CWEClassSpec(id="CWE-121", title="Stack overflow", prompt="x"),
    ]

    f = VulnerabilityFinding(
        cwe="CWE-120",  # agent drifted from our CWE-121 request
        function=FunctionRef(name="vuln", va=0x140001480),
        root_cause="something memory-unsafe via strcpy into a fixed buffer",
        evidence=_ev(),
    )

    async def fake_run(path, args):
        return FindingsReport(binary_path=path, findings=[f])

    with patch("glaurung.llm.cwe_sweep.run_findings_pass", side_effect=fake_run):
        merged = await sweep_binary(
            "/tmp/x.exe",
            SimpleNamespace(),
            classes=classes,
        )

    assert merged.findings[0].cwe == "CWE-121"
    assert merged.findings[0].alternates
    assert merged.findings[0].alternates[0].cwe == "CWE-120"


async def test_sweep_applies_to_filter_passes_through():
    """sweep_binary should honor the applies_to_filter param."""
    classes = [
        CWEClassSpec(id="A", title="t", prompt="p-A", applies_to="userland"),
        CWEClassSpec(id="B", title="t", prompt="p-B", applies_to="kernel"),
    ]
    captured = []

    async def fake_run(path, args):
        captured.append(getattr(args, "cwe_class_prompt", ""))
        return FindingsReport(binary_path=path, findings=[])

    with patch("glaurung.llm.cwe_sweep.run_findings_pass", side_effect=fake_run):
        await sweep_binary("/tmp/x.exe", SimpleNamespace(),
                           classes=classes, applies_to_filter="userland")
    # Only the userland class's prompt should have run.
    assert any("p-A" in c for c in captured)
    assert not any("p-B" in c for c in captured)
