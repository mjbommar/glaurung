"""Tests for L1: VulnerabilityFinding / FindingsReport schema."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from glaurung.llm.findings import (
    AddressRef,
    Evidence,
    FindingsReport,
    FunctionRef,
    VulnerabilityFinding,
    lookup_cwe_name,
    normalize_cwe,
)


# ---- normalize_cwe ----

def test_normalize_cwe_canonical_unchanged():
    assert normalize_cwe("CWE-121") == "CWE-121"


def test_normalize_cwe_lowercase():
    assert normalize_cwe("cwe-121") == "CWE-121"


def test_normalize_cwe_no_dash():
    assert normalize_cwe("cwe121") == "CWE-121"


def test_normalize_cwe_with_space():
    assert normalize_cwe("CWE 121") == "CWE-121"


def test_normalize_cwe_naked_number():
    assert normalize_cwe("121") == "CWE-121"


def test_normalize_cwe_strips_leading_zeros():
    assert normalize_cwe("CWE-0121") == "CWE-121"


def test_normalize_cwe_strips_parenthetical():
    assert normalize_cwe("CWE-121 (Stack-based Buffer Overflow)") == "CWE-121"


def test_normalize_cwe_rejects_garbage():
    with pytest.raises(ValueError):
        normalize_cwe("")
    with pytest.raises(ValueError):
        normalize_cwe("not-a-cwe")


# ---- lookup_cwe_name ----

def test_lookup_cwe_name_known():
    assert lookup_cwe_name("CWE-121") == "Stack-based Buffer Overflow"
    assert lookup_cwe_name("CWE-416") == "Use After Free"


def test_lookup_cwe_name_unknown_returns_none():
    assert lookup_cwe_name("CWE-99999") is None


# ---- FunctionRef ----

def test_function_ref_name_only():
    f = FunctionRef(name="vuln")
    assert f.name == "vuln"
    assert f.va is None
    assert f.hex_va is None
    assert str(f) == "vuln"


def test_function_ref_va_only():
    f = FunctionRef(va=0x140001480)
    assert f.va == 0x140001480
    assert f.hex_va == "0x140001480"


def test_function_ref_both():
    f = FunctionRef(name="vuln", va=0x140001480)
    assert str(f) == "vuln @ 0x140001480"


def test_function_ref_requires_at_least_one():
    with pytest.raises(ValidationError):
        FunctionRef()


# ---- VulnerabilityFinding ----

def _good_evidence() -> Evidence:
    return Evidence(
        kind="disasm",
        location="0x140001520",
        text="call strcpy   ; arg1 controlled by caller",
    )


def test_vulnerability_finding_minimum_viable():
    f = VulnerabilityFinding(
        cwe="CWE-121",
        function=FunctionRef(name="vuln", va=0x140001480),
        root_cause="strcpy of attacker-controlled argv[1] into 32-byte stack buffer",
        evidence=[_good_evidence()],
    )
    assert f.cwe == "CWE-121"
    assert f.cwe_name == "Stack-based Buffer Overflow"  # auto-filled
    assert f.confidence == "medium"
    assert len(f.evidence) == 1


def test_vulnerability_finding_normalizes_cwe_id():
    f = VulnerabilityFinding(
        cwe="cwe 416",  # lowercase, space
        function=FunctionRef(name="VulnTouch"),
        root_cause="returns a freed heap pointer",
        evidence=[Evidence(kind="import", location="HeapFree", text="HeapFree imported")],
    )
    assert f.cwe == "CWE-416"
    assert f.cwe_name == "Use After Free"


def test_vulnerability_finding_rejects_empty_evidence():
    """Cite-or-discard policy: no findings without grounding."""
    with pytest.raises(ValidationError):
        VulnerabilityFinding(
            cwe="CWE-121",
            function=FunctionRef(name="vuln"),
            root_cause="something is wrong",
            evidence=[],
        )


def test_vulnerability_finding_rejects_short_root_cause():
    with pytest.raises(ValidationError):
        VulnerabilityFinding(
            cwe="CWE-121",
            function=FunctionRef(name="vuln"),
            root_cause="bug",  # too short
            evidence=[_good_evidence()],
        )


def test_vulnerability_finding_roundtrips_json():
    f = VulnerabilityFinding(
        cwe="CWE-190",
        function=FunctionRef(name="parse_packet_array", va=0x1400018e0),
        bug_site=AddressRef(va=0x140001910),
        root_cause="record_count * record_size wraps before malloc allocates",
        evidence=[
            Evidence(kind="disasm", location="0x140001910",
                     text="imul edx, ecx ; no overflow check"),
            Evidence(kind="import", location="malloc", text="malloc imported"),
        ],
        confidence="high",
    )
    data = f.model_dump_json()
    parsed = VulnerabilityFinding.model_validate_json(data)
    assert parsed.cwe == "CWE-190"
    assert parsed.bug_site.va == 0x140001910
    assert parsed.confidence == "high"
    assert len(parsed.evidence) == 2


# ---- FindingsReport ----

def test_findings_report_empty():
    r = FindingsReport(binary_path="/tmp/x.exe", notes="nothing stood out")
    assert r.findings == []
    assert r.notes == "nothing stood out"


def test_findings_report_by_cwe():
    f1 = VulnerabilityFinding(
        cwe="CWE-121", function=FunctionRef(name="a"),
        root_cause="stack overflow via strcpy in helper",
        evidence=[_good_evidence()],
    )
    f2 = VulnerabilityFinding(
        cwe="CWE-121", function=FunctionRef(name="b"),
        root_cause="another stack overflow site near sprintf",
        evidence=[_good_evidence()],
    )
    f3 = VulnerabilityFinding(
        cwe="CWE-416", function=FunctionRef(name="c"),
        root_cause="freed buffer returned and dereferenced by caller",
        evidence=[_good_evidence()],
    )
    r = FindingsReport(binary_path="/tmp/x", findings=[f1, f2, f3])
    grouped = r.by_cwe()
    assert sorted(grouped.keys()) == ["CWE-121", "CWE-416"]
    assert len(grouped["CWE-121"]) == 2
    assert len(grouped["CWE-416"]) == 1


def test_findings_report_merge_dedups_by_site():
    """Two reports finding the same (cwe, function, bug_site) tuple should
    produce one entry in the merged output (used by the L3 sweep)."""
    f_dup = VulnerabilityFinding(
        cwe="CWE-121", function=FunctionRef(va=0x140001480),
        bug_site=AddressRef(va=0x140001520),
        root_cause="strcpy of argv[1] into 32-byte stack buffer",
        evidence=[_good_evidence()],
    )
    r1 = FindingsReport(binary_path="/tmp/x", findings=[f_dup])
    r2 = FindingsReport(binary_path="/tmp/x", findings=[f_dup])
    f_other = VulnerabilityFinding(
        cwe="CWE-134", function=FunctionRef(va=0x140002000),
        root_cause="printf called with caller-controlled first arg",
        evidence=[_good_evidence()],
    )
    r3 = FindingsReport(binary_path="/tmp/x", findings=[f_other])
    merged = FindingsReport.merge([r1, r2, r3])
    assert len(merged.findings) == 2
    cwes = {f.cwe for f in merged.findings}
    assert cwes == {"CWE-121", "CWE-134"}
