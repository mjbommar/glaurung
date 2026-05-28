"""Tests for L4: cite-or-discard finding verification."""

from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.llm.finding_verifier import (
    _AnalysedFunction,
    _BinaryContext,
    _parse_va,
    verify_finding,
    verify_report,
)
from glaurung.llm.findings import (
    AddressRef,
    Evidence,
    FindingsReport,
    FunctionRef,
    VulnerabilityFinding,
)


# ---- helpers ----

V1_STRCPY = Path(
    "/nas4/data/workspace-infosec/scratch/cwe-demo-corpus-2026-05-22/build/cwe121_strcpy.exe"
)


def _fake_ctx() -> _BinaryContext:
    """A hand-built BinaryContext that doesn't touch disk."""
    fns_by_va = {
        0x140001480: _AnalysedFunction("vuln", 0x140001480, 0x140001500),
        0x140002000: _AnalysedFunction("main", 0x140002000, 0x140002100),
    }
    fns_by_name = {fn.name: [fn] for fn in fns_by_va.values()}
    return _BinaryContext(
        binary_path="/fake/path",
        functions_by_va=fns_by_va,
        functions_by_name=fns_by_name,
        imports={"strcpy", "printf", "malloc"},
        decompile_cache={
            0x140001480: "fn vuln {\n  rsp -= 32\n  call strcpy\n  call __mingw_printf\n}\n",
        },
    )


def _good_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        cwe="CWE-121",
        function=FunctionRef(name="vuln", va=0x140001480),
        bug_site=AddressRef(va=0x140001488),  # inside [0x140001480, 0x140001500)
        root_cause="strcpy of argv[1] into 32-byte stack buffer",
        evidence=[
            Evidence(kind="import", location="strcpy", text="strcpy imported"),
            Evidence(kind="disasm", location="0x140001488",
                     text="call strcpy"),
            Evidence(kind="decompile", location="vuln:strcpy-call",
                     text="call strcpy"),
        ],
        confidence="high",
    )


# ---- _parse_va ----

def test_parse_va_hex():
    assert _parse_va("0x140001480") == 0x140001480


def test_parse_va_decimal():
    assert _parse_va("1234") == 1234


def test_parse_va_embedded():
    assert _parse_va("at offset 0x140001488; copies from rsp") == 0x140001488


def test_parse_va_missing():
    assert _parse_va("imports[strcpy]") is None
    assert _parse_va("") is None


# ---- verify_finding: happy path ----

def test_verify_finding_clean_finding_no_issues():
    f = _good_finding()
    ctx = _fake_ctx()
    verify_finding(f, ctx)
    assert f.verification_issues == []
    assert f.confidence == "high"  # not demoted


# ---- verify_finding: catches each failure mode ----

def test_verify_finding_unknown_function_va():
    f = _good_finding()
    f.function = FunctionRef(name="ghost", va=0xdeadbeef)
    ctx = _fake_ctx()
    verify_finding(f, ctx)
    assert any("not found in analysis" in s for s in f.verification_issues)
    assert f.confidence == "low"


def test_verify_finding_bug_site_outside_function():
    f = _good_finding()
    f.bug_site = AddressRef(va=0x140003000)  # way past 'vuln' end
    ctx = _fake_ctx()
    verify_finding(f, ctx)
    assert any("outside function" in s for s in f.verification_issues)
    assert f.confidence == "low"


def test_verify_finding_import_not_in_table():
    f = _good_finding()
    f.evidence = [Evidence(kind="import", location="zog_exotic",
                           text="zog_exotic imported")]
    ctx = _fake_ctx()
    verify_finding(f, ctx)
    assert any("not in the PE import table" in s for s in f.verification_issues)
    assert f.confidence == "low"


def test_verify_finding_disasm_va_outside_any_function():
    f = _good_finding()
    f.evidence = [Evidence(kind="disasm", location="0xffffff00",
                           text="bogus")]
    ctx = _fake_ctx()
    verify_finding(f, ctx)
    assert any("not inside any analyzed function" in s
               for s in f.verification_issues)
    assert f.confidence == "low"


def test_verify_finding_decompile_snippet_missing():
    f = _good_finding()
    f.evidence = [Evidence(kind="decompile", location="vuln:phantom",
                           text="phantomFunctionWeNeverCalled")]
    ctx = _fake_ctx()
    verify_finding(f, ctx)
    assert any("not found in pseudocode" in s for s in f.verification_issues)
    assert f.confidence == "low"


def test_verify_finding_disasm_va_parseable_in_compound_location():
    """Real-life: agents often emit 'at offset 0x140001488; xyz' as location."""
    f = _good_finding()
    f.evidence = [Evidence(
        kind="disasm",
        location="call 0x140001490 (strcpy wrapper) at offset 0x140001488",
        text="call",
    )]
    ctx = _fake_ctx()
    verify_finding(f, ctx)
    assert f.verification_issues == []


def test_verify_finding_flags_runtime_helper_function():
    """D3 integration: when the agent claims a bug in mingw's
    __pei386_runtime_relocator (a runtime helper), the verifier must flag
    it and demote confidence."""
    ctx = _fake_ctx()
    # Add a runtime-helper function to the context that the finding will reference.
    rt = _AnalysedFunction(
        "__pei386_runtime_relocator",
        0x140003000, 0x140003100,
        function_class="runtime_helper",
    )
    ctx.functions_by_va[0x140003000] = rt
    ctx.functions_by_name["__pei386_runtime_relocator"] = [rt]

    f = VulnerabilityFinding(
        cwe="CWE-190",
        function=FunctionRef(name="__pei386_runtime_relocator", va=0x140003000),
        bug_site=AddressRef(va=0x140003010),
        root_cause="multiplication wraps before allocator allocates buffer",
        evidence=[Evidence(kind="disasm", location="0x140003010",
                           text="imul edx, ecx")],
        confidence="high",
    )
    verify_finding(f, ctx)
    assert any("runtime_helper" in s for s in f.verification_issues)
    assert f.confidence == "low"


def test_verify_finding_demote_off_keeps_confidence():
    """demote_on_issue=False preserves confidence even with issues."""
    f = _good_finding()
    f.function = FunctionRef(va=0xdeadbeef)
    ctx = _fake_ctx()
    verify_finding(f, ctx, demote_on_issue=False)
    assert f.verification_issues
    assert f.confidence == "high"  # NOT demoted


# ---- live binary verification ----

@pytest.mark.skipif(
    not V1_STRCPY.exists(),
    reason="v1 corpus not present at expected path",
)
def test_verify_finding_against_real_binary_clean():
    """A finding with real VA + real symbol should verify against the v1
    strcpy demo binary without issues."""
    ctx = _BinaryContext.build(str(V1_STRCPY))
    # vuln() in cwe121_strcpy.exe lives at 0x1400014b4 per our earlier
    # discovery. We don't assume the strcpy VA; cite the function entry.
    vuln = ctx.functions_by_name.get("vuln") or []
    assert vuln, "vuln symbol should be present in the v1 corpus"
    entry = vuln[0].entry_va
    finding = VulnerabilityFinding(
        cwe="CWE-121",
        function=FunctionRef(name="vuln", va=entry),
        bug_site=AddressRef(va=entry + 4),
        root_cause="strcpy into 32-byte stack buffer overflows on long argv[1]",
        evidence=[
            Evidence(kind="import", location="strcpy", text="strcpy imported"),
            Evidence(kind="disasm", location=f"0x{entry + 4:x}",
                     text="instruction inside vuln"),
        ],
        confidence="high",
    )
    verify_finding(finding, ctx)
    # The two evidence items are: (1) strcpy is in the import table -- true;
    # (2) entry+4 is inside vuln -- true. No issues expected.
    assert finding.verification_issues == [], (
        f"unexpected issues: {finding.verification_issues}"
    )
    assert finding.confidence == "high"
