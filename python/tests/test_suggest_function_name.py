"""Tests for the PE / CRT / WIL boilerplate filter in
``glaurung.llm.tools.suggest_function_name``.

Background: on the May 2026 Patch-Tuesday corpus, 154 of 345 (45%) of
``glaurung name-func`` proposals hallucinated ``parse_pe_*`` /
``pe_header_*`` / ``init_pe_*`` names. Root cause: the naming LLM was
fed the linker-injected DOS stub, Rich-header signature, PE section
names, CRT/SEH boilerplate, and WIL telemetry helpers as if they were
functional evidence. This module locks in the filter that strips that
contamination before the strings + pseudocode reach the prompt.

These tests do not require a live LLM key.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from glaurung.llm.context import Budgets, MemoryContext
from glaurung.llm.tools.suggest_function_name import (
    _has_strong_kernel_call_evidence,
    _is_pe_boilerplate,
    _strip_pe_boilerplate,
    _strip_pe_boilerplate_lines,
    build_naming_prompt,
)


# ---------------------------------------------------------------------------
# _strip_pe_boilerplate -- whole-string filter
# ---------------------------------------------------------------------------


def test_strip_dos_stub_keeps_real_string():
    """The DOS stub is rejected; a real user string survives."""
    out = _strip_pe_boilerplate(
        ["!This program cannot be run in DOS mode.", "real_user_string"]
    )
    assert out == ["real_user_string"]


def test_strip_dos_stub_all_variants():
    for stub in (
        "!This program cannot be run in DOS mode.",
        "This program cannot be run in DOS mode.",
        "This program cannot be run in DOS mode.\r\n$",
    ):
        assert _is_pe_boilerplate(stub), stub
        assert _strip_pe_boilerplate([stub, "keep"]) == ["keep"]


def test_strip_rich_header_signature_prefix():
    """Anything starting with ``<Rich`` is boilerplate."""
    assert _is_pe_boilerplate("<Rich")
    assert _is_pe_boilerplate("<Rich1234signature")
    assert _strip_pe_boilerplate(["<Rich.signature", "domain.local"]) == [
        "domain.local"
    ]


def test_strip_pe_section_names_in_isolation():
    for sec in (
        ".text",
        ".rdata",
        ".data",
        ".rsrc",
        ".reloc",
        ".bss",
        ".pdata",
        ".xdata",
    ):
        assert _is_pe_boilerplate(sec), sec
    out = _strip_pe_boilerplate([".text", ".rdata", "config.json", ".bss"])
    assert out == ["config.json"]


def test_strip_crt_seh_gs_cookie_prefixes():
    for token in (
        "__security_init_cookie",
        "__security_init_cookie_x64",
        "__GSHandlerCheck",
        "__GSHandlerCheckCommon",
        "__security_check_cookie",
        "__report_gsfailure",
        "__intrinsic_setjmpex",
        "__isa_available",
        "__isa_available_init",
        "_RTC_InitBase",
        "_RTC_Shutdown",
        "__chkstk",
        "__chkstk_ms",
    ):
        assert _is_pe_boilerplate(token), token


def test_strip_wil_and_feature_servicing_prefixes():
    for token in (
        "wil_details_FeatureReporting_RecordUsage",
        "Feature_Servicing_Acquire",
        "Feature_Servicing_FeatureEnabled",
        "wil_details_RaiseFailureException",
    ):
        assert _is_pe_boilerplate(token), token


def test_strip_wpp_tracing_helpers():
    assert _is_pe_boilerplate("Microsoft.Diagnostics.Tracing.WPP")
    assert _is_pe_boilerplate("WPP_GLOBAL_Control")
    assert _is_pe_boilerplate("WPP_TRACE_PROVIDER_Cldnt")


def test_filter_is_case_sensitive():
    """Filter must be case-sensitive -- ``.TEXT`` is a real string, not
    a section name."""
    assert not _is_pe_boilerplate(".TEXT")
    assert not _is_pe_boilerplate(".Data")
    # Real lowercase token survives.
    out = _strip_pe_boilerplate([".TEXT", ".Data"])
    assert out == [".TEXT", ".Data"]


def test_real_filename_paths_survive():
    """Strings that contain dots but are not section-name-equal must
    survive (this is the regression we are guarding against)."""
    inputs = [
        ".text.is.a.filename.txt",
        ".rdata-style-id",
        "C:\\Windows\\System32\\cldflt.sys",
    ]
    assert _strip_pe_boilerplate(inputs) == inputs


# ---------------------------------------------------------------------------
# _has_strong_kernel_call_evidence -- threshold-based dropping
# ---------------------------------------------------------------------------


def test_strong_kernel_evidence_three_distinct_calls():
    """Three distinct kernel calls -> evidence is strong."""
    calls = ["IoCreateDevice", "KeWaitForSingleObject", "MmMapIoSpace"]
    assert _has_strong_kernel_call_evidence(calls)


def test_strong_kernel_evidence_threshold_requires_three_distinct():
    """Two distinct kernel calls (with one repeated) -> not strong."""
    calls = ["IoCreateDevice", "IoCreateDevice", "KeWaitForSingleObject"]
    assert not _has_strong_kernel_call_evidence(calls)


def test_strong_kernel_evidence_handles_mixed_calls():
    """Mix of kernel and non-kernel calls; only kernel ones count."""
    calls = [
        "malloc",
        "free",
        "IoCreateDevice",
        "KeWaitForSingleObject",
        "ExAllocatePool2",
    ]
    assert _has_strong_kernel_call_evidence(calls)


def test_strong_kernel_evidence_empty_list():
    assert not _has_strong_kernel_call_evidence([])


def test_strong_kernel_evidence_no_kernel_calls():
    """Userland calls only -> evidence is not strong."""
    calls = ["malloc", "free", "strcpy", "printf", "memcpy"]
    assert not _has_strong_kernel_call_evidence(calls)


def test_strong_kernel_evidence_with_cldfs_prefixes():
    """Cloud Files / HSM / FLT prefixes count as kernel evidence."""
    calls = ["CldiOpen", "HsmpStreamRead", "FltSendMessage"]
    assert _has_strong_kernel_call_evidence(calls)


# ---------------------------------------------------------------------------
# build_naming_prompt integration -- strings + body scrub
# ---------------------------------------------------------------------------


def _ctx() -> MemoryContext:
    """Build a MemoryContext that forces the fallback (no-decompile) path.

    With ``file_path`` pointing at a non-existent file, ``g.ir.decompile_at``
    raises and the helper falls back to the strings + calls + instructions
    branch -- which is the branch we want to exercise for strings tests.
    """
    return MemoryContext(
        file_path="/nonexistent",
        artifact=MagicMock(),
        budgets=Budgets(timeout_ms=100),
    )


def test_prompt_with_strong_kernel_evidence_drops_all_strings():
    """3+ kernel calls => strings list dropped entirely from the prompt."""
    ctx = _ctx()
    prompt = build_naming_prompt(
        ctx=ctx,
        va=None,
        original_name="sub_140035718",
        demangled_name=None,
        instructions=[],
        calls=["IoCreateDevice", "KeWaitForSingleObject", "MmMapIoSpace"],
        strings=["legitimate_user_string", "another_user_string"],
    )
    # Strings header must not appear when strings are dropped.
    assert "Strings:" not in prompt
    # But the calls must still be visible.
    assert "IoCreateDevice" in prompt


def test_prompt_with_two_kernel_calls_keeps_filtered_strings():
    """2 kernel calls (below threshold) => strings list filtered but kept."""
    ctx = _ctx()
    prompt = build_naming_prompt(
        ctx=ctx,
        va=None,
        original_name="sub_140035718",
        demangled_name=None,
        instructions=[],
        calls=["IoCreateDevice", "KeWaitForSingleObject"],
        strings=[
            "!This program cannot be run in DOS mode.",
            ".text",
            "legitimate_user_string",
        ],
    )
    # Boilerplate must be stripped.
    assert "This program cannot be run in DOS mode" not in prompt
    assert "'.text'" not in prompt
    assert '".text"' not in prompt
    # Real user string must survive.
    assert "legitimate_user_string" in prompt


def test_prompt_with_no_kernel_calls_strips_only_boilerplate():
    """No kernel calls => filter applied, real strings retained."""
    ctx = _ctx()
    prompt = build_naming_prompt(
        ctx=ctx,
        va=None,
        original_name="sub_1234",
        demangled_name=None,
        instructions=[],
        calls=["printf", "malloc"],
        strings=[
            "!This program cannot be run in DOS mode.",
            "wil_details_FeatureReporting_RecordUsage",
            "real_user_string",
        ],
    )
    assert "This program cannot be run in DOS mode" not in prompt
    assert "wil_details_" not in prompt
    assert "real_user_string" in prompt


# ---------------------------------------------------------------------------
# _strip_pe_boilerplate_lines -- pseudocode body scrub
# ---------------------------------------------------------------------------


def test_strip_lines_preserves_first_occurrence_drops_repeats():
    """The line filter preserves the first instance of each boilerplate
    token but drops subsequent quoting lines."""
    body = "\n".join(
        [
            "fn sub_140035718 {",
            '    arg2 = "!This program cannot be run in DOS mode.";',
            "    var0 = call(arg2);",
            '    arg3 = "!This program cannot be run in DOS mode.";',
            '    arg4 = ".text";',
            '    arg5 = ".text";',
            "    return var0;",
            "}",
        ]
    )
    out = _strip_pe_boilerplate_lines(body)
    out_lines = out.splitlines()
    # First occurrence of each boilerplate token kept.
    assert sum("This program cannot be run in DOS mode" in line for line in out_lines) == 1
    assert sum('".text"' in line for line in out_lines) == 1
    # Non-boilerplate lines survive.
    assert any("return var0" in line for line in out_lines)
    assert any("call(arg2)" in line for line in out_lines)


def test_strip_lines_empty_input():
    assert _strip_pe_boilerplate_lines("") == ""


def test_strip_lines_no_boilerplate_passes_through():
    body = "fn foo {\n    return 0;\n}"
    assert _strip_pe_boilerplate_lines(body) == body


# ---------------------------------------------------------------------------
# build_naming_prompt integration with pseudocode containing boilerplate
# ---------------------------------------------------------------------------


def test_prompt_with_fake_pseudocode_strips_section_quotes():
    """When the decompiler returns a body that quotes ``.text`` and
    ``.rdata`` multiple times, only the first instance reaches the prompt.

    We monkey-patch ``g.ir.decompile_at`` so this test is independent of
    samples and target architecture.
    """
    from glaurung.llm.tools import suggest_function_name as mod

    fake_body = "\n".join(
        [
            "fn sub_140035718 {",
            '    arg2 = ".text";',
            '    arg3 = ".text";',
            '    arg4 = ".rdata";',
            '    arg5 = ".rdata";',
            '    arg6 = ".rdata";',
            "    return arg2;",
            "}",
        ]
    )

    class _FakeIR:
        @staticmethod
        def decompile_at(file_path, va, timeout_ms, style):  # noqa: ANN001
            return fake_body

    real_ir = mod.g.ir
    mod.g.ir = _FakeIR  # type: ignore[attr-defined]
    try:
        ctx = MemoryContext(
            file_path="/nonexistent",
            artifact=MagicMock(),
            budgets=Budgets(timeout_ms=100),
        )
        prompt = build_naming_prompt(
            ctx=ctx,
            va=0x140035718,
            original_name="sub_140035718",
            demangled_name=None,
            instructions=[],
            calls=[],
            strings=[],
        )
    finally:
        mod.g.ir = real_ir  # type: ignore[attr-defined]

    # The pseudocode fence must be present (decompile succeeded).
    assert "glaurung --style c" in prompt
    # Section-name quotes must each appear at most once in the body.
    assert prompt.count('".text"') <= 1
    assert prompt.count('".rdata"') <= 1
    # And at least the first instance is preserved.
    assert '".text"' in prompt
    assert '".rdata"' in prompt
