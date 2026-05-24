"""F4 unit tests for the Layer-0 pre-pass extractors.

These tests exercise the three regex-based input extractors that
``_layer0_prepass.run_layer0_prepass`` calls before dispatching to
Tools #5 / #3 / #2:

  - ``_extract_locals``    : var<N> / arg<N> / stack_<N> / t<N>
  - ``_extract_strings``   : double-quoted literals with PE boilerplate filter
  - ``_extract_constants`` : 0x-hex constants minus the trivial set

The extractors are pure functions of the pseudocode string; no
network / binary dependencies needed.
"""

from __future__ import annotations

import pytest

from glaurung.cli.commands._layer0_prepass import (
    Layer0Pair,
    Layer0Result,
    _extract_constants,
    _extract_locals,
    _extract_strings,
    _def_use_slice,
    _short_sha,
    _TRIVIAL_CONSTANTS,
)


# ---------------------------------------------------------------------------
# _extract_locals
# ---------------------------------------------------------------------------


def test_extract_locals_basic_lifter_output():
    pseudo = (
        "function sub_1c0067010 @ 0x1c0067010 {\n"
        "    store %stack_0 = %var0;\n"
        "    %var1 = %arg0;\n"
        "    call (%var1, %var0);\n"
        "    %var0 = %stack_1;\n"
        "    return;\n"
        "}\n"
    )
    got = _extract_locals(pseudo)
    # Distinct identifiers in encounter order.
    assert got == ["stack_0", "var0", "var1", "arg0", "stack_1"]


def test_extract_locals_handles_unprefixed_form():
    """Some renders strip the leading %; we must catch both."""
    pseudo = "if arg0 == 42 then var3 += 1; t7 = arg0 ^ var3"
    got = _extract_locals(pseudo)
    assert got == ["arg0", "var3", "t7"]


def test_extract_locals_dedupes_and_preserves_order():
    pseudo = "var0 var1 var0 arg0 var1 arg0 t9"
    got = _extract_locals(pseudo)
    assert got == ["var0", "var1", "arg0", "t9"]


def test_extract_locals_empty_input():
    assert _extract_locals("") == []
    assert _extract_locals("    ") == []


def test_extract_locals_ignores_non_local_words():
    # "argc"/"vararg" must not match var<digit>/arg<digit>.
    pseudo = "argc + vararg + variable + targets - sublabel"
    assert _extract_locals(pseudo) == []


# ---------------------------------------------------------------------------
# _extract_strings (with PE boilerplate filter)
# ---------------------------------------------------------------------------


def test_extract_strings_basic_path():
    pseudo = 'open("/etc/passwd", "r") + log("opened: %s", path)'
    got = _extract_strings(pseudo)
    assert "/etc/passwd" in got
    assert "r" not in got  # below the min-length threshold
    assert "opened: %s" in got


def test_extract_strings_filters_dos_stub():
    """The F1 boilerplate filter must strip the DOS stub etc."""
    pseudo = (
        'msg("!This program cannot be run in DOS mode.") + '
        'msg(".rdata") + log("real diagnostic: %s", path)'
    )
    got = _extract_strings(pseudo)
    # Boilerplate is dropped; the real diagnostic survives.
    assert "!This program cannot be run in DOS mode." not in got
    assert ".rdata" not in got
    assert "real diagnostic: %s" in got


def test_extract_strings_filters_wil_telemetry():
    pseudo = (
        'reg("wil_details_provider") + reg("Feature_Servicing_Enabled") + '
        'reg("CLDI_StreamHandler")'
    )
    got = _extract_strings(pseudo)
    assert all(not s.startswith("wil_details_") for s in got)
    assert all(not s.startswith("Feature_Servicing_") for s in got)
    # Non-boilerplate stays.
    assert "CLDI_StreamHandler" in got


def test_extract_strings_handles_no_strings():
    assert _extract_strings("int x = 0; return;") == []


# ---------------------------------------------------------------------------
# _extract_constants
# ---------------------------------------------------------------------------


def test_extract_constants_skips_trivial_set():
    pseudo = (
        "x = 0x0 + 0x1 + 0x4 + 0x8 + 0x10 + 0x40 + 0x100 + 0x1000 + 0x4002"
    )
    got = _extract_constants(pseudo)
    # Only 0x4002 survives -- everything else is in _TRIVIAL_CONSTANTS.
    assert got == [0x4002]


def test_extract_constants_keeps_unusual_values():
    pseudo = (
        "if value == 0xdeadbeef then ret = 0xCAFEBABE else ret = 0x80000003"
    )
    got = _extract_constants(pseudo)
    assert 0xDEADBEEF in got
    assert 0xCAFEBABE in got
    assert 0x80000003 in got


def test_extract_constants_dedupes_in_order():
    pseudo = "a = 0xdead b = 0xdead c = 0xbeef d = 0xdead e = 0xbeef"
    got = _extract_constants(pseudo)
    assert got == [0xDEAD, 0xBEEF]


def test_extract_constants_trivial_set_membership():
    """The trivial set explicitly covers 0/1/-1/4/8/16/64/256/0x1000."""
    for trivial in (0, 1, -1, 4, 8, 16, 64, 256, 0x1000):
        assert trivial in _TRIVIAL_CONSTANTS, (
            f"{trivial} (0x{trivial:x}) must be in _TRIVIAL_CONSTANTS"
        )


def test_extract_constants_empty_input():
    assert _extract_constants("") == []


# ---------------------------------------------------------------------------
# _def_use_slice -- per-variable pseudocode slice for Tool #5
# ---------------------------------------------------------------------------


def test_def_use_slice_returns_lines_with_match():
    pseudo = (
        "line one\n"
        "    %var3 = arg0;\n"
        "    %var0 = something;\n"
        "    if %var3 > 0 then;\n"
        "    return %var0;\n"
    )
    got = _def_use_slice(pseudo, "var3")
    assert any("var3" in line for line in got)
    # Slice doesn't include lines that don't mention var3.
    assert all("var3" in line for line in got)


def test_def_use_slice_respects_max_lines():
    pseudo = "\n".join(f"%var0 = {i};" for i in range(20))
    got = _def_use_slice(pseudo, "var0", max_lines=5)
    assert len(got) == 5


def test_def_use_slice_empty_when_id_missing():
    assert _def_use_slice("nothing here", "var0") == []


# ---------------------------------------------------------------------------
# Layer0Pair / Layer0Result shape
# ---------------------------------------------------------------------------


def test_layer0_pair_to_dict_round_trip():
    p = Layer0Pair(
        input="var0",
        output="path_len",
        source="llm",
        confidence=0.82,
        rationale="compared to strlen result",
    )
    d = p.to_dict()
    assert d == {
        "input": "var0",
        "output": "path_len",
        "source": "llm",
        "confidence": 0.82,
        "rationale": "compared to strlen result",
    }


def test_layer0_result_to_json_shape():
    r = Layer0Result(
        variable_names={"var0": "fd"},
        string_names={"/etc/passwd": "PASSWD_PATH"},
        constant_labels={"0x4002": "O_RDWR | O_DIRECT"},
        llm_calls=3,
        cache_hits=1,
    )
    r.variables_audit.append(
        Layer0Pair(
            input="var0", output="fd", source="llm",
            confidence=0.8, rationale="passed to read()",
        )
    )
    js = r.to_json()
    assert set(js.keys()) == {"variables", "strings", "constants", "stats"}
    assert js["stats"] == {
        "variables_resolved": 1,
        "strings_resolved": 1,
        "constants_resolved": 1,
        "llm_calls": 3,
        "cache_hits": 1,
    }
    assert js["variables"][0]["output"] == "fd"


def test_short_sha_stable_and_short():
    assert _short_sha("foo") == _short_sha("foo")  # determinism
    assert _short_sha("foo") != _short_sha("bar")
    assert len(_short_sha("anything")) == 12
