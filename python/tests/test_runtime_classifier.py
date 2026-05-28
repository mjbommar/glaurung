"""Tests for D3: classify mingw/msvcrt/libgcc runtime helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from glaurung.llm.runtime_classifier import (
    application_functions,
    classify_function,
    is_runtime,
    partition_functions,
)


# ---- known mingw / msvcrt / libgcc helpers ----

@pytest.mark.parametrize("name", [
    "__pei386_runtime_relocator",
    "_pei386_runtime_relocator",
    "__mingw_invalidParameterHandler",
    "__mingw_printf",
    "__gcc_register_frame",
    "__gcc_deregister_frame",
    "__tmainCRTStartup",
    "WinMainCRTStartup",
    "mainCRTStartup",
    "atexit",
    "_initterm",
    "__main",
    "__C_specific_handler",
    "__chkstk",
    "_Unwind_Resume",
    "__cxa_throw",
])
def test_classify_runtime_helpers(name):
    assert classify_function(name) == "runtime_helper", (
        f"{name} should be runtime_helper, got {classify_function(name)}"
    )


# ---- import stubs ----

@pytest.mark.parametrize("name", [
    "__imp_strcpy",
    "__imp_KERNEL32.dll!CreateFileA",
    "__imp__malloc",
])
def test_classify_import_stubs(name):
    assert classify_function(name) == "library_import_stub"


# ---- application code ----

@pytest.mark.parametrize("name", [
    "main",
    "vuln",
    "secret_win",
    "build_source_path",
    "dispatch_to_console",
    "parse_packet_array",
    "session_create",
    "Cwe476DeviceControl",
    "DriverEntry",
    "VulnTouch",
])
def test_classify_application_code(name):
    assert classify_function(name) == "application", (
        f"{name} should be application, got {classify_function(name)}"
    )


# ---- unknown sub_<va> fallback ----

def test_classify_sub_unknown():
    assert classify_function("sub_140001480") == "unknown"
    assert classify_function("sub_deadbeef") == "unknown"


# ---- section-locality shortcut ----

def test_classify_crt_section_forces_runtime():
    assert classify_function("foo", section=".CRT$XCA") == "runtime_helper"
    assert classify_function("anything_at_all", section=".tls$AAA") == "runtime_helper"


def test_classify_section_text_doesnt_override_app_check():
    # .text section is the default for app code; section shouldn't change the
    # classification when name is plainly user code.
    assert classify_function("main", section=".text") == "application"


# ---- is_runtime convenience ----

def test_is_runtime_covers_both_runtime_and_stub():
    assert is_runtime("__mingw_printf") is True
    assert is_runtime("__imp_strcpy") is True
    assert is_runtime("main") is False
    assert is_runtime("sub_140001480") is False  # unknown is not runtime


# ---- partition_functions / application_functions ----

def _fn(name: str, va: int = 0):
    return SimpleNamespace(name=name, entry_point=SimpleNamespace(value=va))


def test_partition_separates_each_class():
    fns = [
        _fn("main"),
        _fn("vuln"),
        _fn("__mingw_printf"),
        _fn("__imp_strcpy"),
        _fn("sub_140001000"),
    ]
    p = partition_functions(fns)
    app_names = {f.name for f in p["application"]}
    rt_names = {f.name for f in p["runtime_helper"]}
    stub_names = {f.name for f in p["library_import_stub"]}
    unk_names = {f.name for f in p["unknown"]}
    assert app_names == {"main", "vuln"}
    assert rt_names == {"__mingw_printf"}
    assert stub_names == {"__imp_strcpy"}
    assert unk_names == {"sub_140001000"}


def test_application_functions_keeps_unknown_sub_names():
    """Stripped binaries surface real user code as sub_<va>. The default
    LLM-visible filter must KEEP these (otherwise we exclude all user code
    on a stripped binary)."""
    fns = [
        _fn("__mingw_printf"),
        _fn("main"),
        _fn("sub_140001100"),  # likely user code in a stripped build
    ]
    kept = application_functions(fns)
    kept_names = {f.name for f in kept}
    assert kept_names == {"main", "sub_140001100"}
    assert "__mingw_printf" not in kept_names
