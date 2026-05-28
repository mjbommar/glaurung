"""Classify discovered functions as application code vs. compiler runtime.

The v2 corpus discovery sub-agent twice latched onto compiler runtime
helpers (``__pei386_runtime_relocator`` from mingw's pseudo-relocation
runtime; the ``vfprintf`` width-parser inside msvcrt) as "the bug in the
application". They aren't application code; they're shipped-with-toolchain
helpers that almost every C binary contains. This classifier tags such
functions during analysis so the LLM agent and the rule sweeper can
exclude them from their default "interesting functions" view.

Two signal sources, combined in :func:`classify_function`:

1. Name allowlists / patterns. mingw + msvcrt + libgcc helpers have
   distinctive names (``__pei386_*``, ``_initterm``, ``__mingw_*``,
   ``__gcc_register_frame``, ``__c_specific_handler``, …). The patterns
   below cover the families our v2 corpus exposes; extend on demand.

2. Import-stub structure. PE import-table thunks (``__imp_*`` /
   short trampolines that jmp [IAT]) are best ignored regardless of name.

Result is one of:

* ``application`` -- our default target for vuln discovery.
* ``runtime_helper`` -- skip unless ``--include-runtime``.
* ``library_import_stub`` -- skip; trivial trampolines.
* ``unknown`` -- treat as application (default-include).
"""

from __future__ import annotations

import re
from typing import Iterable, Literal


FunctionClass = Literal[
    "application", "runtime_helper", "library_import_stub", "unknown",
]


# Exact-name set: mingw / msvcrt / libgcc helpers we never want to flag.
# Sourced from inspection of v1/v2 corpus + standard mingw runtime.
_RUNTIME_HELPER_EXACT: frozenset[str] = frozenset({
    # mingw / win-CRT startup
    "_amsg_exit", "_cexit", "_commode", "_initterm", "_fmode",
    "__getmainargs", "__initenv", "__iob_func", "__set_app_type",
    "__setusermatherr", "__C_specific_handler",
    "__tmainCRTStartup", "mainCRTStartup", "WinMainCRTStartup",
    "atexit", "_atexit", "__main",
    # mingw pseudo-relocation runtime + register/deregister hooks
    "__gcc_register_frame", "__gcc_deregister_frame",
    "_pei386_runtime_relocator", "__pei386_runtime_relocator",
    # invalid-parameter handler / locale shims
    "__mingw_invalidParameterHandler",
    "___lc_codepage_func", "___mb_cur_max_func",
    # SEH / vectored handlers
    "SetUnhandledExceptionFilter",
})


# Prefix patterns: anything starting with these is a runtime helper.
# Anchored with re for clarity even though startswith would suffice.
_RUNTIME_HELPER_PREFIXES: tuple[str, ...] = (
    "__mingw_",
    "__pei386_",
    "_pei386_",
    "__gcc_",
    "__cxa_",          # libstdc++ exception ABI
    "_Unwind_",        # libgcc unwinder
    "__udivti3", "__umodti3", "__divti3", "__modti3",  # libgcc soft-divide
    "_setargv", "_matherr", "__C_specific_handler",
    "__chkstk",        # stack-probe helper
)


# Substring patterns inside symbol names. Used sparingly to avoid
# misclassifying user code that happens to share a prefix.
_RUNTIME_HELPER_SUBSTRS: tuple[str, ...] = (
    "_RTC_",           # MSVC runtime checks
    "_security_check_cookie",
    "__report_gsfailure",
)


_IMPORT_STUB_PREFIXES: tuple[str, ...] = (
    "__imp_",          # MSVC import-table direct reference
    "__imp__",
)


def classify_function(
    name: str,
    *,
    section: str | None = None,
) -> FunctionClass:
    """Classify a single function name.

    ``section`` is the section the function lives in (``.text``,
    ``.crt$XCA``, etc.) -- when supplied, ``.crt$``, ``.tls$``, ``.rdata``,
    and other non-text sections force ``runtime_helper`` regardless of
    name. Pass ``None`` if the section is unknown.
    """
    if not name:
        return "unknown"

    # 0. Section-locality shortcut.
    if section is not None:
        sec = section.lower()
        if sec.startswith(".crt$") or sec.startswith(".tls$"):
            return "runtime_helper"

    # 1. Import-table stubs.
    for prefix in _IMPORT_STUB_PREFIXES:
        if name.startswith(prefix):
            return "library_import_stub"

    # 2. Exact runtime-helper names.
    if name in _RUNTIME_HELPER_EXACT:
        return "runtime_helper"

    # 3. Prefix patterns.
    for prefix in _RUNTIME_HELPER_PREFIXES:
        if name.startswith(prefix):
            return "runtime_helper"

    # 4. Substring patterns.
    for substr in _RUNTIME_HELPER_SUBSTRS:
        if substr in name:
            return "runtime_helper"

    # 5. The disassembler's auto-generated 'sub_<hex>' fallback names are
    #    not by themselves diagnostic -- but a strict heuristic: if the
    #    function name is exactly 'sub_<hex>', it's at least 'unknown'.
    if re.match(r"^sub_[0-9a-fA-F]+$", name):
        return "unknown"
    # Functions named '.text' / '.bss' / etc. are section labels, not real fns
    if name.startswith("."):
        return "runtime_helper"

    return "application"


def is_runtime(name: str, *, section: str | None = None) -> bool:
    """Convenience: True if name is a runtime helper or import stub."""
    return classify_function(name, section=section) in (
        "runtime_helper",
        "library_import_stub",
    )


def partition_functions(
    functions: Iterable,
) -> dict[FunctionClass, list]:
    """Split discovered functions by class.

    ``functions`` items must expose ``.name`` (str). Section attribute
    is optional; if present, used in classification.
    """
    out: dict[FunctionClass, list] = {
        "application": [],
        "runtime_helper": [],
        "library_import_stub": [],
        "unknown": [],
    }
    for fn in functions:
        section = getattr(fn, "section", None)
        cls = classify_function(fn.name, section=section)
        out[cls].append(fn)
    return out


def application_functions(functions: Iterable) -> list:
    """Filter helper: return only application functions (the default
    LLM-visible set). Unknown sub_<va> names are KEPT here, since
    stripped binaries surface real user code as sub_<va>.
    """
    out = []
    for fn in functions:
        cls = classify_function(fn.name, section=getattr(fn, "section", None))
        if cls in ("application", "unknown"):
            out.append(fn)
    return out
