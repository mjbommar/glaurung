"""Tool: identify the compiler, language, and runtime of a binary.

Reverse engineers reach for this early — compiler/runtime shape most
other decisions (which ABI rules to apply, whether panics unwind via
Rust or longjmp via C, whether main is called from glibc's
``__libc_start_main`` or from a Go runtime loader).

We use three signal sources, cheapest first:

1. Raw file scan for well-known markers (``GCC:``, ``clang version``,
   ``rustc``, ``go build``) — usually parked in a ``.comment`` or
   ``.rdata`` section and persists even in "stripped" binaries.
2. Imported/dynamic symbols — ``__libc_start_main`` → C + glibc,
   ``_ZSt`` mangled names → libstdc++, ``rust_panic`` / ``core::`` →
   Rust, ``runtime.goexit`` → Go.
3. Triage verdict (format/arch/bits) for the descriptive headline.

Reporting confidence is tiered: HIGH if a direct compiler-version
marker was recovered, MEDIUM if multiple indirect symbols agree, LOW
if we're guessing from a single weak signal.
"""

from __future__ import annotations

import re
from typing import List, Optional

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


_COMPILER_PATTERNS = [
    # (regex, compiler_family)
    (re.compile(rb"GCC:[^\x00\n]{0,120}"), "gcc"),
    (re.compile(rb"clang version [^\x00\n]{0,80}"), "clang"),
    (re.compile(rb"Rust (?:version )?\d+\.\d+\.\d+[^\x00\n]{0,60}"), "rustc"),
    (re.compile(rb"rustc version [^\x00\n]{0,60}"), "rustc"),
    (re.compile(rb"Go build ID:[^\x00\n]{0,80}"), "go"),
    (re.compile(rb"Go buildinf[^\x00]{0,40}"), "go"),
    (re.compile(rb"Microsoft \(R\) [^\x00\n]{0,120}"), "msvc"),
    (re.compile(rb"TCC [\d.]+[^\x00\n]{0,40}"), "tcc"),
]

_LIBC_PATTERNS = [
    (re.compile(rb"GLIBC_\d+(?:\.\d+)+"), "glibc"),
    (re.compile(rb"musl libc"), "musl"),
    (re.compile(rb"uClibc-ng "), "uclibc"),
    (re.compile(rb"BIONIC_[^\x00]{0,30}"), "bionic"),
    (re.compile(rb"msvcrt\.dll", re.IGNORECASE), "msvcrt"),
    (re.compile(rb"ucrtbase\.dll", re.IGNORECASE), "ucrt"),
]


class IdentifyCompilerArgs(BaseModel):
    max_scan_bytes: int | None = Field(
        None,
        description="Cap on bytes read from the file. Defaults to "
                    "ctx.budgets.max_read_bytes.",
    )


class IdentifyCompilerResult(BaseModel):
    format: Optional[str]
    arch: Optional[str]
    bits: Optional[int]
    compiler: Optional[str] = Field(
        None, description="Toolchain family: gcc / clang / rustc / go / msvc / tcc"
    )
    compiler_version: Optional[str] = None
    language: Optional[str] = Field(
        None, description="Dominant language: C / C++ / Rust / Go / Unknown"
    )
    libc: Optional[str] = Field(
        None, description="Libc flavour: glibc / musl / uclibc / bionic / ucrt / msvcrt"
    )
    glibc_versions: List[str] = Field(default_factory=list)
    stripped: Optional[bool] = None
    evidence: List[str] = Field(
        default_factory=list,
        description="Short list of the raw evidence strings or symbol names "
                    "that drove the classification.",
    )
    confidence: str = Field("LOW", description="HIGH / MEDIUM / LOW")


class IdentifyCompilerAndRuntimeTool(
    MemoryTool[IdentifyCompilerArgs, IdentifyCompilerResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="identify_compiler_and_runtime",
                description="Infer the compiler, language, and libc/runtime of "
                            "the target binary from markers and symbols. "
                            "Returns a confidence tier and the raw evidence.",
                tags=("triage", "identification"),
            ),
            IdentifyCompilerArgs,
            IdentifyCompilerResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: IdentifyCompilerArgs,
    ) -> IdentifyCompilerResult:
        fmt = arch = None
        bits = None
        try:
            v = ctx.artifact.verdicts[0]  # type: ignore[union-attr]
            fmt = str(v.format)
            arch = str(v.arch)
            bits = int(v.bits)
        except Exception:
            pass

        max_bytes = args.max_scan_bytes or ctx.budgets.max_read_bytes
        try:
            with open(ctx.file_path, "rb") as f:
                data = f.read(max_bytes)
        except FileNotFoundError:
            data = b""

        evidence: List[str] = []
        compiler: Optional[str] = None
        compiler_version: Optional[str] = None
        hits = 0

        for pat, family in _COMPILER_PATTERNS:
            m = pat.search(data)
            if m:
                compiler = family
                compiler_version = m.group(0).decode("ascii", errors="ignore").strip()
                evidence.append(compiler_version)
                hits += 1
                break  # first direct match wins

        libc: Optional[str] = None
        glibc_versions: List[str] = []
        glibc_seen: set[str] = set()
        for pat, name in _LIBC_PATTERNS:
            for m in pat.finditer(data):
                tok = m.group(0).decode("ascii", errors="ignore")
                if name == "glibc" and tok not in glibc_seen:
                    glibc_seen.add(tok)
                    glibc_versions.append(tok)
                if libc is None:
                    libc = name
                    evidence.append(tok)
                    hits += 1

        # Pull symbols for language/runtime inference.
        imports: List[str] = []
        exports: List[str] = []
        stripped: Optional[bool] = None
        try:
            summ = g.symbols.list_symbols_demangled(
                ctx.file_path,
                ctx.budgets.max_read_bytes,
                ctx.budgets.max_file_size,
            )
            imports = list(summ.import_names or []) + list(
                summ.demangled_import_names or []
            )
            exports = list(summ.export_names or []) + list(
                summ.demangled_export_names or []
            )
            stripped = bool(summ.stripped)
        except Exception:
            pass

        all_syms = imports + exports
        language: Optional[str] = None
        # Fortran: libgfortran symbols (`_gfortran_*`) are unambiguous —
        # they only ever come from gfortran-compiled code. Checked first
        # because gfortran-compiled binaries also carry the `GCC:` marker
        # and the `__libc_start_main` symbol, so any later branch would
        # mis-classify them.
        if any(s.startswith("_gfortran_") for s in all_syms):
            language = "Fortran"
            compiler = "gfortran"
            hits += 1
        elif any("rust_panic" in s or s.startswith("_ZN4core") for s in all_syms):
            language = "Rust"
            compiler = compiler or "rustc"
            hits += 1
        elif any(s.startswith("runtime.") or s == "runtime.goexit" for s in all_syms):
            language = "Go"
            compiler = compiler or "go"
            hits += 1
        elif any(s.startswith("_ZSt") or s.startswith("_ZN") for s in all_syms):
            language = "C++"
            hits += 1
        elif any("__libc_start_main" in s for s in all_syms):
            language = "C"
            hits += 1

        # Headline confidence.
        if compiler_version:
            confidence = "HIGH"
        elif hits >= 2:
            confidence = "MEDIUM"
        elif hits == 1:
            confidence = "LOW"
        else:
            confidence = "LOW"

        return IdentifyCompilerResult(
            format=fmt,
            arch=arch,
            bits=bits,
            compiler=compiler,
            compiler_version=compiler_version,
            language=language,
            libc=libc,
            glibc_versions=glibc_versions,
            stripped=stripped,
            evidence=evidence,
            confidence=confidence,
        )


def build_tool() -> MemoryTool[IdentifyCompilerArgs, IdentifyCompilerResult]:
    return IdentifyCompilerAndRuntimeTool()
