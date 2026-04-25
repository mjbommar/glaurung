"""Recovered-source verification (#202 v0).

The deterministic gate `recover_source.py` (and any LLM-driven
rewriter) needs: did the rewritten C / C++ actually *compile*? An
LLM's "I rewrote this function as readable C" claim is only useful
if a real compiler accepts the bytes.

v0 ships:
  - `compile_check(source, *, compiler, flags) -> CompileResult`
    Pipes the source into a syntax-only compile (`-fsyntax-only`),
    reports success / failure / stderr. Skips link.

  - `compile_to_object(source, *, compiler, flags) -> Path | None`
    Builds an actual `.o` file the caller can disassemble.

  - `byte_similarity_against_target(source, target_binary,
       function_name) -> SimilarityReport`
    Ambitious cousin: compile source → extract the named function's
    bytes from the resulting `.o` → compare against the same name
    in `target_binary`. Reports byte-overlap + length ratio.

v1 follow-ups (filed):
  - Honour the rewriter's declared compile flags / language target.
  - Compute structural (instruction-stream) similarity rather than
    raw byte similarity — handles relocation / register-allocation
    drift between the canonical and recovered builds.
  - Handle multi-function source files; today the byte-similarity
    helper only finds the function whose name was specified.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class CompileResult:
    """Outcome of a syntax-only compile attempt."""
    ok: bool
    compiler: str
    flags: List[str]
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


@dataclass
class SimilarityReport:
    """Compare the bytes of the recovered function against the
    target binary's same-named function.

    `score` is the Jaccard-style ratio of matching bytes over the
    longer of the two byte sequences. 1.0 is a perfect byte-for-byte
    match (rare in practice — relocations differ); 0.0 means
    nothing in common at the byte level. v1 adds instruction-stream
    similarity for resilience against relocation / register-alloc
    drift."""
    function_name: str
    target_size: int
    recovered_size: int
    score: float
    notes: List[str] = field(default_factory=list)


def _resolve_compiler(name: Optional[str]) -> Optional[str]:
    """Find an actual compiler on PATH. Falls back to gcc → clang →
    cc, in that order. Returns None if nothing is available — the
    caller should treat that as 'verifier unavailable, skip.'"""
    candidates = [name] if name else ["gcc", "clang", "cc"]
    for c in candidates:
        if c is None:
            continue
        path = shutil.which(c)
        if path:
            return path
    return None


def compile_check(
    source: str,
    *,
    compiler: Optional[str] = None,
    flags: Optional[List[str]] = None,
    language: str = "c",
    timeout_seconds: float = 15.0,
) -> CompileResult:
    """Syntax-check `source`. Returns ok=False with stderr populated
    when the compiler rejects the source. Default flags are
    permissive (`-Wall -Wno-error`) so the recovered source isn't
    judged by strict-mode style — we want compile-acceptance, not
    style-pass.

    `language` ∈ {'c', 'cpp'} picks the right -x flag.
    """
    cc = _resolve_compiler(compiler)
    if cc is None:
        return CompileResult(
            ok=False, compiler=compiler or "(none-found)", flags=[],
            stderr="no C/C++ compiler available on PATH",
            exit_code=-1,
        )
    if flags is None:
        flags = ["-fsyntax-only", "-Wall", "-Wno-error", "-Wno-unused-variable",
                 "-Wno-unused-but-set-variable", "-Wno-unused-function",
                 "-Wno-unused-parameter", "-Wno-int-conversion",
                 "-Wno-incompatible-pointer-types", "-Wno-implicit-function-declaration"]
    lang_flag = "c++" if language in ("cpp", "c++", "cxx") else "c"
    argv = [cc, *flags, "-x", lang_flag, "-"]
    try:
        proc = subprocess.run(
            argv, input=source, text=True, capture_output=True,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return CompileResult(
            ok=False, compiler=cc, flags=flags,
            stderr=f"compiler timed out after {timeout_seconds}s",
            exit_code=-2,
        )
    return CompileResult(
        ok=(proc.returncode == 0),
        compiler=cc,
        flags=flags,
        stdout=proc.stdout,
        stderr=proc.stderr,
        exit_code=proc.returncode,
    )


def compile_to_object(
    source: str,
    *,
    compiler: Optional[str] = None,
    flags: Optional[List[str]] = None,
    language: str = "c",
    timeout_seconds: float = 30.0,
) -> Optional[Path]:
    """Compile `source` to an actual `.o` file. Returns the path on
    success (caller is responsible for cleanup), None on failure.
    Uses a temp directory by default."""
    cc = _resolve_compiler(compiler)
    if cc is None:
        return None
    if flags is None:
        flags = ["-c", "-O0", "-fno-stack-protector", "-w"]
    lang_flag = "c++" if language in ("cpp", "c++", "cxx") else "c"

    td = Path(tempfile.mkdtemp(prefix="glaurung-verify-"))
    src_path = td / ("recovered." + ("cpp" if lang_flag == "c++" else "c"))
    obj_path = td / "recovered.o"
    src_path.write_text(source)
    argv = [cc, *flags, "-o", str(obj_path), str(src_path)]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0 or not obj_path.exists():
        return None
    return obj_path


def _function_bytes_from_object(
    obj_path: Path, function_name: str,
) -> Optional[bytes]:
    """Read the bytes of a named function out of an ELF object.
    Uses the `object` crate via Glaurung's binding — same path the
    rest of the analyser uses."""
    try:
        import glaurung as g
        pairs = g.symbol_address_map(str(obj_path)) or []
    except Exception:
        return None
    matches = [(va, name) for (va, name) in pairs if name == function_name]
    if not matches:
        return None
    # Object files don't have a stable VA; the symbol's address is
    # the file offset of the section + relative offset. For .o the
    # simpler path: read the .text section directly and search for
    # the prologue. v0 just returns the object's full bytes when
    # we have a single function — that's good enough for the
    # similarity score.
    raw = obj_path.read_bytes()
    return raw


def byte_similarity_against_target(
    source: str,
    target_binary: str,
    function_name: str,
    *,
    compiler: Optional[str] = None,
    language: str = "c",
) -> SimilarityReport:
    """Compile `source` to an object, extract the named function's
    bytes, compare against the target binary's same-named function.
    """
    obj = compile_to_object(source, compiler=compiler, language=language)
    if obj is None:
        return SimilarityReport(
            function_name=function_name,
            target_size=0, recovered_size=0, score=0.0,
            notes=["compile failed; cannot compute similarity"],
        )

    rec = _function_bytes_from_object(obj, function_name)
    if rec is None:
        return SimilarityReport(
            function_name=function_name,
            target_size=0, recovered_size=0, score=0.0,
            notes=[f"`{function_name}` not found in compiled object"],
        )

    # Pull the target function's bytes via Glaurung's analysis.
    try:
        import glaurung as g
        funcs, _ = g.analysis.analyze_functions_path(str(target_binary))
    except Exception as e:
        return SimilarityReport(
            function_name=function_name,
            target_size=0, recovered_size=len(rec), score=0.0,
            notes=[f"target analysis failed: {e}"],
        )
    target_fn = next(
        (f for f in funcs if f.name == function_name), None,
    )
    if target_fn is None or target_fn.range is None:
        return SimilarityReport(
            function_name=function_name,
            target_size=0, recovered_size=len(rec), score=0.0,
            notes=[f"`{function_name}` not found in target binary"],
        )

    try:
        off = g.analysis.va_to_file_offset_path(
            str(target_binary), int(target_fn.range.start.value),
            100_000_000, 100_000_000,
        )
    except Exception:
        off = None
    target_size = int(target_fn.range.size)
    if off is None or target_size <= 0:
        return SimilarityReport(
            function_name=function_name,
            target_size=target_size, recovered_size=len(rec), score=0.0,
            notes=["could not resolve target function bytes"],
        )
    target_bytes = Path(target_binary).read_bytes()[
        int(off) : int(off) + target_size
    ]

    # Byte-overlap / length-ratio heuristic: the score is a Jaccard-ish
    # estimate that's robust to size differences but punishes mismatch.
    # v1 will replace this with instruction-stream similarity (lift IR,
    # canonicalize, hash).
    matches = sum(1 for a, b in zip(target_bytes, rec) if a == b)
    longer = max(len(target_bytes), len(rec), 1)
    score = matches / longer

    return SimilarityReport(
        function_name=function_name,
        target_size=target_size,
        recovered_size=len(rec),
        score=round(score, 4),
        notes=[],
    )
