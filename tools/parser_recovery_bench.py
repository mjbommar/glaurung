#!/usr/bin/env python3
"""Measure C parser **error recovery** on real decompiler output.

The claim under test is DecBench's, verbatim: *"Joern is the only tool on the
planet to be able to recover a CFG from uncompilable C (very common in
decompilation)."* We are replacing Joern, so whether our C front end recovers
from broken input -- not whether it parses well-formed C -- is load-bearing.

Three parsers are measured, on identical inputs:

* **ours** -- ``glaurung._native.csource.parity_cfgs``
* **clang** -- ``libclang`` with ``PARSE_INCOMPLETE | KeepGoing``
* **tree-sitter** -- ``tree_sitter_c``

Joern's own parser (Eclipse CDT) is **not** measured -- it needs a JVM this
harness deliberately never starts. It appears in the report only as an
*inferred* column derived from DecBench's own ``sanitize_decompiled_c``, which
rewrites five constructs specifically because they break CDT. See
``docs/design/source-front-ends/error-recovery-comparison.md``.

The corpus is real decompiler output, never invented C:

* **ghidra** -- Ghidra 12.1.3 ``analyzeHeadless`` captures under
  ``$GLAURUNG_GHIDRA_OUT`` (default ``~/glaurung-ghidra/out``).
* **angr** -- angr's own decompiler run here, over the *same* binaries, cached
  as JSON. angr is one of DecBench's thirteen decompiler columns.

Damage classes 4-6 (truncation, interleaved garbage, structural breakage) are
applied programmatically, because no decompiler emits them on demand; every
edit is reproducible from ``--seed``.

Usage::

    export TMPDIR="$HOME/.cache/glaurung/tmp"
    # one-time (slow): run angr over the binaries and cache its output
    uv run python tools/parser_recovery_bench.py capture-angr

    # the measurement
    uv run --with clang --with tree_sitter --with tree_sitter_c \\
        python tools/parser_recovery_bench.py run --markdown out.md

``capture-angr`` shells out to ``uv run --no-project --with angr`` so angr is
never added to this project's dependency set.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Monotonic clock, named once so the runner's deadline arithmetic reads
#: the same way everywhere.
_now = time.monotonic

# --- paths ------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_GHIDRA_OUT = Path.home() / "glaurung-ghidra" / "out"
DEFAULT_BINARY_DIR = REPO_ROOT / "tests" / "decompiler_fixtures" / "build"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "glaurung" / "parser-recovery"
DEFAULT_DECBENCH_DIR = (
    Path.home() / ".cache" / "glaurung" / "decbench-full" / "decbench"
)

LIBCLANG_CANDIDATES = (
    "/usr/lib/llvm-21/lib/libclang.so",
    "/usr/lib/llvm-20/lib/libclang.so",
    "/usr/lib/x86_64-linux-gnu/libclang-21.so.1",
)

#: ``CXTranslationUnit_KeepGoing``. Not exposed as a constant by every
#: ``clang.cindex`` build, so it is spelled out rather than imported.
CLANG_KEEP_GOING = 0x200
#: ``CXTranslationUnit_Incomplete``.
CLANG_INCOMPLETE = 0x02
#: ``CXTranslationUnit_SingleFileParse`` is deliberately NOT set: it stops
#: clang building function bodies at all, which would answer a different
#: question than the one this harness asks.

# --- damage classes ---------------------------------------------------------

#: Ordered least to most broken. ``pristine`` is the control: real decompiler
#: output, byte for byte, with nothing done to it.
DAMAGE_CLASSES = (
    "1-pristine",
    "2-dialect",
    "3-gnu",
    "4-truncated",
    "5-garbage",
    "6-structural",
)


# --- corpus model -----------------------------------------------------------


@dataclass(frozen=True)
class FunctionUnit:
    """One function definition as some decompiler actually emitted it.

    Attributes:
        source: Producing decompiler, ``"ghidra"`` or ``"angr"``.
        binary: Stem of the binary it came from.
        name: Function name the decompiler gave it. This is ground truth: it
            is read from the producer, never re-derived by a parser under test.
        text: The definition, including any preamble the decompiler emitted
            with it (Ghidra's ``/* WARNING */`` comments, angr's typedefs and
            ``extern`` declarations).
    """

    source: str
    binary: str
    name: str
    text: str


@dataclass(frozen=True)
class Case:
    """One benchmark input: a translation unit plus its ground truth.

    Attributes:
        case_id: Stable identifier, unique within a run.
        pristine_id: ``case_id`` of the undamaged case this one derives from.
            Equal to ``case_id`` for class 1. Fidelity is measured against it.
        source: Producing decompiler of every unit in the case.
        damage_class: One of :data:`DAMAGE_CLASSES`.
        variant: Which operator inside the class produced this case.
        text: The translation unit handed to every parser.
        functions: Every function name the decompiler defined here.
        touched: The subset of ``functions`` the damage edited or destroyed.
            ``functions - touched`` is what a recovering parser must still
            return, and is the denominator of localization and fidelity.
    """

    case_id: str
    pristine_id: str
    source: str
    damage_class: str
    variant: str
    text: str
    functions: tuple[str, ...]
    touched: tuple[str, ...]

    @property
    def intact(self) -> tuple[str, ...]:
        """Function names the damage never touched."""
        touched = set(self.touched)
        return tuple(name for name in self.functions if name not in touched)


@dataclass(frozen=True)
class Recovered:
    """What one parser recovered for one function.

    Attributes:
        body_size: Number of body elements the parser produced. Zero means a
            definition with an empty body, which does not count as recovered.
        signature: A structural fingerprint of the body, in that parser's own
            vocabulary. Only ever compared to another signature from the *same*
            parser, so the three need not agree on what a node is.
        error_free: Whether the parser itself reported no error inside this
            function. The three parsers signal errors differently; see the
            per-parser docstrings, and the caveat in the report.
    """

    body_size: int
    signature: str
    error_free: bool


@dataclass
class ParseOutcome:
    """The result of running one parser over one case.

    Attributes:
        functions: Recovered functions by name.
        status: ``"ok"``, ``"timeout"``, or ``"crash"``.
        detail: Exception text when ``status`` is not ``"ok"``.
    """

    functions: dict[str, Recovered] = field(default_factory=dict)
    status: str = "ok"
    detail: str = ""


# --- corpus: Ghidra ---------------------------------------------------------


def _strip_c_noncode(text: str) -> str:
    """Blank out comments and literal interiors, preserving offsets and lines.

    Brace and paren scanning must not be fooled by a ``"}"`` inside a string or
    a ``/* { */`` in one of Ghidra's warning comments. Offsets are preserved so
    a match on the masked text indexes straight into the original.

    Args:
        text: Arbitrary C-like text.

    Returns:
        Text of identical length with comment and literal bytes replaced by
        spaces (newlines kept, so line numbers still line up).
    """
    out = list(text)
    state = "code"
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        nxt = text[index + 1] if index + 1 < length else ""
        if state == "code":
            if char == "/" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and nxt == "*":
                out[index] = out[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char in ('"', "'"):
                out[index] = " "
                state = "string" if char == '"' else "char"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                out[index] = " "
        else:
            if char == "\\" and nxt:
                out[index] = out[index + 1] = " "
                index += 2
                continue
            out[index] = " " if char != "\n" else "\n"
            if (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        index += 1
    return "".join(out)


def _declarator_name(header: str) -> str | None:
    """The function name in a definition header, or ``None``.

    Reads the identifier immediately before the outermost ``(``. Handles
    Ghidra's pointer returns (``undefined8 * FUN_x(void)``) and its aggregate
    returns (``undefined1 [8] FUN_x(void)``), neither of which a naive
    "last word before the paren" rule gets right on its own.

    Args:
        header: Text between the previous definition and the body's ``{``.

    Returns:
        The declared name, or ``None`` when the header is not a definition.
    """
    masked = _strip_c_noncode(header)
    depth = 0
    open_index = -1
    for index, char in enumerate(masked):
        if char == "(":
            if depth == 0:
                open_index = index
                break
            depth += 1
    if open_index < 0:
        return None
    prefix = masked[:open_index].rstrip()
    end = len(prefix)
    start = end
    while start > 0 and (prefix[start - 1].isalnum() or prefix[start - 1] == "_"):
        start -= 1
    name = prefix[start:end]
    if not name or name[0].isdigit():
        return None
    return name


def definition_name(text: str) -> str | None:
    """The name declared by the function definition inside ``text``.

    Used for angr, whose ``Function.name`` is the **mangled** ELF symbol
    (``_ZN18_166_rust_generics11max_genericE...``) while its codegen writes the
    *demangled* one (``_166_rust_generics::max_generic``). Taking ground truth
    from the producer's symbol table would then score every parser zero on a
    function all three recovered perfectly, so ground truth comes from the text
    the parsers are actually given.

    Both decompilers put the body's ``{`` alone on its own line, which is what
    separates a definition header from angr's ``typedef struct ... {`` preamble.

    Args:
        text: One function's emitted C, preamble included.

    Returns:
        The declared name, or ``None`` when no definition is found.
    """
    masked_lines = _strip_c_noncode(text).splitlines(keepends=True)
    lines = text.splitlines(keepends=True)
    offset = 0
    for index, line in enumerate(lines):
        if masked_lines[index].rstrip("\n") == "{":
            return _declarator_name(text[:offset])
        offset += len(line)
    return None


def normalized_name(name: str) -> str:
    """A function name reduced to the part every tool agrees on.

    Ghidra and angr both print C++/Rust *qualified* names into C output
    (``std::sys::unix::args::imp::ARGV_INIT_ARRAY::init_wrapper``). A parser
    that keeps the qualification and one that keeps only the last component
    have both recovered the same function, so the comparison is made on the
    last component. Nothing else is touched -- this is not a demangler.

    Args:
        name: A function name from any side of the comparison.

    Returns:
        The text after the last ``::``, or ``name`` unchanged.
    """
    return name.rsplit("::", 1)[-1]


def slice_ghidra_functions(
    text: str, *, source: str, binary: str
) -> list[FunctionUnit]:
    """Split one Ghidra ``analyzeHeadless`` capture into function definitions.

    Ghidra's C exporter is line-regular: any preceding ``/* WARNING */``
    comments, then a header line, a blank line, ``{`` alone in column zero, the
    body, and ``}`` alone in column zero. This reads that shape directly rather
    than parsing, so ground truth never comes from a parser under test.

    Args:
        text: Whole capture file.
        source: Producing decompiler label, recorded on each unit.
        binary: Binary stem, recorded on each unit.

    Returns:
        Every definition found, in file order. A header whose name cannot be
        read is skipped rather than guessed at.
    """
    masked = _strip_c_noncode(text)
    lines = text.splitlines(keepends=True)
    masked_lines = masked.splitlines(keepends=True)
    offsets: list[int] = []
    running = 0
    for line in lines:
        offsets.append(running)
        running += len(line)

    units: list[FunctionUnit] = []
    previous_end = 0
    index = 0
    while index < len(lines):
        if masked_lines[index].rstrip("\n") != "{":
            index += 1
            continue
        depth = 0
        close_line = -1
        for scan in range(index, len(lines)):
            depth += masked_lines[scan].count("{") - masked_lines[scan].count("}")
            if depth == 0:
                close_line = scan
                break
        if close_line < 0:
            break
        header = text[previous_end : offsets[index]]
        name = _declarator_name(header)
        if name is not None:
            body_end = offsets[close_line] + len(lines[close_line])
            units.append(
                FunctionUnit(
                    source=source,
                    binary=binary,
                    name=name,
                    text=text[previous_end:body_end].strip("\n") + "\n",
                )
            )
        previous_end = offsets[close_line] + len(lines[close_line])
        index = close_line + 1
    return units


def load_ghidra_units(ghidra_out: Path) -> list[FunctionUnit]:
    """Load every Ghidra capture under ``ghidra_out``.

    Args:
        ghidra_out: Directory of ``<binary stem>.c`` captures.

    Returns:
        Units sorted by ``(binary, name)`` so sampling is order-stable.

    Raises:
        FileNotFoundError: When the directory does not exist.
    """
    if not ghidra_out.is_dir():
        raise FileNotFoundError(f"no Ghidra captures at {ghidra_out}")
    units: list[FunctionUnit] = []
    for path in sorted(ghidra_out.glob("*.c")):
        text = path.read_text(encoding="utf-8", errors="replace")
        units.extend(slice_ghidra_functions(text, source="ghidra", binary=path.stem))
    units.sort(key=lambda unit: (unit.binary, unit.name))
    return units


# --- corpus: angr -----------------------------------------------------------

#: Run inside ``uv run --no-project --with angr``: it must not import glaurung,
#: this module, or anything else from the project environment.
_ANGR_CAPTURE_SCRIPT = r"""
import json, logging, sys, time
for name in ("angr", "cle", "pyvex", "claripy", "ailment"):
    logging.getLogger(name).setLevel(logging.CRITICAL)
import angr

out_path, per_binary, timeout_s = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
records = []
for binary in sys.argv[4:]:
    started = time.time()
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
    except Exception as exc:
        records.append({"binary": binary, "error": f"{type(exc).__name__}: {exc}"})
        continue
    kept = 0
    for func in sorted(proj.kb.functions.values(), key=lambda f: f.addr):
        if kept >= per_binary or time.time() - started > timeout_s:
            break
        if func.is_plt or func.is_simprocedure or func.is_alignment:
            continue
        try:
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        except Exception as exc:
            records.append({"binary": binary, "name": func.name,
                            "error": f"{type(exc).__name__}: {exc}"})
            continue
        codegen = getattr(dec, "codegen", None)
        text = getattr(codegen, "text", None) if codegen is not None else None
        if not text:
            records.append({"binary": binary, "name": func.name, "error": "no codegen text"})
            continue
        records.append({"binary": binary, "name": func.name, "text": text})
        kept += 1
with open(out_path, "w") as handle:
    json.dump({"angr_version": getattr(angr, "__version__", "unknown"),
               "records": records}, handle)
"""


def capture_angr(
    binaries: Sequence[Path],
    cache_path: Path,
    *,
    per_binary: int,
    timeout_s: float,
) -> dict[str, Any]:
    """Decompile ``binaries`` with angr and cache the raw per-function C.

    angr is run in a throwaway ``uv run --no-project --with angr`` interpreter,
    so it never enters this project's dependency set and cannot perturb the
    extension under measurement.

    Args:
        binaries: Binaries to decompile.
        cache_path: JSON file to write.
        per_binary: Cap on functions kept per binary.
        timeout_s: Wall-clock budget per binary, checked between functions.

    Returns:
        The cache payload that was written.

    Raises:
        RuntimeError: When the angr subprocess fails.
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "uv",
        "run",
        "--no-project",
        "--with",
        "angr",
        "python",
        "-c",
        _ANGR_CAPTURE_SCRIPT,
        str(cache_path),
        str(per_binary),
        str(timeout_s),
        *[str(path) for path in binaries],
    ]
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_s * len(binaries) + 600,
    )
    if completed.returncode != 0 or not cache_path.exists():
        raise RuntimeError(
            f"angr capture failed (rc={completed.returncode}): {completed.stderr[-2000:]}"
        )
    return json.loads(cache_path.read_text(encoding="utf-8"))


def load_angr_units(cache_path: Path) -> list[FunctionUnit]:
    """Read the angr cache written by :func:`capture_angr`.

    Args:
        cache_path: JSON file produced by ``capture-angr``.

    Returns:
        Units sorted by ``(binary, name)``.

    Raises:
        FileNotFoundError: When the cache has not been captured yet.
    """
    if not cache_path.is_file():
        raise FileNotFoundError(
            f"no angr cache at {cache_path}; run `parser_recovery_bench.py capture-angr` first"
        )
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    units: list[FunctionUnit] = []
    for record in payload["records"]:
        text = record.get("text")
        if not text:
            continue
        text = text.rstrip("\n") + "\n"
        # The declarator, not ``record["name"]``: see :func:`definition_name`.
        declared = definition_name(text)
        if declared is None:
            continue
        units.append(
            FunctionUnit(
                source="angr",
                binary=Path(record["binary"]).stem,
                name=declared,
                text=text,
            )
        )
    units.sort(key=lambda unit: (unit.binary, unit.name))
    return units


# --- damage operators -------------------------------------------------------
#
# Every operator takes the assembled translation unit plus the span of the
# function it targets, and returns (damaged text, names it touched). "Touched"
# is deliberately generous: truncation destroys everything after the cut, so
# every later function is touched even though the edit is a single slice.


@dataclass(frozen=True)
class Assembled:
    """A translation unit built from units, with each function's span recorded.

    Attributes:
        text: The unit text.
        names: Function names in file order.
        spans: ``(start, end)`` byte offsets into ``text`` per name.
    """

    text: str
    names: tuple[str, ...]
    spans: dict[str, tuple[int, int]]


def assemble(units: Sequence[FunctionUnit]) -> Assembled:
    """Concatenate units into one translation unit, DecBench-style.

    DecBench joins per-function decompiled C with ``// Function: <name>``
    markers before handing it to Joern (``decbench/utils/cfg.py``), so the
    benchmark builds the same shape rather than a shape of its own.

    Args:
        units: Function definitions, in the order they should appear.

    Returns:
        The assembled unit with per-function spans.
    """
    pieces: list[str] = []
    spans: dict[str, tuple[int, int]] = {}
    offset = 0
    for unit in units:
        marker = f"// Function: {unit.name}\n"
        body = unit.text if unit.text.endswith("\n") else unit.text + "\n"
        piece = marker + body + "\n"
        spans[unit.name] = (offset + len(marker), offset + len(marker) + len(body))
        offset += len(piece)
        pieces.append(piece)
    return Assembled(
        text="".join(pieces),
        names=tuple(unit.name for unit in units),
        spans=spans,
    )


def _body_open_brace(text: str, span: tuple[int, int]) -> int:
    """Offset of the ``{`` that opens the target function's body.

    Args:
        text: The whole translation unit.
        span: ``(start, end)`` of the target function.

    Returns:
        Offset of the opening brace.

    Raises:
        ValueError: When the span holds no brace, which means the corpus
            slicer produced something that is not a definition.
    """
    masked = _strip_c_noncode(text)
    index = masked.find("{", span[0], span[1])
    if index < 0:
        raise ValueError("target function has no body brace")
    return index


def _statement_offsets(text: str, span: tuple[int, int]) -> list[int]:
    """Offsets just past each ``;`` inside the target function's body.

    Args:
        text: The whole translation unit.
        span: ``(start, end)`` of the target function.

    Returns:
        Ascending offsets, each one a safe place to splice between statements.
    """
    masked = _strip_c_noncode(text)
    start = _body_open_brace(text, span)
    return [index + 1 for index in range(start, span[1]) if masked[index] == ";"]


def damage_truncate(
    assembled: Assembled, target: str, rng: random.Random, *, where: str
) -> tuple[str, tuple[str, ...]]:
    """Cut the file off inside the target function.

    Three cut points, all real failure modes of a decompiler killed mid-write
    or of a truncated capture: after the body's ``{`` (unbalanced brace, no
    statements), after a complete statement (unbalanced brace), and mid
    expression (unbalanced brace *and* an incomplete statement).

    Args:
        assembled: The undamaged unit.
        target: Name of the function to cut inside.
        rng: Seeded source of randomness.
        where: ``"open_brace"``, ``"statement"``, or ``"expression"``.

    Returns:
        ``(damaged text, touched names)``. Every function at or after the
        target is touched, because the cut deletes them outright.

    Raises:
        ValueError: When ``where`` is not one of the three cut points.
    """
    span = assembled.spans[target]
    if where == "open_brace":
        cut = _body_open_brace(assembled.text, span) + 1
    elif where == "statement":
        offsets = _statement_offsets(assembled.text, span)
        cut = (
            rng.choice(offsets)
            if offsets
            else _body_open_brace(assembled.text, span) + 1
        )
    elif where == "expression":
        offsets = _statement_offsets(assembled.text, span)
        base = (
            rng.choice(offsets)
            if offsets
            else _body_open_brace(assembled.text, span) + 1
        )
        cut = min(base + 12, span[1] - 1)
    else:
        raise ValueError(f"unknown truncation point: {where}")
    index = assembled.names.index(target)
    return assembled.text[:cut], assembled.names[index:]


def damage_drop_close_brace(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Delete the target function's closing ``}``.

    The rest of the file survives on disk, so this separates a parser that
    resynchronizes from one that swallows every later function into the
    unterminated body.

    Args:
        assembled: The undamaged unit.
        target: Function whose closer is deleted.
        rng: Unused; present so every operator has one signature.

    Returns:
        ``(damaged text, touched names)`` -- only the target is touched.
    """
    del rng
    span = assembled.spans[target]
    masked = _strip_c_noncode(assembled.text)
    close = masked.rfind("}", span[0], span[1])
    if close < 0:
        raise ValueError("target function has no closing brace")
    return assembled.text[:close] + assembled.text[close + 1 :], (target,)


def damage_stray_close_brace(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Insert an extra ``}`` inside the target function's body.

    The body now closes early and its tail becomes top-level garbage -- the
    shape a decompiler produces when its structurer emits an unmatched region.

    Args:
        assembled: The undamaged unit.
        target: Function to break.
        rng: Seeded source of randomness, choosing the insertion point.

    Returns:
        ``(damaged text, touched names)`` -- only the target is touched.
    """
    span = assembled.spans[target]
    offsets = _statement_offsets(assembled.text, span)
    at = rng.choice(offsets) if offsets else _body_open_brace(assembled.text, span) + 1
    return assembled.text[:at] + "\n}\n" + assembled.text[at:], (target,)


def damage_drop_close_paren(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Delete one ``)`` from inside the target function's body.

    Args:
        assembled: The undamaged unit.
        target: Function to break.
        rng: Seeded source of randomness, choosing which paren to delete.

    Returns:
        ``(damaged text, touched names)`` -- only the target is touched.
    """
    span = assembled.spans[target]
    masked = _strip_c_noncode(assembled.text)
    start = _body_open_brace(assembled.text, span)
    candidates = [index for index in range(start, span[1]) if masked[index] == ")"]
    if not candidates:
        raise ValueError("target function body has no parenthesis")
    at = rng.choice(candidates)
    return assembled.text[:at] + assembled.text[at + 1 :], (target,)


def damage_overlapping_definition(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Start the next function's header before the target's body closes.

    This is the shape a per-function decompiler produces when one function's
    output is truncated and the concatenator appends the next one anyway --
    exactly how DecBench assembles a translation unit.

    Args:
        assembled: The undamaged unit.
        target: Function whose body is interrupted.
        rng: Seeded source of randomness, choosing the interruption point.

    Returns:
        ``(damaged text, touched names)`` -- the target and its successor.

    Raises:
        ValueError: When the target is the last function in the unit.
    """
    index = assembled.names.index(target)
    if index + 1 >= len(assembled.names):
        raise ValueError("no successor to overlap with")
    successor = assembled.names[index + 1]
    succ_span = assembled.spans[successor]
    header_end = _body_open_brace(assembled.text, succ_span)
    header = assembled.text[succ_span[0] : header_end].strip()
    span = assembled.spans[target]
    offsets = _statement_offsets(assembled.text, span)
    at = rng.choice(offsets) if offsets else _body_open_brace(assembled.text, span) + 1
    return assembled.text[:at] + "\n" + header + "\n" + assembled.text[at:], (
        target,
        successor,
    )


#: Bytes a decompiler inlines verbatim from ``.rodata``: an ANSI colour escape,
#: a bell, a form feed, a lone CR, and a NUL.
_RODATA_BYTES = "\x1b[1;31m\x07\x0c\r\x00"


def damage_rodata_garbage(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Splice raw ``.rodata`` bytes into the target function's body as code.

    Not inside a literal -- these land between statements, where they are not
    valid C at all. DecBench escapes the in-literal case (see
    ``escape_literal_control_bytes``); this is the harder one it does not.

    Args:
        assembled: The undamaged unit.
        target: Function to contaminate.
        rng: Seeded source of randomness, choosing the splice point.

    Returns:
        ``(damaged text, touched names)`` -- only the target is touched.
    """
    span = assembled.spans[target]
    offsets = _statement_offsets(assembled.text, span)
    at = rng.choice(offsets) if offsets else _body_open_brace(assembled.text, span) + 1
    return assembled.text[:at] + "\n" + _RODATA_BYTES + "\n" + assembled.text[at:], (
        target,
    )


def damage_control_bytes_in_literal(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Add a statement whose string literal holds raw control bytes.

    This is DecBench's fifth sanitizer rule reproduced as damage: valid C that
    ``sanitize_decompiled_c`` still rewrites, because raw control bytes make
    pyjoern's fast parser emit non-JSON and void the whole invocation.

    Args:
        assembled: The undamaged unit.
        target: Function to contaminate.
        rng: Seeded source of randomness, choosing the splice point.

    Returns:
        ``(damaged text, touched names)`` -- only the target is touched.
    """
    span = assembled.spans[target]
    offsets = _statement_offsets(assembled.text, span)
    at = rng.choice(offsets) if offsets else _body_open_brace(assembled.text, span) + 1
    line = f'\n  char *__rodata = "{_RODATA_BYTES}ok";\n'
    return assembled.text[:at] + line + assembled.text[at:], (target,)


#: Lines a capture picks up when a decompiler interleaves its own logging or a
#: disassembly listing into the C stream.
_NON_C_LINES = (
    "0000000000401136 <main>:",
    "  401136:\t55                   \tpush   %rbp",
    "[angr] WARNING | unsupported jumpkind Ijk_Sys_syscall",
    "*** stack smashing detected ***",
)


def damage_non_c_lines(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Interleave non-C lines into the target function's body.

    Args:
        assembled: The undamaged unit.
        target: Function to contaminate.
        rng: Seeded source of randomness, choosing splice point and lines.

    Returns:
        ``(damaged text, touched names)`` -- only the target is touched.
    """
    span = assembled.spans[target]
    offsets = _statement_offsets(assembled.text, span)
    at = rng.choice(offsets) if offsets else _body_open_brace(assembled.text, span) + 1
    chosen = rng.sample(_NON_C_LINES, k=2)
    return assembled.text[:at] + "\n" + "\n".join(chosen) + "\n" + assembled.text[
        at:
    ], (target,)


def _rewrite_header(
    assembled: Assembled, target: str, rewrite: Callable[[str], str]
) -> tuple[str, tuple[str, ...]]:
    """Apply ``rewrite`` to the target function's header text.

    Args:
        assembled: The undamaged unit.
        target: Function whose header is rewritten.
        rewrite: Maps the header text to its replacement.

    Returns:
        ``(damaged text, touched names)`` -- only the target is touched.
    """
    span = assembled.spans[target]
    brace = _body_open_brace(assembled.text, span)
    header = assembled.text[span[0] : brace]
    return assembled.text[: span[0]] + rewrite(header) + assembled.text[brace:], (
        target,
    )


def _qualified_declarator(header: str, name: str) -> tuple[int, int]:
    """Span of the declarator in ``header``, qualification included.

    Both decompilers print C++/Rust qualified names into C
    (``_166_rust_generics::max_generic``), and a calling convention or a
    ``@<reg>`` annotation belongs in front of the *whole* declarator. Splicing
    it in front of the last component instead produces
    ``_166_rust_generics::__fastcall max_generic``, which no decompiler emits --
    that would measure the harness, not the parser.

    Args:
        header: Text from the definition's start to its body brace.
        name: The declarator's last component.

    Returns:
        ``(start, end)`` offsets into ``header``.

    Raises:
        ValueError: When the name is not in the header.
    """
    masked = _strip_c_noncode(header)
    end = masked.rfind(name)
    if end < 0:
        raise ValueError(f"{name!r} is not in the header")
    stop = end + len(name)
    start = end
    while start > 0 and (masked[start - 1].isalnum() or masked[start - 1] in "_:$."):
        start -= 1
    return start, stop


def damage_calling_convention(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Prefix the target's declarator with an IDA/Hex-Rays calling convention.

    ``__fastcall`` and friends are what IDA emits on every function; DecBench
    does not sanitize them, so any parser in the pipeline meets them raw.

    Args:
        assembled: The undamaged unit.
        target: Function to annotate.
        rng: Seeded source of randomness, choosing the convention.

    Returns:
        ``(damaged text, touched names)``.
    """
    convention = rng.choice(("__fastcall", "__cdecl", "__stdcall"))

    def rewrite(header: str) -> str:
        start, _ = _qualified_declarator(header, target)
        return f"{header[:start]}{convention} {header[start:]}"

    return _rewrite_header(assembled, target, rewrite)


def damage_usercall(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Rewrite the target as IDA's ``__usercall f@<eax>(...)``.

    ``@<reg>`` is not C. DecBench's ``_REG_ANNOTATION`` strips the binja
    ``@ rax`` spelling but not this one.

    Args:
        assembled: The undamaged unit.
        target: Function to annotate.
        rng: Seeded source of randomness, choosing the register.

    Returns:
        ``(damaged text, touched names)``.
    """
    register = rng.choice(("eax", "rax", "edi"))

    def rewrite(header: str) -> str:
        start, end = _qualified_declarator(header, target)
        declarator = header[start:end]
        return f"{header[:start]}__usercall {declarator}@<{register}>{header[end:]}"

    return _rewrite_header(assembled, target, rewrite)


def damage_register_annotation(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Add binja's `` @ rax`` register annotation to a local declaration.

    This is DecBench's second sanitizer rule as damage: ``@`` is not valid C
    and, per DecBench's own comment, "breaks Joern's parse for the whole
    function".

    Args:
        assembled: The undamaged unit.
        target: Function to annotate.
        rng: Seeded source of randomness, choosing the register.

    Returns:
        ``(damaged text, touched names)``.
    """
    span = assembled.spans[target]
    register = rng.choice(("rax", "rdi", "rsi"))
    at = _body_open_brace(assembled.text, span) + 1
    line = f"\n  long __annotated @ {register};\n"
    return assembled.text[:at] + line + assembled.text[at:], (target,)


def damage_aggregate_return(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Give the target Ghidra's aggregate return type ``T [N] name(...)``.

    DecBench's first sanitizer rule, verbatim from its comment: "``T [N]
    name(...)`` is not valid C, so Joern parses nothing for such a function and
    it silently drops out of GED's denominator."

    Args:
        assembled: The undamaged unit.
        target: Function to rewrite.
        rng: Unused; kept for operator signature uniformity.

    Returns:
        ``(damaged text, touched names)``.
    """
    del rng
    return _rewrite_header(
        assembled, target, lambda _: f"undefined1 [8] {target}(void)\n"
    )


def damage_int128_and_qword(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Declare IDA's ``_QWORD``/``__int128`` locals in the target's body.

    ``__int128`` is DecBench's third sanitizer rule. ``_QWORD`` is an IDA
    typedef that no header in the unit defines, so it also exercises the
    undeclared-type path.

    Args:
        assembled: The undamaged unit.
        target: Function to rewrite.
        rng: Unused; kept for operator signature uniformity.

    Returns:
        ``(damaged text, touched names)``.
    """
    del rng
    span = assembled.spans[target]
    at = _body_open_brace(assembled.text, span) + 1
    line = "\n  __int128 __wide = 0;\n  _QWORD __ida_slot = 0;\n  unsigned __int128 __uwide = 0;\n"
    return assembled.text[:at] + line + assembled.text[at:], (target,)


def damage_computed_goto(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Add a GNU computed goto and a label-address to the target's body.

    DecBench's fourth sanitizer rule. angr emits ``goto *(...)`` on its own
    (see the pristine class), so this operator only guarantees coverage rather
    than inventing an unseen construct.

    Args:
        assembled: The undamaged unit.
        target: Function to rewrite.
        rng: Unused; kept for operator signature uniformity.

    Returns:
        ``(damaged text, touched names)``.
    """
    del rng
    span = assembled.spans[target]
    at = _body_open_brace(assembled.text, span) + 1
    line = "\n  void *__tgt = &&__lbl;\n  goto *__tgt;\n__lbl:\n  ;\n"
    return assembled.text[:at] + line + assembled.text[at:], (target,)


def damage_gnu_extensions(
    assembled: Assembled, target: str, rng: random.Random
) -> tuple[str, tuple[str, ...]]:
    """Add a statement expression, ``typeof``, and an attribute to the target.

    Args:
        assembled: The undamaged unit.
        target: Function to rewrite.
        rng: Unused; kept for operator signature uniformity.

    Returns:
        ``(damaged text, touched names)``.
    """
    del rng
    span = assembled.spans[target]
    at = _body_open_brace(assembled.text, span) + 1
    line = (
        "\n  int __stmt_expr = ({ int __t = 1; __t + 1; });\n"
        "  __typeof__(__stmt_expr) __same = __stmt_expr;\n"
        "  __attribute__((unused)) int __attr = __same;\n"
    )
    return assembled.text[:at] + line + assembled.text[at:], (target,)


#: ``damage_class -> ((variant name, operator), ...)``. Class 1 has no
#: operators: it is the undamaged control.
DAMAGE_OPERATORS: dict[
    str, tuple[tuple[str, Callable[..., tuple[str, tuple[str, ...]]]], ...]
] = {
    "1-pristine": (),
    "2-dialect": (
        ("calling_convention", damage_calling_convention),
        ("usercall_at_reg", damage_usercall),
        ("register_annotation", damage_register_annotation),
        ("aggregate_return", damage_aggregate_return),
        ("int128_qword", damage_int128_and_qword),
    ),
    "3-gnu": (
        ("computed_goto", damage_computed_goto),
        ("stmt_expr_typeof_attr", damage_gnu_extensions),
    ),
    "4-truncated": (
        (
            "truncate_open_brace",
            lambda a, t, r: damage_truncate(a, t, r, where="open_brace"),
        ),
        (
            "truncate_statement",
            lambda a, t, r: damage_truncate(a, t, r, where="statement"),
        ),
        (
            "truncate_expression",
            lambda a, t, r: damage_truncate(a, t, r, where="expression"),
        ),
    ),
    "5-garbage": (
        ("rodata_bytes", damage_rodata_garbage),
        ("control_bytes_in_literal", damage_control_bytes_in_literal),
        ("non_c_lines", damage_non_c_lines),
    ),
    "6-structural": (
        ("drop_close_brace", damage_drop_close_brace),
        ("stray_close_brace", damage_stray_close_brace),
        ("drop_close_paren", damage_drop_close_paren),
        ("overlapping_definition", damage_overlapping_definition),
    ),
}


# --- case construction ------------------------------------------------------


#: Names ``parity_cfgs`` refuses by design (``is_scoreable_name``). A corpus
#: entry with such a name would score our front end zero for a policy decision
#: rather than a recovery failure, so they never enter the corpus.
UNSCOREABLE_PREFIXES = ("<", "+", "*", "(", ">")
UNSCOREABLE_NAMES = frozenset({"JUMPOUT", "__builtin_unreachable"})


def is_corpus_name(name: str) -> bool:
    """Whether a decompiler-emitted name may enter the corpus.

    Args:
        name: Function name as the producing decompiler wrote it.

    Returns:
        ``False`` for the names ``parity_cfgs`` blacklists, which would
        otherwise misattribute a deliberate policy to a recovery failure.
    """
    return (
        bool(name)
        and name not in UNSCOREABLE_NAMES
        and not name.startswith(UNSCOREABLE_PREFIXES)
    )


def normalize_pool(
    units: Sequence[FunctionUnit], *, max_per_binary: int
) -> list[FunctionUnit]:
    """Deduplicate names within a binary and cap each binary's contribution.

    Ghidra emits the same name twice for thunk pairs (84 of 1,543 units in the
    2026-09-04 capture set). Two definitions of one name in a single case make
    the ground truth ambiguous, because every parser here is keyed by name.
    The per-binary cap stops the four large Rust captures -- 1,380 of those
    1,543 units -- from being the whole benchmark.

    Args:
        units: Pool from one decompiler, sorted by ``(binary, name)``.
        max_per_binary: Cap on units kept per binary.

    Returns:
        The filtered pool, order preserved.
    """
    seen: dict[str, set[str]] = {}
    kept_count: dict[str, int] = {}
    kept: list[FunctionUnit] = []
    for unit in units:
        if not is_corpus_name(unit.name):
            continue
        names = seen.setdefault(unit.binary, set())
        if unit.name in names or kept_count.get(unit.binary, 0) >= max_per_binary:
            continue
        names.add(unit.name)
        kept_count[unit.binary] = kept_count.get(unit.binary, 0) + 1
        kept.append(unit)
    return kept


def build_cases(
    units: Sequence[FunctionUnit],
    *,
    seed: int,
    cases_per_source: int,
    functions_per_case: int,
    max_per_binary: int = 16,
) -> list[Case]:
    """Build the full damage matrix from a pool of real decompiler output.

    Each case holds ``functions_per_case`` definitions from one binary. Damage
    always targets exactly one of them (never the first, so there is always an
    earlier intact function, and the target is chosen once per base group so
    every damage class attacks the same function).

    Args:
        units: Pool of function definitions, from one decompiler.
        seed: Recorded and used for every random choice.
        cases_per_source: Number of base groups to build.
        functions_per_case: Definitions per group.
        max_per_binary: Cap on units taken from any one binary.

    Returns:
        Every case, class 1 first so a caller can parse the controls up front.

    Raises:
        ValueError: When the pool cannot fill a single group.
    """
    by_binary: dict[str, list[FunctionUnit]] = {}
    for unit in normalize_pool(units, max_per_binary=max_per_binary):
        by_binary.setdefault(unit.binary, []).append(unit)
    groups: list[list[FunctionUnit]] = []
    for binary in sorted(by_binary):
        pool = by_binary[binary]
        for start in range(0, len(pool) - functions_per_case + 1, functions_per_case):
            groups.append(pool[start : start + functions_per_case])
    if not groups:
        raise ValueError(
            f"no group of {functions_per_case} functions available from {len(units)} units"
        )
    rng = random.Random(seed)
    rng.shuffle(groups)
    groups = groups[:cases_per_source]

    cases: list[Case] = []
    damaged: list[Case] = []
    for index, group in enumerate(groups):
        source = group[0].source
        assembled = assemble(group)
        base_id = f"{source}-{index:03d}"
        target = random.Random(f"{seed}:{base_id}".encode()).choice(assembled.names[1:])
        cases.append(
            Case(
                case_id=base_id,
                pristine_id=base_id,
                source=source,
                damage_class="1-pristine",
                variant="none",
                text=assembled.text,
                functions=assembled.names,
                touched=(),
            )
        )
        for damage_class, operators in DAMAGE_OPERATORS.items():
            for variant, operator in operators:
                case_rng = random.Random(f"{seed}:{base_id}:{variant}".encode())
                try:
                    text, touched = operator(assembled, target, case_rng)
                except ValueError:
                    continue
                damaged.append(
                    Case(
                        case_id=f"{base_id}:{variant}",
                        pristine_id=base_id,
                        source=source,
                        damage_class=damage_class,
                        variant=variant,
                        text=text,
                        functions=assembled.names,
                        touched=touched,
                    )
                )
    return cases + damaged


# --- parsers ----------------------------------------------------------------


def parse_ours(text: str) -> dict[str, Recovered]:
    """Recover functions with Glaurung's C front end.

    ``parity_cfgs`` is the production entry point DecBench's GED column uses,
    so this measures the shipped path rather than a test-only one.

    The front end exposes no per-function error signal through this API, so
    ``error_free`` falls back to "not degenerate" -- a weaker claim than
    clang's or tree-sitter's. That asymmetry is stated in the report; it is
    also why fidelity, not ``error_free``, is the strict metric.

    Args:
        text: A translation unit.

    Returns:
        Recovered functions by name; a degenerate or empty CFG is dropped.
    """
    from glaurung._native import csource

    out: dict[str, Recovered] = {}
    for name, cfg in csource.parity_cfgs(text).items():
        nodes = list(cfg["nodes"])
        if not nodes:
            continue
        edges = sorted(tuple(edge) for edge in cfg["edges"])
        signature = json.dumps(
            {
                "n": len(nodes),
                "e": edges,
                "entry": sorted(cfg["entry"]),
                "exit": sorted(cfg["exit"]),
            },
            sort_keys=True,
        )
        out[name] = Recovered(
            body_size=len(nodes),
            signature=signature,
            error_free=not bool(cfg["degenerate"]),
        )
    return out


def _libclang_path() -> str:
    """Locate ``libclang.so``.

    Returns:
        Path to the first candidate that exists.

    Raises:
        FileNotFoundError: When none of the candidates is present.
    """
    override = os.environ.get("GLAURUNG_LIBCLANG")
    candidates = (override, *LIBCLANG_CANDIDATES) if override else LIBCLANG_CANDIDATES
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    raise FileNotFoundError(f"no libclang among {candidates}")


def parse_clang(text: str) -> dict[str, Recovered]:
    """Recover functions with libclang in its most permissive mode.

    ``PARSE_INCOMPLETE`` plus ``CXTranslationUnit_KeepGoing`` is clang's own
    "do not give up on errors" configuration, and ``-ferror-limit=0`` stops it
    bailing out after twenty diagnostics -- without which a badly damaged file
    reports fewer functions for a reason that is not recovery.

    ``error_free`` means "no error-severity diagnostic inside this function's
    extent". Note that on decompiler output this is dominated by *semantic*
    errors (``unknown type name 'undefined8'``), which is itself a finding:
    clang's severity gives no way to separate "undeclared type" from "broken
    syntax".

    Args:
        text: A translation unit.

    Returns:
        Recovered functions by name; a definition with an empty body is
        dropped, matching the other two parsers.
    """
    import clang.cindex as cindex

    if not cindex.Config.loaded:
        cindex.Config.set_library_file(_libclang_path())
    index = cindex.Index.create()
    unit = index.parse(
        "input.c",
        args=["-std=gnu11", "-ferror-limit=0", "-w", "-nostdinc"],
        unsaved_files=[("input.c", text)],
        options=CLANG_INCOMPLETE | CLANG_KEEP_GOING,
    )
    error_offsets: list[int] = []
    for diagnostic in unit.diagnostics:
        if diagnostic.severity >= cindex.Diagnostic.Error:
            location = diagnostic.location
            if location is not None and location.offset:
                error_offsets.append(location.offset)

    out: dict[str, Recovered] = {}
    for cursor in unit.cursor.get_children():
        if cursor.kind != cindex.CursorKind.FUNCTION_DECL or not cursor.is_definition():
            continue
        body = next(
            (
                child
                for child in cursor.get_children()
                if child.kind == cindex.CursorKind.COMPOUND_STMT
            ),
            None,
        )
        if body is None:
            continue
        kinds: list[str] = []
        stack = list(body.get_children())
        while stack:
            node = stack.pop()
            kinds.append(node.kind.name)
            stack.extend(node.get_children())
        if not kinds:
            continue
        extent = cursor.extent
        start, end = extent.start.offset, extent.end.offset
        out[cursor.spelling] = Recovered(
            body_size=len(kinds),
            signature="|".join(sorted(kinds)) + f"#{len(kinds)}",
            error_free=not any(start <= offset <= end for offset in error_offsets),
        )
    return out


def parse_tree_sitter(text: str) -> dict[str, Recovered]:
    """Recover functions with tree-sitter-c.

    tree-sitter always returns a tree, so "did it parse" is meaningless for it.
    A ``function_definition`` counts as recovered when it has a named body with
    at least one child; ``error_free`` additionally requires no ``ERROR`` or
    missing node anywhere in that body.

    Args:
        text: A translation unit.

    Returns:
        Recovered functions by name. A definition whose declarator holds no
        identifier is dropped: without a name there is nothing to score.
    """
    import tree_sitter_c
    from tree_sitter import Language, Parser

    parser = Parser(Language(tree_sitter_c.language()))
    tree = parser.parse(text.encode("utf-8", errors="surrogateescape"))

    def declarator_name(node: Any) -> str | None:
        current = node.child_by_field_name("declarator")
        while current is not None:
            if current.type == "identifier":
                return current.text.decode("utf-8", errors="replace")
            nxt = current.child_by_field_name("declarator")
            if nxt is None:
                for child in current.named_children:
                    if child.type in (
                        "identifier",
                        "function_declarator",
                        "pointer_declarator",
                    ):
                        nxt = child
                        break
            current = nxt
        return None

    out: dict[str, Recovered] = {}
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.named_children)
        if node.type != "function_definition":
            continue
        body = node.child_by_field_name("body")
        if body is None or not body.named_children:
            continue
        name = declarator_name(node)
        if name is None:
            continue
        types: list[str] = []
        broken = False
        inner = list(body.named_children)
        while inner:
            child = inner.pop()
            types.append(child.type)
            if child.type == "ERROR" or child.is_missing:
                broken = True
            inner.extend(child.named_children)
        out[name] = Recovered(
            body_size=len(types),
            signature="|".join(sorted(types)) + f"#{len(types)}",
            error_free=not broken and not body.has_error,
        )
    return out


#: Parser name -> callable. Ordered as the report's columns.
PARSERS: dict[str, Callable[[str], dict[str, Recovered]]] = {
    "ours": parse_ours,
    "clang": parse_clang,
    "tree-sitter": parse_tree_sitter,
}


# --- isolated execution -----------------------------------------------------


def _resolve_parser(name: str) -> Callable[[str], dict[str, Recovered]]:
    """Look a parser up in the report set, then the fault injectors.

    Args:
        name: Parser key.

    Returns:
        The callable.

    Raises:
        KeyError: When the name is neither a real parser nor an injector.
    """
    if name in PARSERS:
        return PARSERS[name]
    return DIAGNOSTIC_PARSERS[name]


def _diagnostic_crash(_: str) -> dict[str, Recovered]:
    """A parser that always raises.

    Args:
        _: Ignored translation unit.

    Returns:
        Never returns.

    Raises:
        RuntimeError: Always.
    """
    raise RuntimeError("diagnostic crash")


def _diagnostic_hang(_: str) -> dict[str, Recovered]:
    """A parser that never returns within any sane timeout.

    Args:
        _: Ignored translation unit.

    Returns:
        Never returns in practice.
    """
    time.sleep(3600)
    return {}


#: Fault injectors the worker will serve but the report never has a column for.
#: They exist so :class:`IsolatedRunner`'s crash and timeout paths are covered
#: by a test rather than by inspection -- a runner whose timeout never fires in
#: anger is a runner nobody has checked.
DIAGNOSTIC_PARSERS: dict[str, Callable[[str], dict[str, Recovered]]] = {
    "__diagnostic_crash": _diagnostic_crash,
    "__diagnostic_hang": _diagnostic_hang,
}


def _serve_worker() -> int:
    """Answer parse requests on stdin, one JSON object per line.

    Deliberately a **subprocess** rather than a forked worker. The harness runs
    under pytest, whose plugin set makes the parent multi-threaded, and
    ``fork()`` from a multi-threaded parent deadlocked this runner in practice:
    a child inherited a held lock and both processes sat at 0% CPU until
    killed. A fresh interpreter has no inherited locks, and killing it on a
    timeout needs no cooperation from the wedged code.

    Returns:
        Process exit status.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request = json.loads(line)
        try:
            functions = {
                name: [rec.body_size, rec.signature, rec.error_free]
                for name, rec in _resolve_parser(request["parser"])(
                    request["text"]
                ).items()
            }
            reply: dict[str, Any] = {"status": "ok", "functions": functions}
        except Exception as exc:  # noqa: BLE001 -- a parser crash is a result
            reply = {"status": "crash", "detail": f"{type(exc).__name__}: {exc}"}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    return 0


class IsolatedRunner:
    """Runs parsers in a separate interpreter so a crash or hang is a *result*.

    ``parity_cfgs`` releases the GIL and runs native code, so a Python signal
    alarm cannot interrupt it; only a separate process can. One long-lived
    worker per parser amortizes interpreter and library startup; a timeout
    kills that worker and the next call starts a fresh one.
    """

    def __init__(self, timeout_s: float) -> None:
        """Create a runner.

        Args:
            timeout_s: Per-call wall-clock budget.
        """
        self._timeout_s = timeout_s
        self._workers: dict[str, subprocess.Popen[str]] = {}

    def _worker_for(self, parser: str) -> subprocess.Popen[str]:
        """Return a live worker for ``parser``, starting one if needed.

        Args:
            parser: Key into :data:`PARSERS`.

        Returns:
            The worker process.
        """
        worker = self._workers.get(parser)
        if worker is not None and worker.poll() is None:
            return worker
        worker = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            cwd=REPO_ROOT,
        )
        self._workers[parser] = worker
        return worker

    def _kill(self, parser: str) -> None:
        """Terminate a parser's worker.

        Args:
            parser: Key into :data:`PARSERS`.
        """
        worker = self._workers.pop(parser, None)
        if worker is None:
            return
        worker.kill()
        try:
            worker.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass

    def run(self, parser: str, text: str) -> ParseOutcome:
        """Run one parser over one translation unit.

        Args:
            parser: Key into :data:`PARSERS`.
            text: A translation unit.

        Returns:
            The outcome; a timeout or an exception is recorded, never raised.
        """
        import selectors

        worker = self._worker_for(parser)
        if worker.stdin is None or worker.stdout is None:
            return ParseOutcome(status="crash", detail="worker has no pipes")
        try:
            worker.stdin.write(json.dumps({"parser": parser, "text": text}) + "\n")
            worker.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self._kill(parser)
            return ParseOutcome(status="crash", detail=f"{type(exc).__name__}: {exc}")

        selector = selectors.DefaultSelector()
        selector.register(worker.stdout, selectors.EVENT_READ)
        deadline = _now() + self._timeout_s
        buffer = ""
        try:
            while "\n" not in buffer:
                remaining = deadline - _now()
                if remaining <= 0 or not selector.select(timeout=remaining):
                    self._kill(parser)
                    return ParseOutcome(
                        status="timeout", detail=f"> {self._timeout_s}s"
                    )
                chunk = worker.stdout.readline()
                if not chunk:
                    self._kill(parser)
                    return ParseOutcome(status="crash", detail="worker exited")
                buffer += chunk
        finally:
            selector.close()

        reply = json.loads(buffer.strip())
        if reply["status"] != "ok":
            return ParseOutcome(status="crash", detail=reply.get("detail", ""))
        return ParseOutcome(
            functions={
                name: Recovered(body_size=size, signature=signature, error_free=clean)
                for name, (size, signature, clean) in reply["functions"].items()
            }
        )

    def close(self) -> None:
        """Shut every worker down."""
        for parser in list(self._workers):
            worker = self._workers.pop(parser)
            try:
                if worker.stdin is not None:
                    worker.stdin.close()
                worker.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                worker.kill()


# --- scoring ----------------------------------------------------------------


@dataclass
class Tally:
    """Counters for one (parser, source, damage class) cell.

    Attributes:
        recall_hit: Ground-truth functions recovered with a non-empty body.
        recall_total: Ground-truth functions in the cell.
        local_hit: Intact functions recovered.
        local_total: Intact functions in the cell.
        fidelity_hit: Intact functions whose recovered structure is identical
            to the same parser's structure for the undamaged case.
        fidelity_total: Intact functions with a pristine result to compare to.
        error_free_hit: Recovered functions the parser reported no error in.
        error_free_total: Recovered functions.
        timeouts: Cases that exceeded the per-call budget.
        crashes: Cases that raised.
        cases: Cases in the cell.
    """

    recall_hit: int = 0
    recall_total: int = 0
    local_hit: int = 0
    local_total: int = 0
    fidelity_hit: int = 0
    fidelity_total: int = 0
    error_free_hit: int = 0
    error_free_total: int = 0
    timeouts: int = 0
    crashes: int = 0
    cases: int = 0

    def rate(self, hit: int, total: int) -> float:
        """Percentage, or ``0.0`` when the denominator is empty.

        Args:
            hit: Numerator.
            total: Denominator.

        Returns:
            ``100 * hit / total``, or ``0.0``.
        """
        return 100.0 * hit / total if total else 0.0


def _normalized(functions: dict[str, Recovered]) -> dict[str, Recovered]:
    """Re-key a parser's result by :func:`normalized_name`.

    When two recovered names collapse onto one, the larger body wins, matching
    the way ``parity_cfgs`` itself resolves a name collision.

    Args:
        functions: Recovered functions, keyed as the parser named them.

    Returns:
        The same records keyed by normalized name.
    """
    out: dict[str, Recovered] = {}
    for name, record in functions.items():
        key = normalized_name(name)
        existing = out.get(key)
        if existing is None or record.body_size > existing.body_size:
            out[key] = record
    return out


def score(
    cases: Sequence[Case],
    outcomes: dict[tuple[str, str], ParseOutcome],
) -> dict[tuple[str, str, str], Tally]:
    """Reduce raw parse outcomes to the report matrix.

    Args:
        cases: Every case, including the class-1 controls.
        outcomes: ``(parser, case_id) -> outcome``.

    Returns:
        ``(parser, source, damage class) -> Tally``.
    """
    by_id = {case.case_id: case for case in cases}
    tallies: dict[tuple[str, str, str], Tally] = {}
    for parser in PARSERS:
        for case in cases:
            key = (parser, case.source, case.damage_class)
            tally = tallies.setdefault(key, Tally())
            tally.cases += 1
            outcome = outcomes.get((parser, case.case_id))
            if outcome is None:
                continue
            if outcome.status == "timeout":
                tally.timeouts += 1
            elif outcome.status == "crash":
                tally.crashes += 1
            recovered = _normalized(outcome.functions)
            pristine_outcome = outcomes.get((parser, by_id[case.pristine_id].case_id))
            pristine = (
                _normalized(pristine_outcome.functions)
                if pristine_outcome is not None
                else None
            )
            for raw_name in case.functions:
                name = normalized_name(raw_name)
                tally.recall_total += 1
                got = recovered.get(name)
                if got is not None:
                    tally.recall_hit += 1
                    tally.error_free_total += 1
                    tally.error_free_hit += int(got.error_free)
            for raw_name in case.intact:
                name = normalized_name(raw_name)
                tally.local_total += 1
                got = recovered.get(name)
                if got is not None:
                    tally.local_hit += 1
                if (
                    pristine is None
                    or pristine_outcome is None
                    or pristine_outcome.status != "ok"
                ):
                    continue
                base = pristine.get(name)
                if base is None:
                    continue
                tally.fidelity_total += 1
                if got is not None and got.signature == base.signature:
                    tally.fidelity_hit += 1
    return tallies


def score_by_variant(
    cases: Sequence[Case],
    outcomes: dict[tuple[str, str], ParseOutcome],
) -> dict[tuple[str, str, str], Tally]:
    """Reduce outcomes per damage *operator* rather than per class.

    A class-level number says a parser lost ground; only the operator says
    which construct did it, which is the actionable half.

    Args:
        cases: Every case.
        outcomes: ``(parser, case_id) -> outcome``.

    Returns:
        ``(parser, source, variant) -> Tally``.
    """
    tallies: dict[tuple[str, str, str], Tally] = {}
    for parser in PARSERS:
        for case in cases:
            if case.damage_class == "1-pristine":
                continue
            tally = tallies.setdefault((parser, case.source, case.variant), Tally())
            tally.cases += 1
            outcome = outcomes.get((parser, case.case_id))
            if outcome is None:
                continue
            recovered = _normalized(outcome.functions)
            for name in case.functions:
                tally.recall_total += 1
                tally.recall_hit += int(normalized_name(name) in recovered)
            for name in case.intact:
                tally.local_total += 1
                tally.local_hit += int(normalized_name(name) in recovered)
    return tallies


def pristine_misses(
    cases: Sequence[Case],
    outcomes: dict[tuple[str, str], ParseOutcome],
) -> dict[str, list[str]]:
    """Functions a parser failed to recover from *undamaged* decompiler output.

    A class-1 miss is the strongest single result the harness produces: the
    text is exactly what the decompiler wrote, so anything lost there is a
    construct the parser cannot handle at all.

    Args:
        cases: Every case.
        outcomes: ``(parser, case_id) -> outcome``.

    Returns:
        ``parser -> ["case_id::function", ...]``, sorted.
    """
    misses: dict[str, list[str]] = {parser: [] for parser in PARSERS}
    for case in cases:
        if case.damage_class != "1-pristine":
            continue
        for parser in PARSERS:
            outcome = outcomes.get((parser, case.case_id))
            if outcome is None:
                continue
            recovered = _normalized(outcome.functions)
            for name in case.functions:
                if normalized_name(name) not in recovered:
                    misses[parser].append(f"{case.case_id}/{name}")
    for parser in misses:
        misses[parser].sort()
    return misses


#: Ghidra's aggregate return, the first rule DecBench's sanitizer rewrites.
_AGGREGATE_RETURN_RE = re.compile(
    r"^([A-Za-z_][\w ]*?)\s*\[\d+\]\s+([A-Za-z_]\w*\s*\()", re.M
)

#: Constructs that occur in real decompiler output with no damage applied.
#: ``label`` -> predicate over one pristine case's text.
NATURAL_HAZARDS: tuple[tuple[str, Callable[[str], bool]], ...] = (
    ("computed goto (`goto *`)", lambda text: "goto *" in _strip_c_noncode(text)),
    ("`::`-qualified declarator", lambda text: "::" in _strip_c_noncode(text)),
    ("`__int128`", lambda text: "__int128" in text),
    ("`@` register annotation", lambda text: "@" in _strip_c_noncode(text)),
    (
        "aggregate return `T [N] name(`",
        lambda text: _AGGREGATE_RETURN_RE.search(text) is not None,
    ),
    (
        "raw control byte outside a literal",
        lambda text: any(
            char < " " and char not in "\t\n\r" for char in _strip_c_noncode(text)
        ),
    ),
    (
        "`<` or `>` in a declarator (template-like)",
        lambda text: "<" in _strip_c_noncode(text),
    ),
)


def corpus_hazards(cases: Sequence[Case]) -> dict[tuple[str, str], int]:
    """Count naturally occurring hazards in the undamaged corpus.

    Nothing here is injected: these are constructs the decompilers emitted on
    their own, which is what makes them evidence about the real population
    rather than about the damage operators.

    Args:
        cases: Every case; only class 1 is inspected.

    Returns:
        ``(source, hazard label) -> number of pristine cases containing it``.
    """
    counts: dict[tuple[str, str], int] = {}
    for case in cases:
        if case.damage_class != "1-pristine":
            continue
        for label, predicate in NATURAL_HAZARDS:
            key = (case.source, label)
            counts.setdefault(key, 0)
            if predicate(case.text):
                counts[key] += 1
    return counts


def sanitizer_hazard(
    cases: Sequence[Case], decbench_dir: Path
) -> dict[tuple[str, str], int] | None:
    """Count cases DecBench must rewrite before Joern's parser sees them.

    This is **not** a measurement of Eclipse CDT. It is a measurement of
    DecBench's ``sanitize_decompiled_c``, whose five rewrites exist, by its own
    docstring, to "clean decompiler-specific C quirks that break Joern's
    parser". A case it rewrites is one DecBench's authors judged CDT could not
    take raw. Importing the function is pure Python -- no JVM is started.

    Args:
        cases: Cases to test.
        decbench_dir: Root of the DecBench checkout.

    Returns:
        ``(source, damage class) -> number of cases rewritten``, or ``None``
        when the checkout is absent.
    """
    if not (decbench_dir / "decbench" / "utils" / "cfg.py").is_file():
        return None
    sys.path.insert(0, str(decbench_dir))
    try:
        from decbench.utils.cfg import sanitize_decompiled_c
    except ImportError:
        return None
    finally:
        sys.path.pop(0)
    counts: dict[tuple[str, str], int] = {}
    for case in cases:
        key = (case.source, case.damage_class)
        counts.setdefault(key, 0)
        try:
            rewritten = sanitize_decompiled_c(case.text)
        except (ValueError, RecursionError):
            rewritten = case.text
        if rewritten != case.text:
            counts[key] += 1
    return counts


# --- reporting --------------------------------------------------------------


def render_markdown(
    tallies: dict[tuple[str, str, str], Tally],
    hazards: dict[tuple[str, str], int] | None,
    meta: dict[str, Any],
    *,
    variants: dict[tuple[str, str, str], Tally] | None = None,
    misses: dict[str, list[str]] | None = None,
    natural: dict[tuple[str, str], int] | None = None,
) -> str:
    """Render the recovery matrix as Markdown.

    Args:
        tallies: Output of :func:`score`.
        hazards: Output of :func:`sanitizer_hazard`, or ``None``.
        meta: Run provenance (seed, build, versions) printed above the tables.
        variants: Output of :func:`score_by_variant`, or ``None``.
        misses: Output of :func:`pristine_misses`, or ``None``.
        natural: Output of :func:`corpus_hazards`, or ``None``.

    Returns:
        A Markdown document.
    """
    lines: list[str] = ["# Parser recovery matrix", ""]
    for key in sorted(meta):
        lines.append(f"- `{key}`: {meta[key]}")
    lines.append("")

    sources = sorted({source for _, source, _ in tallies})
    for source in sources:
        lines.append(f"## Corpus: {source}")
        lines.append("")
        lines.append(
            "| damage class | parser | cases | recall | localization | fidelity | "
            "error-free | timeout | crash |"
        )
        lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|")
        for damage_class in DAMAGE_CLASSES:
            for parser in PARSERS:
                tally = tallies.get((parser, source, damage_class))
                if tally is None:
                    continue
                lines.append(
                    f"| {damage_class} | {parser} | {tally.cases} "
                    f"| {tally.rate(tally.recall_hit, tally.recall_total):.1f}% "
                    f"({tally.recall_hit}/{tally.recall_total}) "
                    f"| {tally.rate(tally.local_hit, tally.local_total):.1f}% "
                    f"({tally.local_hit}/{tally.local_total}) "
                    f"| {tally.rate(tally.fidelity_hit, tally.fidelity_total):.1f}% "
                    f"({tally.fidelity_hit}/{tally.fidelity_total}) "
                    f"| {tally.rate(tally.error_free_hit, tally.error_free_total):.1f}% "
                    f"| {tally.timeouts} | {tally.crashes} |"
                )
        lines.append("")

    if variants:
        lines.append("## Per damage operator")
        lines.append("")
        lines.append("| corpus | operator | parser | recall | localization |")
        lines.append("|---|---|---|---:|---:|")
        for (parser, source, variant), tally in sorted(
            variants.items(), key=lambda item: (item[0][1], item[0][2], item[0][0])
        ):
            lines.append(
                f"| {source} | {variant} | {parser} "
                f"| {tally.rate(tally.recall_hit, tally.recall_total):.1f}% "
                f"({tally.recall_hit}/{tally.recall_total}) "
                f"| {tally.rate(tally.local_hit, tally.local_total):.1f}% "
                f"({tally.local_hit}/{tally.local_total}) |"
            )
        lines.append("")

    if misses is not None:
        lines.append(
            "## Class-1 misses: functions lost from UNDAMAGED decompiler output"
        )
        lines.append("")
        for parser, lost in sorted(misses.items()):
            lines.append(
                f"- **{parser}** ({len(lost)}): {', '.join(lost) if lost else 'none'}"
            )
        lines.append("")

    if natural:
        lines.append("## Naturally occurring hazards in the undamaged corpus")
        lines.append("")
        lines.append("| corpus | construct | pristine cases containing it |")
        lines.append("|---|---|---:|")
        for (source, label), count in sorted(natural.items()):
            lines.append(f"| {source} | {label} | {count} |")
        lines.append("")

    if hazards is not None:
        lines.append("## DecBench sanitizer hazard (inferred, NOT a CDT measurement)")
        lines.append("")
        lines.append("| corpus | damage class | cases rewritten before Joern |")
        lines.append("|---|---|---:|")
        for (source, damage_class), count in sorted(hazards.items()):
            lines.append(f"| {source} | {damage_class} | {count} |")
        lines.append("")
    return "\n".join(lines) + "\n"


# --- CLI --------------------------------------------------------------------


def _binaries_for_captures(ghidra_out: Path, binary_dir: Path) -> list[Path]:
    """Binaries that have a Ghidra capture, so both corpora share a base set.

    Args:
        ghidra_out: Directory of Ghidra captures.
        binary_dir: Directory of fixture binaries.

    Returns:
        Existing ``.so`` paths, sorted.
    """
    found: list[Path] = []
    for capture in sorted(ghidra_out.glob("*.c")):
        candidate = binary_dir / f"{capture.stem}.so"
        if candidate.is_file():
            found.append(candidate)
    return found


def _collect_units(
    args: argparse.Namespace,
) -> tuple[list[FunctionUnit], dict[str, str]]:
    """Load both corpora, tolerating an absent one.

    Args:
        args: Parsed command line.

    Returns:
        ``(units, notes)`` where ``notes`` records why a corpus is missing.
    """
    units: list[FunctionUnit] = []
    notes: dict[str, str] = {}
    try:
        units.extend(load_ghidra_units(args.ghidra_out))
    except FileNotFoundError as exc:
        notes["ghidra"] = str(exc)
    try:
        units.extend(load_angr_units(args.angr_cache))
    except FileNotFoundError as exc:
        notes["angr"] = str(exc)
    return units, notes


def _iter_case_work(cases: Sequence[Case]) -> Iterator[tuple[str, Case]]:
    """Yield ``(parser, case)`` with class-1 controls first.

    Fidelity compares each damaged case to its pristine parse, so the controls
    must already be in the outcome map when a damaged case is scored.

    Args:
        cases: Every case.

    Yields:
        ``(parser name, case)`` pairs.
    """
    ordered = sorted(
        cases, key=lambda case: (case.damage_class != "1-pristine", case.case_id)
    )
    for parser in PARSERS:
        for case in ordered:
            yield parser, case


def command_capture_angr(args: argparse.Namespace) -> int:
    """Run angr over the fixture binaries and cache its output.

    Args:
        args: Parsed command line.

    Returns:
        Process exit status.
    """
    binaries = _binaries_for_captures(args.ghidra_out, args.binary_dir)
    if not binaries:
        print(f"no binaries matching captures in {args.ghidra_out}", file=sys.stderr)
        return 2
    payload = capture_angr(
        binaries,
        args.angr_cache,
        per_binary=args.angr_per_binary,
        timeout_s=args.angr_timeout,
    )
    ok = sum(1 for record in payload["records"] if record.get("text"))
    failed = len(payload["records"]) - ok
    print(
        f"angr {payload['angr_version']}: {ok} functions from {len(binaries)} binaries "
        f"({failed} failures) -> {args.angr_cache}"
    )
    return 0


def command_run(args: argparse.Namespace) -> int:
    """Build the corpus, run every parser, and write the matrix.

    Args:
        args: Parsed command line.

    Returns:
        Process exit status.
    """
    units, notes = _collect_units(args)
    if args.exclude_binary:
        # ``str(...)`` because argparse hands back ``Any``; without it the
        # compiled pattern is ``Pattern[Any]`` and no ``search`` overload matches.
        pattern: re.Pattern[str] = re.compile(str(args.exclude_binary))
        before = len(units)
        units = [unit for unit in units if not pattern.search(unit.binary)]
        notes["excluded"] = (
            f"{args.exclude_binary}: {before - len(units)} units dropped"
        )
    if not units:
        print(f"no corpus available: {notes}", file=sys.stderr)
        return 2

    cases: list[Case] = []
    for source in sorted({unit.source for unit in units}):
        cases.extend(
            build_cases(
                [unit for unit in units if unit.source == source],
                seed=args.seed,
                cases_per_source=args.cases_per_source,
                functions_per_case=args.functions_per_case,
                max_per_binary=args.max_per_binary,
            )
        )

    runner = IsolatedRunner(args.timeout)
    outcomes: dict[tuple[str, str], ParseOutcome] = {}
    work = list(_iter_case_work(cases))
    for index, (parser, case) in enumerate(work, start=1):
        outcomes[(parser, case.case_id)] = runner.run(parser, case.text)
        if args.verbose and index % 50 == 0:
            print(f"  {index}/{len(work)}", file=sys.stderr)
    runner.close()

    tallies = score(cases, outcomes)
    hazards = sanitizer_hazard(cases, args.decbench_dir)
    meta: dict[str, Any] = {
        "seed": args.seed,
        "cases": len(cases),
        "functions_per_case": args.functions_per_case,
        "timeout_s": args.timeout,
        "corpus_notes": notes or "none",
        "max_per_binary": args.max_per_binary,
        "cases_per_source": args.cases_per_source,
        "exclude_binary": args.exclude_binary or "none",
        **_build_provenance(),
    }
    variants = score_by_variant(cases, outcomes)
    misses = pristine_misses(cases, outcomes)
    natural = corpus_hazards(cases)
    report = render_markdown(
        tallies, hazards, meta, variants=variants, misses=misses, natural=natural
    )
    print(report)
    if args.markdown:
        args.markdown.write_text(report, encoding="utf-8")
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "meta": meta,
                    "cells": [
                        {
                            "parser": parser,
                            "source": source,
                            "damage_class": damage_class,
                            **vars(tally),
                        }
                        for (parser, source, damage_class), tally in sorted(
                            tallies.items()
                        )
                    ],
                    "variants": [
                        {
                            "parser": parser,
                            "source": source,
                            "variant": variant,
                            **vars(tally),
                        }
                        for (parser, source, variant), tally in sorted(variants.items())
                    ],
                    "pristine_misses": misses,
                    "natural_hazards": [
                        {"source": source, "construct": label, "cases": count}
                        for (source, label), count in sorted(natural.items())
                    ],
                    "hazards": [
                        {
                            "source": source,
                            "damage_class": damage_class,
                            "rewritten": count,
                        }
                        for (source, damage_class), count in sorted(
                            (hazards or {}).items()
                        )
                    ],
                    "failures": [
                        {
                            "parser": parser,
                            "case": case_id,
                            "status": outcome.status,
                            "detail": outcome.detail,
                        }
                        for (parser, case_id), outcome in sorted(outcomes.items())
                        if outcome.status != "ok"
                    ],
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    return 0


def _build_provenance() -> dict[str, str]:
    """Record which build of the extension and which tree produced a number.

    Returns:
        Commit, working-tree dirtiness of the C front end, and library
        versions -- everything needed to say what was measured.
    """
    out: dict[str, str] = {}
    for key, command in (
        ("commit", ["git", "rev-parse", "--short", "HEAD"]),
        (
            "csource_dirty",
            ["git", "status", "--porcelain", "src/csource", "src/metrics"],
        ),
    ):
        try:
            result = subprocess.run(
                command,
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            out[key] = result.stdout.strip().replace("\n", "; ") or "clean"
        except (OSError, subprocess.SubprocessError):
            out[key] = "unknown"
    try:
        import glaurung._native as native

        out["native_so"] = str(getattr(native, "__file__", "unknown"))
    except ImportError:
        out["native_so"] = "unimportable"
    try:
        import clang.cindex as cindex

        out["libclang"] = _libclang_path()
        out["clang_bindings"] = str(getattr(cindex, "__file__", "unknown"))
    except (ImportError, FileNotFoundError):
        out["libclang"] = "unavailable"
    try:
        import tree_sitter

        out["tree_sitter"] = str(getattr(tree_sitter, "__version__", "unknown"))
    except ImportError:
        out["tree_sitter"] = "unavailable"
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Returns:
        The configured parser.
    """
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--seed", type=int, default=20260904, help="seed for every random choice"
    )
    parser.add_argument(
        "--ghidra-out",
        type=Path,
        default=Path(os.environ.get("GLAURUNG_GHIDRA_OUT", DEFAULT_GHIDRA_OUT)),
        help="directory of Ghidra analyzeHeadless C captures",
    )
    parser.add_argument(
        "--binary-dir", type=Path, default=DEFAULT_BINARY_DIR, help="fixture binaries"
    )
    parser.add_argument(
        "--angr-cache",
        type=Path,
        default=DEFAULT_CACHE_DIR / "angr-units.json",
        help="JSON cache of angr's decompiler output",
    )
    parser.add_argument(
        "--decbench-dir",
        type=Path,
        default=Path(os.environ.get("DECBENCH_DIR", DEFAULT_DECBENCH_DIR)),
        help="DecBench checkout, read for its sanitizer only",
    )
    parser.add_argument("--angr-per-binary", type=int, default=40)
    parser.add_argument("--angr-timeout", type=float, default=300.0)
    parser.add_argument("--cases-per-source", type=int, default=24)
    parser.add_argument("--max-per-binary", type=int, default=16)
    parser.add_argument(
        "--exclude-binary",
        default=None,
        help="regex; binaries whose stem matches are dropped from both corpora",
    )
    parser.add_argument("--functions-per-case", type=int, default=4)
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="per parser call, seconds"
    )
    parser.add_argument("--markdown", type=Path, default=None)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "command",
        choices=("run", "capture-angr", "worker"),
        help="what to do; `worker` is the internal parse server, not for direct use",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Command line, defaulting to ``sys.argv[1:]``.

    Returns:
        Process exit status.
    """
    if (argv if argv is not None else sys.argv[1:]) == ["worker"]:
        return _serve_worker()
    args = build_arg_parser().parse_args(argv)
    if args.command == "capture-angr":
        return command_capture_angr(args)
    return command_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
