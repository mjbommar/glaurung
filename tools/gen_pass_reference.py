#!/usr/bin/env python3
"""Generate `docs/reference/decompiler-passes.md` from the pipeline source.

The decompiler's pass order lives in exactly two Rust functions:

  `run_ast_passes`                    `src/python_bindings/ir/pipeline.rs`
  `decbench_text_with_installed_…`    `src/python_bindings/ir/decbench_render.rs`

Both wrap every step in a naming macro (`pass!`, `refine!`) or in
`profiler.measure(..)`, because a transform that is not named is a transform
the health report cannot attribute. That naming discipline is what makes this
file extractable: the generator reads the same names the profiler and
`GLAURUNG_DUMP_PASSES` print, so the reference and the runtime cannot disagree.

Why generated and not written: the hand-written pipeline reference this
replaces described a 21-pass pipeline at a 2026-04 commit and was still linked
as current guidance sixteen months of pass changes later. A table that drifts
silently is worse than no table.

Usage::

    uv run python tools/gen_pass_reference.py            # write
    uv run python tools/gen_pass_reference.py --check    # exit 1 if stale

`python/tests/test_gen_pass_reference.py` regenerates into a temporary
directory and diffs, so the file cannot go stale without a test going red.
Both the test and `--check` ignore the commit line in the header: the content
is a property of the source, not of when it was last regenerated.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIPELINE = Path("src/python_bindings/ir/pipeline.rs")
DECBENCH = Path("src/python_bindings/ir/decbench_render.rs")
OUT = Path("docs/reference/decompiler-passes.md")

#: The `pass!`/`refine!` bodies and the LLIR prep sequence both contain
#: fully-qualified calls of this shape. The trailing `(` is what separates a
#: CALL from a type path such as `crate::ir::types::LlirFunction`.
CRATE_CALL = re.compile(r"crate::(\w+)::(\w+)::([a-z][a-z_0-9]*)\s*\(")

#: A bare call to a helper defined in the same file (`recognise_machine_frame`).
BARE_CALL = re.compile(r"(?<![\w:.])([a-z][a-z_0-9]*)\s*\(")

#: Steps that are debugging output rather than pipeline stages. Every one of
#: them sits inside a `GLAURUNG_DUMP_PASSES` guard, which is excluded wholesale
#: (see `_dump_spans`); this set is the belt to that suspenders.
DEBUG_ONLY = frozenset({"render", "render_c", "render_with_types"})

COMMIT_MARKER = "<!-- Commit:"


# --------------------------------------------------------------------------
# A minimal Rust scanner: enough to match delimiters without being fooled by
# a `(` inside a comment or a string literal, which this source has plenty of.
# --------------------------------------------------------------------------


def _code_mask(text: str) -> list[bool]:
    """True at every offset that is real code (not a comment or a literal)."""
    mask = [True] * len(text)
    i = 0
    n = len(text)
    while i < n:
        two = text[i : i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                mask[k] = False
            i = j
        elif two == "/*":
            depth = 1
            j = i + 2
            while j < n and depth:
                if text[j : j + 2] == "/*":
                    depth += 1
                    j += 2
                elif text[j : j + 2] == "*/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            for k in range(i, min(j, n)):
                mask[k] = False
            i = j
        elif text[i] == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            # The opening and closing quotes stay code so a string ARGUMENT is
            # still findable; only its contents are masked.
            for k in range(i + 1, max(i + 1, j - 1)):
                mask[k] = False
            i = j
        else:
            i += 1
    return mask


OPEN = {"(": ")", "[": "]", "{": "}"}
CLOSE = {v: k for k, v in OPEN.items()}


def _match_delim(text: str, mask: list[bool], start: int) -> int:
    """Index just past the delimiter opened at `start`."""
    stack = [text[start]]
    i = start + 1
    while i < len(text) and stack:
        if mask[i]:
            char = text[i]
            if char in OPEN:
                stack.append(char)
            elif char in CLOSE:
                if stack and stack[-1] == CLOSE[char]:
                    stack.pop()
                else:  # pragma: no cover - unbalanced source would be a bug
                    raise ValueError(f"unbalanced delimiter at offset {i}")
        i += 1
    return i


def _fn_body(text: str, mask: list[bool], name: str) -> tuple[int, int]:
    """The `{ .. }` span of `fn <name>`, as (start, end) offsets."""
    match = re.search(rf"\bfn\s+{re.escape(name)}\s*[(<]", text)
    if match is None:
        raise ValueError(f"{name} not found")
    brace = text.index("{", _match_delim(text, mask, text.index("(", match.start())))
    return brace, _match_delim(text, mask, brace)


def _dump_spans(text: str, mask: list[bool]) -> list[tuple[int, int]]:
    """Spans of every `GLAURUNG_DUMP_PASSES`-guarded block.

    Their contents are diagnostics, not pipeline steps: the verified-MIR lower
    inside one of them is exactly the `#[allow(dead_code)]` artifact the
    architecture doc calls out as having no production consumer, and listing it
    as a stage would make the reference claim the opposite.
    """
    spans = []
    for match in re.finditer(r"GLAURUNG_DUMP_PASSES", text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        if not text[line_start:].lstrip().startswith(("if ", "let dump", "let ")):
            continue
        brace = text.find("{", match.end())
        if brace < 0:
            continue
        spans.append((match.start(), _match_delim(text, mask, brace)))
    return spans


def _in(spans: list[tuple[int, int]], offset: int) -> bool:
    return any(start <= offset < end for start, end in spans)


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


@dataclass
class Step:
    name: str
    kind: str
    calls: list[tuple[str, str]] = field(default_factory=list)  # (module, fn)


def _calls_in(
    fragment: str,
    local_fns: set[str],
    offset: int,
    dump: list[tuple[int, int]],
) -> list[tuple[str, str]]:
    mask = _code_mask(fragment)
    found: list[tuple[str, str]] = []
    for match in CRATE_CALL.finditer(fragment):
        if not mask[match.start()] or _in(dump, offset + match.start()):
            continue
        module, function = match.group(2), match.group(3)
        if function in DEBUG_ONLY and module in {"ast"}:
            continue
        if (module, function) not in found:
            found.append((module, function))
    if not found:
        for match in BARE_CALL.finditer(fragment):
            if not mask[match.start()]:
                continue
            if match.group(1) in local_fns and (None, match.group(1)) not in found:
                found.append((None, match.group(1)))  # type: ignore[arg-type]
    return found


def _named_steps(
    text: str,
    mask: list[bool],
    span: tuple[int, int],
    local_fns: set[str],
    dump: list[tuple[int, int]],
) -> list[Step]:
    """Every `pass!` / `refine!` / `profiler.measure` / `trace_pass`, in order."""
    start, end = span
    pattern = re.compile(
        r"(?:(pass|refine)!\s*\(|(profiler\.measure)\s*\(|"
        r"crate::ir::health::(trace_pass)\s*\()"
    )
    steps: list[Step] = []
    for match in pattern.finditer(text, start, end):
        if not mask[match.start()] or _in(dump, match.start()):
            continue
        kind = match.group(1) or ("measure" if match.group(2) else "boundary")
        open_paren = text.index("(", match.start())
        close = _match_delim(text, mask, open_paren)
        args = text[open_paren + 1 : close - 1]
        name_match = re.match(r'\s*"([^"]+)"', args)
        if name_match is None:
            continue
        name = name_match.group(1)
        body = args[name_match.end() :]
        calls = (
            []
            if kind == "boundary"
            else _calls_in(body, local_fns, open_paren + 1 + name_match.end(), dump)
        )
        steps.append(Step(name=name, kind=kind, calls=calls))
    return steps


def _prep_steps(
    text: str,
    mask: list[bool],
    local_fns: set[str],
    dump: list[tuple[int, int]],
) -> list[Step]:
    """The Stage 1 LLIR preparation sequence, in source order.

    Local helpers are expanded one level, so the two SSA recomputations show
    the sequence they actually run rather than a helper name.
    """
    start, end = _fn_body(text, mask, "prepare_llir_for_lowering")
    body = text[start:end]
    body_mask = mask[start:end]
    steps: list[Step] = []
    seen_offsets: set[int] = set()
    pattern = re.compile(CRATE_CALL.pattern + r"|" + BARE_CALL.pattern)
    for match in pattern.finditer(body):
        if not body_mask[match.start()] or _in(dump, start + match.start()):
            continue
        if match.start() in seen_offsets:
            continue
        seen_offsets.add(match.start())
        if match.group(1):  # crate::a::b::c(
            steps.append(
                Step(
                    name=f"{match.group(2)}::{match.group(3)}",
                    kind="call",
                    calls=[(match.group(2), match.group(3))],
                )
            )
        elif match.group(4) in local_fns:
            inner_start, inner_end = _fn_body(text, mask, match.group(4))
            inner = _calls_in(text[inner_start:inner_end], local_fns, inner_start, dump)
            steps.append(Step(name=match.group(4), kind="helper", calls=inner))
    return steps


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _module_file(module: str, root: Path) -> str | None:
    for candidate in (
        Path("src/ir") / f"{module}.rs",
        Path("src/ir") / module / "mod.rs",
        Path("src/analysis") / f"{module}.rs",
        Path("src/analysis") / module / "mod.rs",
        Path("src/program") / f"{module}.rs",
    ):
        if (root / candidate).is_file():
            return candidate.as_posix()
    return None


def _calls_cell(step: Step, root: Path) -> tuple[str, str]:
    if not step.calls:
        return "--", "--"
    names = []
    files = []
    for module, function in step.calls:
        if module is None:
            names.append(f"`{function}`")
            if PIPELINE.as_posix() not in files:
                files.append(PIPELINE.as_posix())
            continue
        names.append(f"`{module}::{function}`")
        path = _module_file(module, root)
        if path and path not in files:
            files.append(path)
    return ", ".join(names), ", ".join(f"`{p}`" for p in files) or "--"


def _table(steps: list[Step], root: Path, numbered: bool) -> list[str]:
    lines = ["| # | step | calls | file |", "|---:|---|---|---|"]
    index = 0
    for step in steps:
        if step.kind == "boundary":
            lines.append(f"| | *(health boundary)* `{step.name}` | -- | -- |")
            continue
        index += 1
        marker = str(index) if numbered else ""
        label = f"`{step.name}`"
        if step.kind == "refine":
            label += " *(type map only)*"
        elif step.kind == "measure":
            label += " *(measured stage)*"
        calls, files = _calls_cell(step, root)
        lines.append(f"| {marker} | {label} | {calls} | {files} |")
    return lines


HEADER = """\
# Decompiler passes

> **Kind:** reference · **Status:** generated

<!-- Generated by tools/gen_pass_reference.py -- DO NOT EDIT BY HAND. -->
<!-- Sources: src/python_bindings/ir/pipeline.rs, src/python_bindings/ir/decbench_render.rs -->
{commit}

The ordered stage list every `glaurung decompile` runs, extracted from the two
functions that hold it. Names are the ones the profiler
(`GLAURUNG_PROFILE_FUNCTION`), the health tracer (`GLAURUNG_PASS_HEALTH`) and
the AST dump (`GLAURUNG_DUMP_PASSES`) print, so a row here is a row you can
select on the command line.

For what the stages mean, why they are in this order, and which of them are
architecture-specific, read
[`../architecture/decompiler-pipeline.md`](../architecture/decompiler-pipeline.md).
Stage 0 (image load, CFG discovery, naming) and Stage 3 (post-pipeline recovery
and type-map projection) are inline in `src/python_bindings/ir.rs` rather than
in a named list, so they are described there and not tabulated here.
"""


def generate(root: Path = ROOT, commit: str | None = None) -> str:
    pipeline_text = (root / PIPELINE).read_text()
    pipeline_mask = _code_mask(pipeline_text)
    pipeline_dump = _dump_spans(pipeline_text, pipeline_mask)
    pipeline_fns = set(re.findall(r"\bfn\s+([a-z][a-z_0-9]*)\s*[(<]", pipeline_text))

    decbench_text = (root / DECBENCH).read_text()
    decbench_mask = _code_mask(decbench_text)
    decbench_dump = _dump_spans(decbench_text, decbench_mask)
    decbench_fns = set(re.findall(r"\bfn\s+([a-z][a-z_0-9]*)\s*[(<]", decbench_text))

    prep = _prep_steps(pipeline_text, pipeline_mask, pipeline_fns, pipeline_dump)
    ast_passes = _named_steps(
        pipeline_text,
        pipeline_mask,
        _fn_body(pipeline_text, pipeline_mask, "run_ast_passes"),
        pipeline_fns,
        pipeline_dump,
    )
    refine_chain = _named_steps(
        decbench_text,
        decbench_mask,
        _fn_body(
            decbench_text, decbench_mask, "decbench_text_with_installed_environment"
        ),
        decbench_fns,
        decbench_dump,
    )

    commit_line = COMMIT_MARKER + f" {commit or _head(root)} -->"
    out: list[str] = [HEADER.format(commit=commit_line)]

    out.append(
        "\n## Stage 1 -- LLIR preparation\n\n"
        f"`prepare_llir_for_lowering`, `{PIPELINE.as_posix()}`. In source order;"
        " local helpers expanded one level. SSA is computed more than once on"
        " purpose -- a proven direct output turns an operand-free machine return"
        " into an explicit LLIR use, and the definedness oracle has to see it.\n\n"
        "Source order is not always run order here: a"
        " `value_number_with_parameter_slots*` row and the"
        " `live_in_arg_slots_llir` row beside it are the two arms of one"
        " `if recover_semantic_prototype`, and only one runs per"
        " decompilation. The `file` column names the module's own file, which"
        " for a module with submodules (`ast`, `value_number`, `structure`) is"
        " the facade rather than the file holding the function.\n"
    )
    out.extend(_table(prep, root, numbered=True))

    out.append(
        "\n## Stage 2 -- the AST pass pipeline\n\n"
        f"`run_ast_passes`, `{PIPELINE.as_posix()}`. Every decompilation entry"
        " point runs exactly this list, in this order.\n"
    )
    out.extend(_table(ast_passes, root, numbered=True))

    out.append(
        "\n## Stage 3 -- the DecBench render chain\n\n"
        f"`decbench_text_with_installed_environment`, `{DECBENCH.as_posix()}`."
        " Reached only by `--style decbench`. A `pass!` rewrites the AST; a"
        " *(type map only)* `refine!` sharpens a `TypeMap` and leaves the AST"
        " alone, so it emits no health event. `ready_to_render` is the"
        " pre-render verification boundary: everything after it is formatting.\n"
    )
    out.extend(_table(refine_chain, root, numbered=True))

    out.append("")
    return "\n".join(out)


def _head(root: Path) -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):  # pragma: no cover
        return "unknown"


def without_commit(text: str) -> str:
    """The document minus its provenance line.

    The commit stamp records when the file was last regenerated, which is not
    a fact about the pipeline. Comparing with it would make the check fail on
    every commit that did not touch a pass.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.startswith(COMMIT_MARKER)
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the reference differs from the source",
    )
    args = parser.parse_args(argv)

    text = generate()
    path = ROOT / OUT
    existing = path.read_text() if path.exists() else None

    if args.check:
        if existing is not None and without_commit(existing) == without_commit(text):
            return 0
        print(f"stale: {OUT}", file=sys.stderr)
        print("run: uv run python tools/gen_pass_reference.py", file=sys.stderr)
        return 1

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    changed = existing is None or without_commit(existing) != without_commit(text)
    print(f"wrote {OUT} ({'changed' if changed else 'unchanged'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
