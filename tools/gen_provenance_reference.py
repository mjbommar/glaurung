#!/usr/bin/env python3
"""Generate the ladder half of `docs/reference/provenance.md` from the code.

The `set_by` ranking lives in exactly one place:

  `SET_BY_PRIORITY`   `python/glaurung/llm/kb/provenance.py`

Before this generator existed the ladder appeared in five documents and was
right in none of them: four of the five listed seven values in a strict total
order, and the code has twelve values across seven ranks with three deliberate
ties. Four rewrites of the same table is what a hand-maintained ranking costs.

Why parsed and not imported: `import glaurung.llm.kb.provenance` pulls the
package `__init__`, which loads the compiled extension and pydantic
(`python -X importtime`: 1.56 s, and it fails outright on a tree that has not
been built). A documentation generator must run on a clean checkout, so this
reads the module as text with `ast` and evaluates only the two literals it
needs. The trade is real and small: a rank computed at runtime rather than
written as a literal would be invisible here, and `python/tests/`
`test_gen_provenance_reference.py` re-derives the value list a second way to
keep that honest.

The file has two halves. Everything above the `<!-- prose:start -->` marker is
regenerated from the source. Everything between the markers is hand-written and
is carried across regenerations unchanged, so the essay explaining *why* the
rungs sit where they do survives a renumbering.

Usage::

    uv run python tools/gen_provenance_reference.py            # write
    uv run python tools/gen_provenance_reference.py --check    # exit 1 if stale

Both the test and `--check` ignore the commit line in the header: the content
is a property of the source, not of when it was last regenerated.
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = Path("python/glaurung/llm/kb/provenance.py")
OUT = Path("docs/reference/provenance.md")

COMMIT_MARKER = "<!-- Commit:"
PROSE_START = "<!-- prose:start -->"
PROSE_END = "<!-- prose:end -->"

#: A short gloss per rung. Keyed on the RANK, not on the value, because the
#: ties are the point: three sources at 80 are one class of evidence on three
#: platforms, and saying so once is more honest than saying it three times.
RANK_GLOSS: dict[int, str] = {
    100: "the analyst typed it",
    80: "the toolchain's own statement about its output",
    60: "a curated bundle matched on an exact identifier",
    50: "a signature or metadata match",
    40: "carried from another build of the same function",
    30: "derived by our analysis from another recorded fact",
    20: "a heuristic, or a source this table does not know",
}

#: The seed used when the output file does not exist yet. The living copy is
#: whatever sits between the markers in `docs/reference/provenance.md`.
DEFAULT_PROSE = "*(prose section)*\n"


def _module() -> ast.Module:
    return ast.parse((ROOT / SOURCE).read_text())


def _assigned_literal(tree: ast.Module, name: str) -> object:
    """The value of a module-level ``NAME: Final[...] = <literal>``."""
    for node in tree.body:
        target = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target = node.target.id
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            first = node.targets[0]
            if isinstance(first, ast.Name):
                target = first.id
        if target != name or node.value is None:
            continue
        return ast.literal_eval(_inline_names(node.value, tree))
    raise SystemExit(f"{SOURCE}: no module-level assignment to {name}")


def _inline_names(node: ast.expr, tree: ast.Module) -> ast.expr:
    """Replace bare `NAME` references with the literal they were assigned.

    `SET_BY_PRIORITY` writes `AUTO_PRIORITY` for its three lowest rungs rather
    than repeating `20`, which is the right thing for the code and means the
    dict is not a bare literal. Only names already bound to an int constant
    earlier in the module are substituted; anything else stays and
    `literal_eval` rejects it, which is the failure we want.
    """
    constants = {
        node_.target.id: node_.value
        for node_ in tree.body
        if isinstance(node_, ast.AnnAssign)
        and isinstance(node_.target, ast.Name)
        and isinstance(node_.value, ast.Constant)
    }

    class _Inline(ast.NodeTransformer):
        def visit_Name(self, name: ast.Name) -> ast.expr:
            replacement = constants.get(name.id)
            return replacement if replacement is not None else name

    return ast.fix_missing_locations(_Inline().visit(node))


def _docstring_of(tree: ast.Module, function: str) -> str:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == function:
            return ast.get_docstring(node) or ""
    raise SystemExit(f"{SOURCE}: no function {function}")


def _first_sentence(text: str) -> str:
    """The docstring summary line, with reST literal markup flattened."""
    summary = text.strip().split("\n\n", 1)[0].replace("\n", " ")
    return " ".join(summary.replace("``", "`").split())


def existing_prose(path: Path) -> str:
    """The hand-written half of the document as it stands on disk."""
    if not path.exists():
        return DEFAULT_PROSE
    text = path.read_text()
    if PROSE_START not in text or PROSE_END not in text:
        return DEFAULT_PROSE
    body = text.split(PROSE_START, 1)[1].split(PROSE_END, 1)[0]
    return body.strip("\n") + "\n"


def commit(root: Path) -> str:
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


def generate(root: Path = ROOT) -> str:
    tree = _module()
    priority: dict[str, int] = dict(_assigned_literal(tree, "SET_BY_PRIORITY"))  # type: ignore[arg-type]
    auto = int(_assigned_literal(tree, "AUTO_PRIORITY"))  # type: ignore[call-overload]

    by_rank: dict[int, list[str]] = {}
    for value, rank in priority.items():
        by_rank.setdefault(rank, []).append(value)

    lines = [
        "# Provenance: the `set_by` ladder",
        "",
        "> **Kind:** reference · **Status:** generated",
        "",
        f"<!-- The table below is generated by tools/{Path(__file__).name}. -->",
        "<!-- Edit only between the prose markers; everything else is rewritten. -->",
        f"<!-- Source: {SOURCE} -->",
        f"{COMMIT_MARKER} {commit(root)} -->",
        "",
        "Every writable fact in a `.glaurung` project file — a function name, a",
        "data label, a comment, a stack variable, a type, a prototype — carries a",
        "`set_by` string naming where it came from. That string is ranked, and the",
        "rank decides whether a later write is allowed to replace an earlier one.",
        "",
        "## The ladder",
        "",
        f"{len(priority)} values across {len(by_rank)} ranks. Values on the same row hold the",
        "same rank on purpose; the gaps between ranks are left free so a new source",
        "can be added without moving an existing one.",
        "",
        "| rank | `set_by` | |",
        "|---:|---|---|",
    ]
    for rank in sorted(by_rank, reverse=True):
        values = ", ".join(f"`{value}`" for value in sorted(by_rank[rank]))
        lines.append(f"| {rank} | {values} | {RANK_GLOSS.get(rank, '')} |")

    outranks = _first_sentence(_docstring_of(tree, "outranks"))
    set_by_priority = _first_sentence(_docstring_of(tree, "set_by_priority"))

    lines += [
        "",
        "## Semantics",
        "",
        f"`outranks(new_set_by, existing_set_by)` — {outranks}",
        "",
        "It compares with `>=`, so **an equal rank replaces**. That is deliberate:",
        "a later `auto` pass must be able to improve on an earlier one, and an",
        "analyst must be able to correct their own earlier edit. The rule is about",
        "provenance rank, not immutability.",
        "",
        f"`set_by_priority(set_by)` — {set_by_priority}",
        "",
        f"An unrecognised or empty string therefore ranks at `{auto}`, the same rank",
        "as `auto` — neither zero nor the top. Ranking an unknown source lowest",
        "would let a typo be permanently outranked by everything; ranking it",
        "highest would let a typo clobber real debug information.",
        "",
        "The ranks are compared across versions of this code against rows written",
        "by older ones, so the numbers are frozen: renumbering a rung silently",
        "re-decides precedence questions already settled in shipped project files.",
        "",
        "## Who enforces it",
        "",
        "`outranks` is imported by `python/glaurung/llm/kb/xref_db.py` and",
        "`python/glaurung/llm/kb/type_db.py`, and every setter that writes a named",
        "fact calls it before the write. There is no caller-side bypass: the guard",
        "is inside the setter, not at the call site.",
        "",
        "```",
        "rg -n 'outranks\\(' python/glaurung/llm/kb/",
        "```",
        "",
        "`python/tests/test_kb_provenance_rank.py` pins the ranking and",
        "`python/tests/test_kb_manual_precedence.py` pins the top rung against",
        "every setter.",
        "",
        PROSE_START,
        "",
        existing_prose(root / OUT).rstrip("\n"),
        "",
        PROSE_END,
        "",
    ]
    return "\n".join(lines)


def without_commit(text: str) -> str:
    """The document minus its provenance line.

    The commit stamp records when the file was last regenerated, which is not
    a fact about the ladder. Comparing with it would make the check fail on
    every commit that did not touch `provenance.py`.
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
        print(f"run: uv run python tools/{Path(__file__).name}", file=sys.stderr)
        return 1

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    changed = existing is None or without_commit(existing) != without_commit(text)
    print(f"wrote {OUT} ({'changed' if changed else 'unchanged'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
