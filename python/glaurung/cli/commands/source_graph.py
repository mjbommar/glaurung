"""Export C source graphs: `glaurung source-graph`.

The replacement for `joern-export --repr {ast,cfg} --format {dot,graphml,...}`,
without the JVM. Joern also offers `cdg`, `ddg` and `pdg`; those need a
data-dependence analysis this front end does not do, so they are absent rather
than stubbed -- a `--repr ddg` that returned a control-flow graph would be worse
than an error.

Two output modes, because the two uses want different things:

* **stdout**, one graph after another with a comment naming each, for piping a
  single function into `dot` or reading it;
* **a directory** (`-o`), one file per function, which is what
  `joern-export` does and what a batch consumer expects.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

import glaurung as g

from .base import BaseCommand
from ..formatters.base import BaseFormatter

#: Comment syntax per format, for the header written above each graph on
#: stdout. Mermaid's `%%` and DOT's `//` are both line comments; GraphML and
#: JSON have no comment syntax, so those get no header and `--out` is the way
#: to keep them separable.
_COMMENT = {"dot": "//", "mermaid": "%%"}


class SourceGraphCommand(BaseCommand):
    """Export the syntax tree or control-flow graph of C source."""

    def get_name(self) -> str:
        """Return the command name."""
        return "source-graph"

    def get_help(self) -> str:
        """Return the command help text."""
        return "Export C source graphs: AST or CFG as DOT, GraphML, JSON, Mermaid"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-specific arguments."""
        parser.add_argument(
            "paths",
            nargs="+",
            help="C files, or directories to search for *.c and *.h",
        )
        parser.add_argument(
            "--repr",
            choices=list(g.source.EXPORT_REPRS),
            default="cfg",
            help=(
                "Graph to export: 'cfg' is the general control-flow graph, "
                "never the Joern-parity one; 'ast' is the syntax tree "
                "(default: cfg)"
            ),
        )
        # Not `--format`, which every command already carries for the CLI's
        # own output shape (plain/rich/json/jsonl). Two flags with one name is
        # an argparse conflict, and two meanings for `json` would be worse.
        parser.add_argument(
            "--graph-format",
            choices=list(g.source.EXPORT_FORMATS),
            default="dot",
            help=(
                "Wire format for the graph itself, distinct from --format. "
                "'json' is node-link JSON NetworkX reads; 'mermaid' renders in "
                "Markdown without Graphviz (default: dot)"
            ),
        )
        parser.add_argument(
            "--func",
            metavar="NAME",
            default=None,
            help="Export only the function with this name",
        )
        parser.add_argument(
            "-o",
            "--out",
            metavar="DIR",
            default=None,
            help=(
                "Write one file per function into DIR instead of to stdout. "
                "The directory is created if absent"
            ),
        )
        parser.add_argument(
            "--dialect",
            choices=["preprocessed", "decompiled"],
            default=None,
            help=(
                "Normalize before parsing: 'preprocessed' for a gcc .i unit, "
                "'decompiled' for a decompiler's output. Note that "
                "'preprocessed' strips everything not under a user-file line "
                "marker, so it empties an ordinary .c file"
            ),
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        """Export every named file's graphs."""
        paths = _expand(args.paths)
        if not paths:
            formatter.output_plain("Error: no C source files found")
            return 2

        out_dir = Path(args.out) if args.out else None
        if out_dir is not None:
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
            except OSError as error:
                formatter.output_plain(f"Error: {args.out}: {error}", stream=sys.stderr)
                return 2

        written = 0
        for path in paths:
            try:
                graphs = g.source.export_path(
                    path, repr=args.repr, format=args.graph_format, dialect=args.dialect
                )
            except OSError as error:
                # Unreadable file: report it and keep going. One bad path must
                # not void a tree-wide run.
                formatter.output_plain(f"Error: {path}: {error}", stream=sys.stderr)
                continue

            for index, (name, body) in enumerate(graphs):
                if args.func is not None and name != args.func:
                    continue
                if out_dir is None:
                    _emit_stdout(path, name, body, args.graph_format)
                else:
                    _emit_file(out_dir, path, name, index, body, args.graph_format)
                written += 1

        if written == 0:
            what = f"function {args.func!r}" if args.func else "function"
            formatter.output_plain(f"Error: no {what} to export", stream=sys.stderr)
            return 1
        if out_dir is not None:
            formatter.output_plain(f"{written} graph(s) written to {out_dir}")
        return 0


def _emit_stdout(path: Path, name: str, body: str, format_name: str) -> None:
    """Print one graph, with a header when the format has a comment syntax."""
    comment = _COMMENT.get(format_name)
    if comment:
        print(f"{comment} {path}: {name or '<unnamed>'}")
    print(body, end="" if body.endswith("\n") else "\n")


def _emit_file(
    out_dir: Path, path: Path, name: str, index: int, body: str, format_name: str
) -> None:
    """Write one graph to `out_dir`, named for its file and function.

    The index is part of the stem because two definitions in one file can carry
    the same name after recovery, and the second must not overwrite the first.
    """
    extension = {"dot": "dot", "graphml": "graphml", "json": "json", "mermaid": "mmd"}[
        format_name
    ]
    safe_name = _slug(name) or "unnamed"
    stem = f"{_slug(path.stem)}-{index:03d}-{safe_name}"
    (out_dir / f"{stem}.{extension}").write_text(body, encoding="utf-8")


def _slug(text: str) -> str:
    """Reduce `text` to characters that are safe in a file name."""
    return "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in text)


def _expand(paths: Iterable[str]) -> list[Path]:
    """Every C file named, with directories searched recursively.

    Returns paths sorted, so a run over a tree is reproducible and two runs can
    be diffed.
    """
    found: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            found.extend(p for p in path.rglob("*.c") if p.is_file())
            found.extend(p for p in path.rglob("*.h") if p.is_file())
        elif path.is_file():
            found.append(path)
    return sorted(set(found))
