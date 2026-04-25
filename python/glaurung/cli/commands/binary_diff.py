"""Function-level binary diff CLI subcommand (#184)."""

import argparse
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class BinaryDiffCommand(BaseCommand):
    """Pair-wise function-level diff of two binaries."""

    def get_name(self) -> str:
        return "diff"

    def get_help(self) -> str:
        return "Diff two binaries function-by-function"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("binary_a", help="First binary (\"before\")")
        parser.add_argument("binary_b", help="Second binary (\"after\")")
        parser.add_argument(
            "--include-anonymous", action="store_true",
            help="Include `sub_<hex>` placeholder functions in the diff. "
                 "Off by default — their VAs shift between builds and "
                 "the resulting noise dominates real changes.",
        )
        parser.add_argument(
            "--max-rows", type=int, default=64,
            help="Cap on changed-function rows shown in Markdown output.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        from glaurung.llm.kb.binary_diff import diff_binaries, render_diff_markdown, to_json

        a, b = Path(args.binary_a), Path(args.binary_b)
        if not a.exists():
            formatter.output_plain(f"Error: binary a not found: {a}")
            return 2
        if not b.exists():
            formatter.output_plain(f"Error: binary b not found: {b}")
            return 2

        diff = diff_binaries(
            str(a), str(b),
            skip_anonymous=not args.include_anonymous,
        )

        if formatter.format_type == OutputFormat.JSON:
            formatter.output_plain(to_json(diff))
            return 0
        # Plain / rich.
        formatter.output_plain(render_diff_markdown(diff, max_rows=args.max_rows))
        # rc = 0 when binaries are identical (zero changes), else 1.
        return 0 if (diff.changed + diff.added + diff.removed) == 0 else 1
