"""Binary patch CLI subcommand (#185)."""

import argparse
from dataclasses import asdict
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class PatchCommand(BaseCommand):
    """Write hex bytes at a given VA, producing a new binary file."""

    def get_name(self) -> str:
        return "patch"

    def get_help(self) -> str:
        return "Patch hex bytes at a VA to produce a new binary"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("input", help="Source binary")
        parser.add_argument("output", help="Output binary path")
        parser.add_argument(
            "--va", required=True,
            help="Virtual address to patch (hex with 0x or decimal)",
        )
        parser.add_argument(
            "--bytes", required=True, dest="payload",
            help='Hex byte payload, e.g. "90 90 90" or "488b45f8"',
        )
        parser.add_argument(
            "--force", action="store_true",
            help="Overwrite output if it exists",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            self.validate_file_path(args.input)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        try:
            va = int(args.va, 0)
        except ValueError:
            formatter.output_plain(f"Error: bad --va: {args.va!r}")
            return 2

        from glaurung.llm.kb.patch import patch_at_va, render_patch_markdown

        try:
            result = patch_at_va(
                str(args.input), str(args.output), va, args.payload,
                overwrite_output=args.force,
            )
        except FileExistsError as e:
            formatter.output_plain(f"Error: {e}")
            return 3
        except (FileNotFoundError, ValueError, RuntimeError) as e:
            formatter.output_plain(f"Error: {e}")
            return 4

        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(asdict(result))
            return 0
        formatter.output_plain(render_patch_markdown(result, input_path=args.input))
        return 0
