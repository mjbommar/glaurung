"""Triage command implementation."""

import argparse

import glaurung as g
from .base import BaseCommand
from ..formatters.triage import TriageFormatter


class TriageCommand(BaseCommand):
    """Command for triaging files."""

    def get_name(self) -> str:
        """Return the command name."""
        return "triage"

    def get_help(self) -> str:
        """Return the command help text."""
        return "Triage a file for security analysis"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-specific arguments."""
        parser.add_argument("path", help="Path to file")
        parser.add_argument(
            "--max-read-bytes",
            type=int,
            default=10_485_760,
            help="Max bytes to read (default: 10MB)",
        )
        parser.add_argument(
            "--max-file-size",
            type=int,
            default=104_857_600,
            help="Max file size (default: 100MB)",
        )
        parser.add_argument(
            "--max-depth",
            type=int,
            default=1,
            help="Max recursion depth for containers",
        )
        parser.add_argument(
            "--sim",
            dest="sim",
            action="store_true",
            default=True,
            help="Print similarity fields",
        )
        parser.add_argument(
            "--no-sim", dest="sim", action="store_false", help="Hide similarity fields"
        )

        # String analysis options
        parser.add_argument(
            "--str-min-len", type=int, default=4, help="Minimum string length"
        )
        parser.add_argument(
            "--str-max-samples", type=int, default=40, help="Max sampled strings"
        )
        parser.add_argument(
            "--str-lang",
            dest="str_lang",
            action="store_true",
            default=True,
            help="Enable language detection",
        )
        parser.add_argument(
            "--no-str-lang",
            dest="str_lang",
            action="store_false",
            help="Disable language detection",
        )
        parser.add_argument(
            "--str-max-lang-detect",
            type=int,
            default=100,
            help="Max strings to language-detect",
        )
        parser.add_argument(
            "--str-classify",
            dest="str_classify",
            action="store_true",
            default=True,
            help="Enable IOC classification",
        )
        parser.add_argument(
            "--no-str-classify",
            dest="str_classify",
            action="store_false",
            help="Disable IOC classification",
        )
        parser.add_argument(
            "--str-max-classify", type=int, default=200, help="Max strings to classify"
        )
        parser.add_argument(
            "--str-max-ioc-per-string",
            type=int,
            default=16,
            help="Max IOC matches counted per string",
        )
        parser.add_argument(
            "--tree",
            action="store_true",
            help="Show recursion tree of discovered children",
        )
        parser.add_argument(
            "--strings-only-lang",
            dest="strings_only_lang",
            action="store_true",
            help="Filter output to only strings with detected language (JSON/JSONL)",
        )

    def execute(self, args: argparse.Namespace, formatter: TriageFormatter) -> int:
        """Execute the triage command."""
        # Validate file path
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        # Perform triage analysis
        try:
            artifact = g.triage.analyze_path(
                str(path),
                args.max_read_bytes,
                args.max_file_size,
                args.max_depth,
                args.str_min_len,
                args.str_max_samples,
                args.str_lang,
                args.str_max_lang_detect,
                args.str_classify,
                args.str_max_classify,
                args.str_max_ioc_per_string,
            )
        except Exception as e:
            formatter.output_plain(f"Error during analysis: {e}")
            return 3

        # Attach display preference to formatter
        setattr(
            formatter, "strings_only_lang", getattr(args, "strings_only_lang", False)
        )

        # Format and output results
        formatter.format_output(artifact)

        return 0
