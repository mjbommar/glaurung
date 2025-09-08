"""Dedicated strings analysis command."""

import argparse
from dataclasses import dataclass

import glaurung as g

from .base import BaseCommand
from ..formatters.strings import StringsFormatter


@dataclass
class StringsDisplayOptions:
    show_raw: bool = True
    raw_limit: int = 2000
    raw_width: int = 160
    compute_entropy: bool = True
    entropy_bins: int = 8
    truncate_json_strings: bool = False


class StringsCommand(BaseCommand):
    """Analyze strings comprehensively with stats and distributions."""

    def get_name(self) -> str:
        return "strings"

    def get_help(self) -> str:
        return "Detailed string extraction, stats, and distributions"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to file")

        # Control extraction via triage parameters (bounded by native capabilities)
        parser.add_argument(
            "--min-len", type=int, default=4, help="Minimum string length"
        )
        parser.add_argument(
            "--max-samples",
            type=int,
            default=10_000,
            help="Maximum sampled strings per encoding",
        )
        parser.add_argument(
            "--lang",
            dest="lang",
            action="store_true",
            default=True,
            help="Enable language/script detection",
        )
        parser.add_argument(
            "--no-lang",
            dest="lang",
            action="store_false",
            help="Disable language detection",
        )
        parser.add_argument(
            "--max-lang-detect",
            type=int,
            default=10_000,
            help="Max strings to attempt language detection on",
        )

        # IOC classification: on by default for comprehensive analysis
        parser.add_argument(
            "--classify",
            dest="classify",
            action="store_true",
            default=True,
            help="Enable IOC classification for strings",
        )
        parser.add_argument(
            "--max-classify",
            type=int,
            default=500,
            help="Max strings to classify for IOCs (if enabled)",
        )
        parser.add_argument(
            "--max-ioc-per-string",
            type=int,
            default=16,
            help="Max IOC matches counted per string",
        )

        # Display controls
        parser.add_argument(
            "--no-raw",
            dest="show_raw",
            action="store_false",
            help="Hide raw string list",
        )
        parser.add_argument(
            "--raw-limit",
            type=int,
            default=2000,
            help="Maximum number of strings to display in raw list",
        )
        parser.add_argument(
            "--raw-width",
            type=int,
            default=160,
            help="Maximum characters per string row in raw list",
        )
        parser.add_argument(
            "--entropy",
            dest="entropy",
            action="store_true",
            default=True,
            help="Compute per-string entropy and histogram",
        )
        parser.add_argument(
            "--no-entropy",
            dest="entropy",
            action="store_false",
            help="Skip per-string entropy calculations",
        )
        parser.add_argument(
            "--entropy-bins",
            type=int,
            default=8,
            help="Number of entropy bins (0..8 by default)",
        )
        parser.add_argument(
            "--truncate-json-strings",
            action="store_true",
            help="Truncate string text in JSON output to raw-width",
        )
        parser.add_argument(
            "--only-lang",
            dest="only_lang",
            action="store_true",
            default=False,
            help="Show only strings with detected language",
        )

    def execute(self, args: argparse.Namespace, formatter: StringsFormatter) -> int:
        # Validate file path
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        # Run triage with generous string budgets
        try:
            artifact = g.triage.analyze_path(
                str(path),
                10_485_760,  # max_read_bytes
                104_857_600,  # max_file_size
                1,  # max_depth
                args.min_len,
                args.max_samples,
                args.lang,
                args.max_lang_detect,
                args.classify,
                args.max_classify,
                args.max_ioc_per_string,
            )
        except TypeError:
            artifact = g.triage.analyze_path(str(path), 10_485_760, 104_857_600, 1)
        except Exception as e:
            formatter.output_plain(f"Error during analysis: {e}")
            return 3

        # Build display options bundle for formatter
        opts = StringsDisplayOptions(
            show_raw=getattr(args, "show_raw", True),
            raw_limit=args.raw_limit,
            raw_width=args.raw_width,
            compute_entropy=getattr(args, "entropy", True),
            entropy_bins=args.entropy_bins,
            truncate_json_strings=args.truncate_json_strings,
        )
        # Attach filter preference onto formatter for display logic
        setattr(formatter, "only_lang", getattr(args, "only_lang", False))

        # Pass both artifact and options to formatter
        formatter.format_output({"artifact": artifact, "options": opts})
        return 0
