"""One-shot first-touch analysis CLI subcommand (#206)."""

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class KickoffCommand(BaseCommand):
    """Run the agent's canonical first-touch pipeline on a binary."""

    def get_name(self) -> str:
        return "kickoff"

    def get_help(self) -> str:
        return "One-shot analysis: detect-packer + triage + analyze + propagate + recover-structs"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to binary")
        parser.add_argument(
            "--db", type=Path, default=None,
            help=".glaurung project file to persist results into. "
                 "Defaults to a fresh tmp file.",
        )
        parser.add_argument(
            "--session", default="main",
            help="KB session name (default: main)",
        )
        parser.add_argument(
            "--max-functions", type=int, default=64,
            help="Cap on functions analysed for stack-frame / propagation / struct lifts.",
        )
        parser.add_argument(
            "--analyze-packed", action="store_true",
            help="Analyse a binary even when packer detection flags it. "
                 "Default: skip deep analysis on packed binaries.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        from glaurung.llm.kb.kickoff import kickoff_analysis, render_kickoff_markdown

        summary = kickoff_analysis(
            str(path),
            db_path=str(args.db) if args.db else None,
            session=args.session,
            max_functions_for_kb_lift=args.max_functions,
            skip_if_packed=not args.analyze_packed,
        )

        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(asdict(summary))
            return 0
        if formatter.format_type == OutputFormat.JSONL:
            formatter.output_jsonl(asdict(summary))
            return 0

        formatter.output_plain(render_kickoff_markdown(summary))
        # rc=0 always — kickoff is informational, not gating.
        return 0
