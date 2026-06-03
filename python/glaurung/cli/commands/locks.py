"""Lock / synchronization-state analysis subcommand.

Inventories acquire/release primitives (raw Ke*/Ex* AND RAII wrappers like
AcquireSpinLock::Acquire) for one function in a .glaurung project, resolves
the lock object each operates on, and reports a per-lock acquire/release
balance plus an honest coverage footer. See glaurung.llm.kb.lock_state.
"""
import argparse
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class LocksCommand(BaseCommand):
    def get_name(self) -> str:
        return "locks"

    def get_help(self) -> str:
        return ("Lock-state inventory for a function (primitive-complete, "
                "with a coverage footer)")

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", nargs="?", default=None,
                            help="Binary path (optional; resolved from --db if omitted)")
        parser.add_argument("--db", type=Path, required=True,
                            help=".glaurung project to read symbols from")
        parser.add_argument("--function", required=True, metavar="NAME|VA",
                            help="Function name (canonical/demangled) or VA")

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        from glaurung.llm.kb.lock_state import analyze_locks

        try:
            rep = analyze_locks(
                str(args.path) if args.path else None,
                db_path=str(args.db), function=args.function,
            )
        except (KeyError, FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        if formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            formatter.output_json(rep.to_dict())
            return 0
        formatter.output_plain(rep.render())
        return 0
