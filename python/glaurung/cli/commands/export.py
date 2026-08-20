"""KB export CLI subcommand (#165)."""

import argparse
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class ExportCommand(BaseCommand):
    """Dump a `.glaurung` project file as JSON / Markdown / C header."""

    def get_name(self) -> str:
        return "export"

    def get_help(self) -> str:
        return "Export a .glaurung project file as JSON / Markdown / C header"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("db", help="Path to .glaurung project file")
        parser.add_argument(
            "--output-format",
            choices=("json", "markdown", "header", "ida", "binja", "ghidra", "bundle"),
            default="markdown",
            help="Export shape (default: markdown). `json` is "
            "round-trippable; `header` emits the type DB as .h; "
            "`ida` / `binja` / `ghidra` emit scripts that apply "
            "the KB inside the respective tool; `bundle` is the whole-binary "
            "artifact — functions with their boundaries, prototypes, stack "
            "variables, xrefs and content-derived identity, and with "
            "--bodies their decompiled C.",
        )
        parser.add_argument(
            "--bodies",
            action="store_true",
            help="bundle only: decompile every function. Costs orders of "
            "magnitude more than the rest of the bundle combined, so it is "
            "off by default; requires --binary.",
        )
        parser.add_argument(
            "--binary",
            type=Path,
            default=None,
            help="Optional: binary path the KB was opened against. "
            "Required when the DB has multiple binaries.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        db_path = Path(args.db)
        if not db_path.exists():
            formatter.output_plain(f"Error: db not found: {db_path}")
            return 2

        from glaurung.llm.kb.export import (
            export_to_binja_script,
            export_to_c_header,
            export_to_ghidra_script,
            export_to_ida_script,
            export_to_json,
            export_to_markdown,
        )
        from glaurung.llm.kb.persistent import PersistentKnowledgeBase

        try:
            kb = PersistentKnowledgeBase.open(
                db_path,
                binary_path=args.binary,
            )
        except Exception as e:
            formatter.output_plain(f"Error opening db: {e}")
            return 3

        try:
            if args.output_format == "bundle":
                import json as _json

                from glaurung.llm.kb import bundle as _bundle

                formatter.output_plain(
                    _json.dumps(
                        _bundle.build(
                            kb,
                            binary_path=str(args.binary) if args.binary else None,
                            include_bodies=bool(args.bodies),
                        ),
                        indent=2,
                    )
                )
            elif args.output_format == "json":
                formatter.output_plain(export_to_json(kb))
            elif args.output_format == "header":
                formatter.output_plain(export_to_c_header(kb))
            elif args.output_format == "ida":
                formatter.output_plain(export_to_ida_script(kb))
            elif args.output_format == "binja":
                formatter.output_plain(export_to_binja_script(kb))
            elif args.output_format == "ghidra":
                formatter.output_plain(export_to_ghidra_script(kb))
            else:
                formatter.output_plain(export_to_markdown(kb))
        finally:
            kb.close()
        return 0
