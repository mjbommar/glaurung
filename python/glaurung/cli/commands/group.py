"""Cross-binary module-group analysis subcommand.

Reports pool tags shared across a driver family (the cross-module
corruption surface). See glaurung.llm.kb.module_group.
"""
import argparse
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class GroupCommand(BaseCommand):
    def get_name(self) -> str:
        return "group"

    def get_help(self) -> str:
        return "Cross-binary module-group analysis (shared pool tags)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--member", action="append", required=True, metavar="NAME=BINARY",
            help="A group member as name=path/to/driver.sys (repeatable, >=2)",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        from glaurung.llm.kb.module_group import ModuleGroup

        named = []
        for spec in args.member:
            if "=" in spec:
                name, _, path = spec.partition("=")
            else:
                name, path = Path(spec).name, spec
            if not Path(path).is_file():
                formatter.output_plain(f"Error: not a file: {path}")
                return 2
            named.append((name, path))
        if len(named) < 2:
            formatter.output_plain("Error: need >=2 members to compare")
            return 2

        grp = ModuleGroup.from_binaries(named)
        if formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            formatter.output_json(grp.to_dict())
            return 0
        formatter.output_plain(grp.render())
        return 0
