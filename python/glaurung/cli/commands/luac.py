"""Lua bytecode triage CLI subcommand (#211).

`glaurung luac <path>` parses a `.luac` (or LuaJIT) file and prints
its engine kind, format byte, and source filename if recoverable
from the embedded debug info.
"""

import argparse
import json
from pathlib import Path

import glaurung as g

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class LuacCommand(BaseCommand):
    """Inspect a Lua bytecode file."""

    def get_name(self) -> str:
        return "luac"

    def get_help(self) -> str:
        return "Recognise Lua bytecode (.luac / LuaJIT) and surface header info"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to .luac or LuaJIT bytecode")

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        path = Path(args.path)
        if not path.exists():
            formatter.output_plain(f"Error: not found: {path}")
            return 2
        info = g.analysis.parse_lua_bytecode_path(str(path))
        if info is None:
            formatter.output_plain(f"Error: not Lua bytecode: {path}")
            return 4
        if formatter.format_type == OutputFormat.JSON:
            formatter.output_json(info)
            return 0
        formatter.output_plain(f"engine: {info['kind']}")
        formatter.output_plain(f"format: {info['format']}")
        if info.get("source"):
            formatter.output_plain(f"source: {info['source']}")
        else:
            formatter.output_plain("source: (stripped)")
        return 0
