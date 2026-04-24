"""Decompile command — render a function's lifted LLIR as C-like pseudocode.

Thin wrapper around the native ``glaurung.ir.decompile_at`` /
``glaurung.ir.decompile_all`` bindings. The full decompiler pipeline
(cfg discovery → LLIR lift → SSA → structural analysis → AST lowering →
expression reconstruction → DCE → name resolution → call-arg reconstruction)
runs inside the Rust extension; this command is just the CLI frontend.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

import glaurung as g

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


class DecompileCommand(BaseCommand):
    """Produce pseudocode for one or more discovered functions."""

    def get_name(self) -> str:
        return "decompile"

    def get_help(self) -> str:
        return "Decompile one or more functions to pseudocode"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to file")
        parser.add_argument(
            "--func",
            dest="func",
            type=lambda x: int(x, 0),
            default=None,
            help="Entry VA of the function to decompile (hex or decimal). "
                 "If omitted, the detected entry point is used.",
        )
        parser.add_argument(
            "--all",
            dest="all",
            action="store_true",
            help="Decompile up to --limit discovered functions instead of one.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=8,
            help="Max number of functions to decompile with --all (default: 8).",
        )
        parser.add_argument(
            "--no-types",
            dest="types",
            action="store_false",
            default=True,
            help="Disable type-annotation pass in the output.",
        )
        parser.add_argument(
            "--timeout-ms",
            type=int,
            default=500,
            help="Per-function analysis timeout in milliseconds (default: 500).",
        )
        parser.add_argument(
            "--style",
            choices=["plain", "c"],
            default="plain",
            help="Pseudocode style: 'plain' keeps the register-level detail "
                 "(default); 'c' strips the %% prefix and annotations for a "
                 "closer-to-C view.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        as_json = formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL)

        try:
            if args.all:
                results = g.ir.decompile_all(
                    str(path), args.limit, timeout_ms=args.timeout_ms
                )
                if as_json:
                    payload = [
                        {"name": name, "entry_va": int(va), "pseudocode": text}
                        for name, va, text in results
                    ]
                    print(json.dumps(payload, indent=2))
                else:
                    for name, va, text in results:
                        formatter.output_plain(text)
                return 0

            # Single-function mode.
            func_va: Optional[int] = args.func
            if func_va is None:
                got = g.analysis.detect_entry_path(str(path))
                if got is None:
                    formatter.output_plain(
                        "Error: could not detect entry point; pass --func 0xVA"
                    )
                    return 2
                func_va = int(got[3])

            try:
                style = "c" if args.style == "c" else ""
                text = g.ir.decompile_at(
                    str(path),
                    int(func_va),
                    timeout_ms=args.timeout_ms,
                    types=args.types,
                    style=style,
                )
            except ValueError as e:
                formatter.output_plain(f"Error: {e}")
                return 2

            if as_json:
                print(json.dumps({"entry_va": int(func_va), "pseudocode": text}, indent=2))
            else:
                formatter.output_plain(text)
            return 0
        except Exception as e:  # pragma: no cover - surfaces as CLI error
            formatter.output_plain(f"Error: {e}")
            return 1
