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
from typing import Optional

import glaurung as g
from glaurung.windows_config import load_windows_analysis_config

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat
from ..func_ref import (
    FuncResolutionError,
    parse_func_arg,
    resolve_func_to_va,
)


class DecompileCommand(BaseCommand):
    """Produce pseudocode for one or more discovered functions."""

    def get_name(self) -> str:
        return "decompile"

    def get_help(self) -> str:
        return "Decompile one or more functions to pseudocode"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to file")
        parser.add_argument(
            "--analysis-config",
            help=(
                "Optional Windows analysis config YAML/JSON. Defaults to "
                ".glaurung/windows-analysis.yaml or "
                "$GLAURUNG_WINDOWS_ANALYSIS_CONFIG when present."
            ),
        )
        parser.add_argument(
            "--func",
            dest="func",
            type=parse_func_arg,
            default=None,
            help="Function selector: hex VA (0x140001480), decimal, or a "
                 "function name like 'main' resolved against analysis. If "
                 "omitted, the detected entry point is used. Stripped "
                 "binaries only have sub_<VA> names so VA is preferred.",
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
            default=None,
            help="Per-function analysis timeout in milliseconds. Defaults to analysis config.",
        )
        parser.add_argument(
            "--max-blocks",
            type=int,
            default=None,
            help="Per-function max basic blocks. Defaults to analysis config.",
        )
        parser.add_argument(
            "--max-instructions",
            type=int,
            default=None,
            help="Per-function max instructions. Defaults to analysis config.",
        )
        parser.add_argument(
            "--range-start",
            type=lambda x: int(x, 0),
            default=None,
            help="Explicit function range start VA for range-seeded decompile.",
        )
        parser.add_argument(
            "--range-end",
            type=lambda x: int(x, 0),
            default=None,
            help="Explicit exclusive function range end VA for range-seeded decompile.",
        )
        parser.add_argument(
            "--style",
            choices=["plain", "c"],
            default="plain",
            help="Pseudocode style: 'plain' keeps the register-level detail "
                 "(default); 'c' strips the %% prefix and annotations for a "
                 "closer-to-C view.",
        )
        parser.add_argument(
            "--pdb-cache",
            default="",
            help="Optional Microsoft-style PDB cache directory used to resolve "
                 "PE/PDB public function names in decompile output.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        as_json = formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL)

        try:
            config = load_windows_analysis_config(args.analysis_config).with_overrides(
                max_blocks=args.max_blocks,
                max_instructions=args.max_instructions,
                timeout_ms=args.timeout_ms,
                pdb_cache_dir=args.pdb_cache or None,
            )
            timeout_ms = config.timeout_ms
            max_blocks = config.max_blocks
            max_instructions = config.max_instructions
            if args.all:
                results = g.ir.decompile_all(
                    str(path),
                    args.limit,
                    timeout_ms=timeout_ms,
                    pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
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
            func_va: Optional[int] = None
            if isinstance(args.func, int):
                func_va = args.func
            elif isinstance(args.func, str):
                # Name-resolution path. Run a bounded discovery pass so
                # the lookup terminates predictably on large binaries.
                try:
                    discovered = g.analysis.analyze_functions_path(
                        str(path), max_functions=2000,
                    )[0]
                except Exception as e:
                    formatter.output_plain(
                        f"Error: --func name resolution failed during analysis: {e}"
                    )
                    return 2
                try:
                    func_va = resolve_func_to_va(args.func, discovered)
                except FuncResolutionError as e:
                    formatter.output_plain(f"Error: {e}")
                    return 2
            else:
                got = g.analysis.detect_entry_path(str(path))
                if got is None:
                    formatter.output_plain(
                        "Error: could not detect entry point; pass --func 0xVA"
                    )
                    return 2
                func_va = int(got[3])

            try:
                style = "c" if args.style == "c" else ""
                if args.range_end is not None or args.range_start is not None:
                    range_start = args.range_start if args.range_start is not None else int(func_va)
                    if args.range_end is None:
                        formatter.output_plain("Error: --range-end is required with --range-start")
                        return 2
                    text = g.ir.decompile_range_at(
                        str(path),
                        int(func_va),
                        int(range_start),
                        int(args.range_end),
                        max_blocks=max_blocks,
                        max_instructions=max_instructions,
                        timeout_ms=timeout_ms,
                        types=args.types,
                        style=style,
                        pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
                    )
                else:
                    text = g.ir.decompile_at(
                        str(path),
                        int(func_va),
                        max_blocks=max_blocks,
                        max_instructions=max_instructions,
                        timeout_ms=timeout_ms,
                        types=args.types,
                        style=style,
                        pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
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
