"""Symbols command implementation."""

import argparse

import glaurung as g
from .base import BaseCommand
from ..formatters.symbols import SymbolsFormatter


class SymbolsCommand(BaseCommand):
    """Command for listing symbols from a binary."""

    def get_name(self) -> str:
        """Return the command name."""
        return "symbols"

    def get_help(self) -> str:
        """Return the command help text."""
        return "List symbols from a binary (best-effort)"

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
            "--filter",
            choices=["all", "dynamic", "imports", "exports", "libs"],
            help="Filter symbols by type",
        )
        parser.add_argument(
            "--search", type=str, help="Search for symbols containing this string"
        )
        parser.add_argument(
            "--limit", type=int, help="Limit number of symbols displayed"
        )

    def execute(self, args: argparse.Namespace, formatter: SymbolsFormatter) -> int:
        """Execute the symbols command."""
        # Validate file path
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        # Extract symbols
        try:
            # Try new native signature with size limits
            try:
                all_syms, dyn_syms, imports, exports, libs = g.triage.list_symbols(
                    str(path), args.max_read_bytes, args.max_file_size
                )
            except TypeError:
                # Fallback to older signature
                all_syms, dyn_syms, imports, exports, libs = g.triage.list_symbols(
                    str(path)
                )
        except AttributeError:
            formatter.output_plain(
                "Native module missing list_symbols; please rebuild."
            )
            return 2
        except Exception as e:
            formatter.output_plain(f"Error extracting symbols: {e}")
            return 3

        # Build data dictionary
        data = {
            "all": all_syms,
            "dynamic": dyn_syms,
            "imports": imports,
            "exports": exports,
            "libs": libs,
        }

        # Apply filters if specified
        if args.filter:
            filtered = {args.filter: data.get(args.filter, [])}
            data = filtered

        # Apply search if specified
        if args.search:
            search_lower = args.search.lower()
            for key in data:
                data[key] = [
                    sym for sym in data[key] if search_lower in str(sym).lower()
                ]

        # Apply limit if specified
        if args.limit:
            for key in data:
                data[key] = data[key][: args.limit]

        # Format and output results
        formatter.format_output(data)

        return 0
