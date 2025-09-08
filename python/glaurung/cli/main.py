"""Main CLI entry point with modular command structure."""

import argparse
import sys
from typing import List, Optional

from .commands.triage import TriageCommand
from .commands.symbols import SymbolsCommand
from .commands.disasm import DisasmCommand
from .commands.cfg import CFGCommand
from .commands.ask import AskCommand
from .commands.strings import StringsCommand

from .formatters import (
    TriageFormatter,
    SymbolsFormatter,
    DisasmFormatter,
    CFGFormatter,
)
from .formatters.ask import AskFormatter
from .formatters.strings import StringsFormatter


class GlaurungCLI:
    """Main CLI application."""

    def __init__(self):
        """Initialize the CLI with available commands."""
        self.commands = {
            "triage": TriageCommand(),
            "strings": StringsCommand(),
            "symbols": SymbolsCommand(),
            "disasm": DisasmCommand(),
            "cfg": CFGCommand(),
            "ask": AskCommand(),
        }

        # Map commands to their formatters
        self.formatter_map = {
            "triage": TriageFormatter,
            "strings": StringsFormatter,
            "symbols": SymbolsFormatter,
            "disasm": DisasmFormatter,
            "cfg": CFGFormatter,
            "ask": AskFormatter,
        }

    def create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            prog="glaurung", description="Glaurung binary analysis CLI"
        )

        # Add global arguments
        parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

        # Create subparsers for commands
        subparsers = parser.add_subparsers(
            dest="cmd", required=True, help="Available commands"
        )

        # Setup each command's parser
        for cmd_name, cmd in self.commands.items():
            cmd.setup_parser(subparsers)

        return parser

    def run(self, argv: Optional[List[str]] = None) -> int:
        """Run the CLI application."""
        parser = self.create_parser()
        args = parser.parse_args(argv)

        # Get the command
        command = self.commands.get(args.cmd)
        if not command:
            print(f"Unknown command: {args.cmd}", file=sys.stderr)
            return 1

        # Determine output format
        output_format = command.get_output_format(args)

        # Create the appropriate formatter
        formatter_class = self.formatter_map.get(args.cmd)
        if not formatter_class:
            print(f"No formatter for command: {args.cmd}", file=sys.stderr)
            return 1

        formatter = formatter_class(output_format)

        # Execute the command
        try:
            return command.execute(args, formatter)
        except KeyboardInterrupt:
            print("\nInterrupted by user", file=sys.stderr)
            return 130
        except Exception as e:
            if args.verbose:
                import traceback

                traceback.print_exc()
            else:
                print(f"Error: {e}", file=sys.stderr)
            return 1


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI."""
    cli = GlaurungCLI()
    return cli.run(argv)


if __name__ == "__main__":
    sys.exit(main())
