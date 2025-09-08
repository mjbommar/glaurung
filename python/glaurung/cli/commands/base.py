"""Base command class for all CLI commands."""

import argparse
from abc import ABC, abstractmethod
from pathlib import Path

from ..formatters.base import OutputFormat, BaseFormatter


class BaseCommand(ABC):
    """Abstract base class for CLI commands."""

    def __init__(self):
        """Initialize the command."""
        self.name = self.get_name()
        self.help = self.get_help()

    @abstractmethod
    def get_name(self) -> str:
        """Return the command name."""
        pass

    @abstractmethod
    def get_help(self) -> str:
        """Return the command help text."""
        pass

    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-specific arguments to the parser."""
        pass

    @abstractmethod
    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        """Execute the command with the given arguments and formatter."""
        pass

    def setup_parser(self, subparsers) -> argparse.ArgumentParser:
        """Set up the command parser."""
        parser = subparsers.add_parser(self.name, help=self.help)

        # Add common arguments
        self.add_common_arguments(parser)

        # Add command-specific arguments
        self.add_arguments(parser)

        return parser

    def add_common_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add common arguments shared by all commands."""
        parser.add_argument(
            "--format",
            choices=["plain", "rich", "json", "jsonl"],
            default="plain",
            help="Output format (default: plain)",
        )
        # Back-compat alias for JSON
        parser.add_argument(
            "--json", action="store_true", help="Alias for --format json"
        )
        parser.add_argument(
            "--no-color",
            action="store_true",
            help="Disable colored output (forces plain format)",
        )
        parser.add_argument(
            "--quiet", "-q", action="store_true", help="Suppress non-essential output"
        )
        parser.add_argument(
            "--verbose", "-v", action="store_true", help="Enable verbose output"
        )

    def validate_file_path(self, path: str) -> Path:
        """Validate that a file path exists and is readable."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not p.is_file():
            raise ValueError(f"Not a file: {path}")
        return p

    def read_file_safely(self, path: Path, max_size: int = 104_857_600) -> bytes:
        """Safely read a file with size limit."""
        size = path.stat().st_size
        if size > max_size:
            raise ValueError(f"File too large: {size} bytes (max: {max_size})")
        return path.read_bytes()

    def get_output_format(self, args: argparse.Namespace) -> OutputFormat:
        """Determine the output format from arguments."""
        if getattr(args, "json", False):
            return OutputFormat.JSON
        if args.no_color:
            return OutputFormat.PLAIN
        try:
            return OutputFormat.from_string(args.format)
        except (ValueError, AttributeError):
            return OutputFormat.RICH
