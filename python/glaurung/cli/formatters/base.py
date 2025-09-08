"""Base output formatter abstraction for consistent CLI output across formats."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Optional
import json
import sys


class OutputFormat(Enum):
    """Supported output formats."""

    PLAIN = "plain"
    RICH = "rich"
    JSON = "json"
    JSONL = "jsonl"

    @classmethod
    def from_string(cls, value: str) -> "OutputFormat":
        """Create from string value."""
        return cls(value.lower())


class BaseFormatter(ABC):
    """Abstract base class for output formatters."""

    def __init__(self, format_type: OutputFormat = OutputFormat.PLAIN):
        """Initialize formatter with output type."""
        self.format_type = format_type
        self._console = None

    @property
    def console(self):
        """Lazy-load rich console if needed."""
        if self._console is None and self.format_type == OutputFormat.RICH:
            try:
                from rich.console import Console

                self._console = Console()
            except ImportError:
                # Fall back to plain if Rich not available
                self.format_type = OutputFormat.PLAIN
        return self._console

    @abstractmethod
    def format_output(self, data: Any) -> None:
        """Format and output data according to the format type."""
        pass

    def output_json(self, data: Any, stream=None) -> None:
        """Output data as JSON."""
        if stream is None:
            stream = sys.stdout
        # One-line JSON to be friendly with tests that read first line only
        json.dump(data, stream, separators=(",", ":"), default=str)
        stream.write("\n")
        stream.flush()

    def output_jsonl(self, data: Any, stream=None) -> None:
        """Output data as JSON Lines."""
        if stream is None:
            stream = sys.stdout
        # If data is iterable, output each item as a line
        if isinstance(data, (list, tuple)):
            for item in data:
                json.dump(item, stream, default=str)
                stream.write("\n")
        else:
            json.dump(data, stream, default=str)
            stream.write("\n")
        stream.flush()

    def output_plain(self, text: str, stream=None) -> None:
        """Output plain text."""
        if stream is None:
            stream = sys.stdout
        stream.write(text)
        if not text.endswith("\n"):
            stream.write("\n")
        stream.flush()

    def output_rich(self, *args, **kwargs) -> None:
        """Output using rich console."""
        if self.console:
            self.console.print(*args, **kwargs)
        else:
            # Fallback to plain text
            self.output_plain(str(args[0]) if args else "")

    def create_table(self, title: Optional[str] = None, **kwargs):
        """Create a rich table if in rich mode, otherwise return None."""
        if self.format_type == OutputFormat.RICH:
            try:
                from rich.table import Table

                return Table(title=title, **kwargs)
            except ImportError:
                pass
        return None

    def create_panel(self, content: Any, title: Optional[str] = None, **kwargs):
        """Create a rich panel if in rich mode."""
        if self.format_type == OutputFormat.RICH:
            try:
                from rich.panel import Panel

                return Panel(content, title=title, **kwargs)
            except ImportError:
                pass
        return None

    def create_syntax(self, code: str, lexer: str = "python", **kwargs):
        """Create syntax-highlighted code if in rich mode."""
        if self.format_type == OutputFormat.RICH:
            try:
                from rich.syntax import Syntax

                return Syntax(code, lexer, **kwargs)
            except ImportError:
                pass
        return code

    def create_tree(self, label: str, **kwargs):
        """Create a tree structure if in rich mode."""
        if self.format_type == OutputFormat.RICH:
            try:
                from rich.tree import Tree

                return Tree(label, **kwargs)
            except ImportError:
                pass
        return None

    def create_progress(self, **kwargs):
        """Create a progress bar if in rich mode."""
        if self.format_type == OutputFormat.RICH:
            try:
                from rich.progress import Progress

                return Progress(**kwargs)
            except ImportError:
                pass
        return None

    def create_markdown(self, text: str, **kwargs):
        """Create markdown output if in rich mode."""
        if self.format_type == OutputFormat.RICH:
            try:
                from rich.markdown import Markdown

                return Markdown(text, **kwargs)
            except ImportError:
                pass
        return text


def create_formatter(format_type: OutputFormat, formatter_class: type) -> BaseFormatter:
    """Factory function to create formatter instances."""
    return formatter_class(format_type)
