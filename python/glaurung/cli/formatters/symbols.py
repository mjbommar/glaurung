"""Formatter for symbols command output."""

from typing import List, Tuple, Optional
from .base import BaseFormatter, OutputFormat


class SymbolsFormatter(BaseFormatter):
    """Formatter for symbols command output."""

    def format_output(self, data: dict) -> None:
        """Format and output symbols data."""
        if self.format_type == OutputFormat.JSON:
            self.output_json(data)
        elif self.format_type == OutputFormat.JSONL:
            # Output each symbol category as a separate line
            for category, symbols in data.items():
                self.output_jsonl({"type": category, "symbols": symbols})
        elif self.format_type == OutputFormat.RICH:
            self._format_rich(data)
        else:
            self._format_plain(data)

    def _format_rich(self, data: dict) -> None:
        """Format symbols using Rich."""
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        from rich.tree import Tree

        # Create a layout with all symbol categories
        total_symbols = sum(len(v) for v in data.values() if v)

        # Summary panel
        summary = Text()
        summary.append("📊 Symbol Analysis Summary\n", style="bold cyan")
        summary.append("Total Symbols: ", style="bold")
        summary.append(f"{total_symbols}\n")

        for category, symbols in data.items():
            if symbols:
                summary.append(f"  • {category.title()}: ", style="bold")
                summary.append(f"{len(symbols)}\n", style="yellow")

        self.console.print(
            Panel(
                summary,
                title="[bold blue]Symbol Overview[/bold blue]",
                border_style="blue",
            )
        )

        # Detailed tables for each category
        for category, symbols in data.items():
            if not symbols:
                continue

            # Style mapping for different categories
            styles = {
                "all": "cyan",
                "dynamic": "yellow",
                "imports": "green",
                "exports": "magenta",
                "libs": "blue",
            }

            style = styles.get(category, "white")

            # Create table for this category
            table = Table(
                title=f"[bold {style}]{category.title()} Symbols[/bold {style}]",
                show_header=True,
                header_style=f"bold {style}",
                show_lines=False,
                expand=False,
            )

            # Determine columns based on symbol type
            if category == "libs":
                table.add_column("Library", style=style)
            else:
                table.add_column(
                    "Symbol", style=style, overflow="ellipsis", max_width=60
                )

                # Add extra columns for detailed info if available
                if (
                    symbols
                    and isinstance(symbols[0], (tuple, list))
                    and len(symbols[0]) > 1
                ):
                    table.add_column("Address", style="dim yellow")
                    table.add_column("Type", style="dim cyan")

            # Add rows (limit to reasonable number for display)
            max_display = 50 if not self.console.is_terminal else 20

            for i, symbol in enumerate(symbols[:max_display]):
                if isinstance(symbol, (tuple, list)):
                    # Handle structured symbol data
                    table.add_row(*[str(s) for s in symbol])
                else:
                    # Simple string symbol
                    table.add_row(str(symbol))

            if len(symbols) > max_display:
                table.add_row(f"[dim]... and {len(symbols) - max_display} more[/dim]")

            self.console.print(table)
            self.console.print()  # Space between tables

        # Show import dependencies tree if libraries are present
        libs = data.get("libs", [])
        if libs:
            tree = Tree("[bold blue]📚 Library Dependencies[/bold blue]")
            for lib in libs:
                tree.add(f"[cyan]{lib}[/cyan]")
            self.console.print(tree)

    def _format_plain(self, data: dict) -> None:
        """Format symbols as plain text."""
        lines = []

        for category, symbols in data.items():
            if not symbols:
                continue

            lines.append(f"{category}: {len(symbols)}")
            for symbol in symbols:
                if isinstance(symbol, (tuple, list)):
                    lines.append(f"  {' '.join(str(s) for s in symbol)}")
                else:
                    lines.append(f"  {symbol}")

        self.output_plain("\n".join(lines))


class SymbolTableFormatter(BaseFormatter):
    """Advanced formatter for symbol tables with filtering and grouping."""

    def __init__(self, format_type: OutputFormat = OutputFormat.PLAIN):
        """Initialize with format type."""
        super().__init__(format_type)
        self.filters = {}
        self.group_by = None

    def set_filters(self, **filters):
        """Set filters for symbol display."""
        self.filters = filters

    def set_grouping(self, group_by: Optional[str]):
        """Set grouping for symbol display."""
        self.group_by = group_by

    def format_symbol_table(self, symbols: List[Tuple], headers: List[str]) -> None:
        """Format a detailed symbol table."""
        if self.format_type == OutputFormat.RICH:
            from rich.table import Table

            table = Table(title="[bold cyan]Symbol Table[/bold cyan]", show_header=True)

            for header in headers:
                table.add_column(header, style="cyan" if header == "Name" else "yellow")

            for symbol in symbols:
                # Apply filters if set
                if self._should_display(symbol):
                    table.add_row(*[str(s) for s in symbol])

            self.console.print(table)
        else:
            # Plain text format
            lines = []
            lines.append("\t".join(headers))
            lines.append("-" * 80)

            for symbol in symbols:
                if self._should_display(symbol):
                    lines.append("\t".join(str(s) for s in symbol))

            self.output_plain("\n".join(lines))

    def _should_display(self, symbol: Tuple) -> bool:
        """Check if symbol passes filters."""
        # Implement filtering logic based on self.filters
        return True  # For now, show all
