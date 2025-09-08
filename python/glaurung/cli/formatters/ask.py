"""Formatter for natural language Q&A output."""

import json
import sys
from typing import Any, Dict

from .base import BaseFormatter, OutputFormat


class AskFormatter(BaseFormatter):
    """Formatter for ask command output."""

    def format_output(self, data: Any) -> None:
        """Format and output Q&A results according to the format type."""
        if self.format_type == OutputFormat.JSON:
            self.output_json(data)
        elif self.format_type == OutputFormat.JSONL:
            self._output_jsonl_results(data)
        elif self.format_type == OutputFormat.RICH:
            self._output_rich(data)
        else:
            self._output_plain(data)

    def format_error(self, message: str) -> None:
        """Format an error message."""
        if self.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            self.output_json({"error": message}, stream=sys.stderr)
        elif self.format_type == OutputFormat.RICH:
            if self.console:
                # Rich console doesn't support 'file' parameter directly
                from rich.console import Console

                err_console = Console(stderr=True)
                err_console.print(f"[red]❌ Error:[/red] {message}")
            else:
                print(f"Error: {message}", file=sys.stderr)
        else:
            print(f"Error: {message}", file=sys.stderr)

    def format_progress(self, message: str) -> None:
        """Format a progress message."""
        if self.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            # Don't output progress in JSON modes
            return
        elif self.format_type == OutputFormat.RICH:
            if self.console:
                # Rich console doesn't support 'file' parameter directly
                from rich.console import Console

                err_console = Console(stderr=True)
                err_console.print(f"[dim]⏳ {message}[/dim]")
            else:
                print(f"... {message}", file=sys.stderr)
        else:
            print(f"... {message}", file=sys.stderr)

    def format_info(self, message: str) -> None:
        """Format an info message."""
        if self.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            # Don't output info in JSON modes
            return
        elif self.format_type == OutputFormat.RICH:
            if self.console:
                self.console.print(f"[blue]ℹ️  {message}[/blue]")
            else:
                print(f"Info: {message}")
        else:
            print(f"Info: {message}")

    def format_answer(self, answer: str) -> None:
        """Format an answer for interactive mode."""
        if self.format_type == OutputFormat.RICH:
            if self.console:
                self.console.print(f"[green]💬 Answer:[/green] {answer}")
            else:
                print(f"Answer: {answer}")
        else:
            print(f"Answer: {answer}")

    def _output_plain(self, data: Dict[str, Any]) -> None:
        """Output results in plain text format."""
        results = data.get("results", [])
        show_tools = data.get("show_tools", False)
        show_plan = data.get("show_plan", False)

        for i, result in enumerate(results, 1):
            if len(results) > 1:
                print(f"\n{'=' * 60}")
                print(f"Question {i}: {result['question']}")
                print(f"{'=' * 60}")
            else:
                print(f"Question: {result['question']}")
                print("-" * 60)

            # Show planning/reasoning if requested
            if show_plan and result.get("reasoning"):
                print("\nPlanning:")
                print(result["reasoning"])
                print("-" * 40)

            # Show tool calls if requested
            if show_tools and result.get("tool_calls"):
                print("\nTool Calls:")
                for j, tool in enumerate(result["tool_calls"], 1):
                    print(f"  {j}. {tool['tool']}({tool.get('args', {})})")
                    if tool.get("result"):
                        print(f"     Result: {tool['result']}")
                print("-" * 40)

            # Show answer
            print("\nAnswer:")
            print(result["answer"])

    def _output_rich(self, data: Dict[str, Any]) -> None:
        """Output results in rich format with colors and formatting."""
        if not self.console:
            # Fallback to plain if Rich not available
            self._output_plain(data)
            return

        from rich.panel import Panel
        from rich.table import Table
        from rich.markdown import Markdown

        results = data.get("results", [])
        show_tools = data.get("show_tools", False)
        show_plan = data.get("show_plan", False)
        binary = data.get("binary", "unknown")

        # Header
        self.console.print(
            Panel(
                f"[bold]Binary Analysis Q&A[/bold]\n"
                f"[dim]File: {binary}[/dim]\n"
                f"[dim]Questions: {len(results)}[/dim]",
                title="🔍 Glaurung Ask",
                border_style="blue",
            )
        )

        # Process each result
        for i, result in enumerate(results, 1):
            self.console.print()

            # Question panel
            self.console.print(
                Panel(
                    result["question"],
                    title=f"❓ Question {i}/{len(results)}",
                    border_style="cyan",
                )
            )

            # Planning/reasoning if requested
            if show_plan and result.get("reasoning"):
                self.console.print(
                    Panel(
                        result["reasoning"],
                        title="🧠 Planning",
                        border_style="dim",
                        style="dim",
                    )
                )

            # Tool calls if requested
            if show_tools and result.get("tool_calls"):
                table = Table(title="🔧 Tool Calls", show_header=True)
                table.add_column("Tool", style="yellow")
                table.add_column("Arguments", style="dim")
                table.add_column("Result", style="green")

                for tool in result["tool_calls"]:
                    # Format arguments
                    args = tool.get("args", {})
                    if isinstance(args, dict) and args:
                        args_str = json.dumps(args, indent=2)
                    elif isinstance(args, str):
                        args_str = args
                    else:
                        args_str = "{}"

                    # Format result
                    tool_result = tool.get("result")
                    if tool_result is None:
                        result_str = "None"
                    elif isinstance(tool_result, (list, dict)):
                        # Try to format as JSON for readability
                        try:
                            result_str = json.dumps(tool_result, indent=2)
                            if len(result_str) > 200:
                                # Truncate but keep structure visible
                                if isinstance(tool_result, list):
                                    result_str = f"[{len(tool_result)} items]"
                                else:
                                    result_str = f"{{...{len(tool_result)} keys...}}"
                        except:
                            result_str = str(tool_result)[:100] + "..."
                    else:
                        result_str = str(tool_result)
                        if len(result_str) > 100:
                            result_str = result_str[:100] + "..."

                    table.add_row(tool["tool"], args_str, result_str)

                self.console.print(table)

            # Answer panel
            self.console.print(
                Panel(
                    Markdown(result["answer"]), title="💬 Answer", border_style="green"
                )
            )

    def _output_jsonl_results(self, data: Dict[str, Any]) -> None:
        """Output results in JSONL format (one result per line)."""
        results = data.get("results", [])
        binary = data.get("binary", "unknown")

        for result in results:
            # Add binary path to each result
            result["binary"] = binary
            # Output as a single line of JSON
            self.output_jsonl(result)
