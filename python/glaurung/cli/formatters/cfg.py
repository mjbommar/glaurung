"""Formatter for CFG command output."""

from typing import List, Dict, Any
from .base import BaseFormatter, OutputFormat
from ..utils.formatting import format_hex, format_confidence, format_risk_level


class CFGFormatter(BaseFormatter):
    """Formatter for Control Flow Graph analysis output."""

    def format_output(self, data: Dict[str, Any]) -> None:
        """Format and output CFG data."""
        if self.format_type == OutputFormat.JSON:
            self.output_json(data)
        elif self.format_type == OutputFormat.JSONL:
            # Output functions and analysis as separate lines
            self.output_jsonl({"type": "metadata", "data": data.get("metadata", {})})
            for func in data.get("functions", []):
                self.output_jsonl({"type": "function", "data": func})
            if "ai_analysis" in data:
                self.output_jsonl({"type": "ai_analysis", "data": data["ai_analysis"]})
        elif self.format_type == OutputFormat.RICH:
            self._format_rich(data)
        else:
            self._format_plain(data)

    def _format_rich(self, data: Dict[str, Any]) -> None:
        """Format CFG analysis using Rich."""
        from rich.table import Table

        functions = data.get("functions", [])
        callgraph = data.get("callgraph", {})
        ai_analysis = data.get("ai_analysis", {})

        # Control flow summary table
        table = Table(
            title=f"[bold cyan]Control Flow Analysis[/bold cyan]\n{len(functions)} functions | {callgraph.get('edge_count', 0)} callgraph edges",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Function", style="cyan")
        table.add_column("Address", style="yellow")
        table.add_column("Blocks", justify="right", style="green")
        table.add_column("Edges", justify="right", style="blue")
        table.add_column("Size", justify="right", style="white")
        table.add_column("Complexity", justify="center", style="magenta")

        for func in functions:
            # Calculate cyclomatic complexity (edges - nodes + 2)
            blocks = func.get("basic_blocks", 0)
            edges = func.get("edges", 0)
            complexity = edges - blocks + 2 if blocks > 0 else 1

            # Style complexity
            if complexity <= 5:
                complexity_str = f"[green]{complexity}[/green]"
            elif complexity <= 10:
                complexity_str = f"[yellow]{complexity}[/yellow]"
            else:
                complexity_str = f"[red]{complexity}[/red]"

            table.add_row(
                func.get("name", "unknown"),
                format_hex(func.get("entry_point", 0)),
                str(blocks),
                str(edges),
                str(func.get("size", 0)),
                complexity_str,
            )

        self.console.print(table)

        # AI Analysis if present
        if ai_analysis:
            self._format_ai_analysis(ai_analysis)

        # Callgraph visualization (simplified)
        if callgraph and callgraph.get("edges"):
            self._format_callgraph(callgraph)

    def _format_ai_analysis(self, ai_analysis: Dict[str, Any]) -> None:
        """Format AI analysis results."""
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        # Binary-level analysis
        binary_analysis = ai_analysis.get("binary", {})
        if binary_analysis:
            summary_text = Text()
            summary_text.append("📊 Binary Analysis\n", style="bold cyan")

            purpose = binary_analysis.get("purpose", "Unknown")
            summary_text.append("Purpose: ", style="bold")
            summary_text.append(f"{purpose}\n")

            risk = binary_analysis.get("risk_level", "unknown")
            summary_text.append("Risk Level: ", style="bold")
            summary_text.append(format_risk_level(risk) + "\n")

            behaviors = binary_analysis.get("key_behaviors", [])
            if behaviors:
                summary_text.append("\nKey Behaviors:\n", style="bold")
                for behavior in behaviors[:5]:
                    summary_text.append(f"  • {behavior}\n", style="dim")

            recommendation = binary_analysis.get("recommendation", "")
            if recommendation:
                summary_text.append("\nRecommendation: ", style="bold")
                summary_text.append(f"{recommendation}\n", style="italic")

            self.console.print(
                Panel(
                    summary_text,
                    title="[bold blue]AI Binary Analysis[/bold blue]",
                    border_style="blue",
                )
            )

        # Function-level analysis
        function_suggestions = ai_analysis.get("functions", [])
        if function_suggestions:
            table = Table(
                title="[bold cyan]Function Name Suggestions[/bold cyan]",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("Original", style="dim", width=15)
            table.add_column("Address", style="cyan", no_wrap=True)
            table.add_column("Suggested Name", style="green")
            table.add_column("Confidence", justify="center")
            table.add_column("Summary", style="white", overflow="fold")

            for func in function_suggestions:
                conf = func.get("confidence", 0.0)
                conf_str = format_confidence(conf)

                table.add_row(
                    func.get("original_name", ""),
                    format_hex(func.get("address", 0)),
                    func.get("suggested_name", ""),
                    conf_str,
                    func.get("summary", ""),
                )

            self.console.print(table)

    def _format_callgraph(self, callgraph: Dict[str, Any]) -> None:
        """Format callgraph visualization."""
        from rich.tree import Tree
        from rich.panel import Panel

        edges = callgraph.get("edges", [])
        if not edges:
            return

        # Build adjacency list
        graph = {}
        for src, dst in edges:
            if src not in graph:
                graph[src] = []
            graph[src].append(dst)

        # Find root functions (no incoming edges)
        all_dsts = set(dst for _, dst in edges)
        all_srcs = set(src for src, _ in edges)
        roots = all_srcs - all_dsts

        if not roots:
            # If no clear roots, use functions with most outgoing edges
            roots = sorted(
                graph.keys(), key=lambda x: len(graph.get(x, [])), reverse=True
            )[:3]

        tree = Tree("[bold cyan]📞 Call Graph[/bold cyan]")

        def build_tree(node, parent, visited, depth=0):
            """Recursively build call tree."""
            if depth > 3:  # Limit depth to avoid huge trees
                return
            if node in visited:
                parent.add(f"[dim]{format_hex(node)} (recursive)[/dim]")
                return

            visited.add(node)
            node_label = f"[cyan]{format_hex(node)}[/cyan]"
            tree_node = parent.add(node_label)

            for child in graph.get(node, [])[:5]:  # Limit children shown
                build_tree(child, tree_node, visited.copy(), depth + 1)

        for root in list(roots)[:5]:  # Show top 5 root functions
            build_tree(root, tree, set())

        self.console.print(Panel(tree, border_style="blue"))

    def _format_plain(self, data: Dict[str, Any]) -> None:
        """Format CFG analysis as plain text."""
        lines = []

        functions = data.get("functions", [])
        callgraph = data.get("callgraph", {})

        lines.append(
            f"functions: {len(functions)} | callgraph edges: {callgraph.get('edge_count', 0)}"
        )

        for func in functions:
            name = func.get("name", "unknown")
            addr = format_hex(func.get("entry_point", 0))
            blocks = func.get("basic_blocks", 0)
            edges = func.get("edges", 0)
            size = func.get("size", 0)

            lines.append(f"- {name} @{addr} blocks={blocks} edges={edges} size={size}")

        # AI analysis if present
        ai_analysis = data.get("ai_analysis", {})
        if ai_analysis:
            lines.append("")
            lines.append("[AI] suggestions:")

            binary_analysis = ai_analysis.get("binary", {})
            if binary_analysis:
                purpose = binary_analysis.get("purpose", "Unknown")
                risk = binary_analysis.get("risk_level", "unknown")
                lines.append(f"  Binary: {purpose} | {risk}")

            function_suggestions = ai_analysis.get("functions", [])
            for func in function_suggestions:
                orig = func.get("original_name", "")
                addr = format_hex(func.get("address", 0))
                suggested = func.get("suggested_name", "")
                conf = func.get("confidence", 0.0)
                summary = func.get("summary", "")

                lines.append(
                    f"  • {orig} @{addr} -> {suggested} ({conf:.2f}) - {summary}"
                )

        self.output_plain("\n".join(lines))


class DOTFormatter(BaseFormatter):
    """Formatter for DOT graph output."""

    def format_dot_graph(self, functions: List[Dict], edges: List[tuple]) -> None:
        """Format CFG as DOT graph."""
        lines = ["digraph cfg {"]
        lines.append("  node [shape=box, fontname=monospace];")

        # Add nodes
        for func in functions:
            name = func.get("name", "unknown")
            addr = format_hex(func.get("entry_point", 0))
            label = f"{name}\\n{addr}"
            lines.append(f'  "{name}" [label="{label}"];')

        # Add edges
        for src, dst in edges:
            lines.append(f'  "{src}" -> "{dst}";')

        lines.append("}")

        if self.format_type == OutputFormat.RICH:
            from rich.syntax import Syntax

            syntax = Syntax("\n".join(lines), "dot", theme="monokai")
            self.console.print(syntax)
        else:
            self.output_plain("\n".join(lines))
