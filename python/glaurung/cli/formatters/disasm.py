"""Formatter for disassembly command output."""

from typing import List, Dict, Any
from .base import BaseFormatter, OutputFormat
from ..utils.formatting import format_hex


class DisasmFormatter(BaseFormatter):
    """Formatter for disassembly output."""

    def format_output(self, data: Dict[str, Any]) -> None:
        """Format and output disassembly data."""
        if self.format_type == OutputFormat.JSON:
            self.output_json(data)
        elif self.format_type == OutputFormat.JSONL:
            # Output each instruction as a separate line
            for inst in data.get("instructions", []):
                self.output_jsonl(inst)
        elif self.format_type == OutputFormat.RICH:
            self._format_rich(data)
        else:
            self._format_plain(data)

    def _format_rich(self, data: Dict[str, Any]) -> None:
        """Format disassembly using Rich with syntax highlighting."""
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text

        engine = data.get("engine", "unknown")
        arch = data.get("arch", "unknown")
        instructions = data.get("instructions", [])
        metadata = data.get("metadata", {})

        # Header panel
        header = Text()
        header.append("🔧 Disassembly\n", style="bold cyan")
        header.append("Engine: ", style="bold")
        header.append(f"{engine}\n", style="yellow")
        header.append("Architecture: ", style="bold")
        header.append(f"{arch}\n", style="green")

        if metadata:
            if "start_address" in metadata:
                header.append("Start Address: ", style="bold")
                header.append(
                    f"{format_hex(metadata['start_address'])}\n", style="magenta"
                )
            if "window_bytes" in metadata:
                header.append("Window Size: ", style="bold")
                header.append(f"{metadata['window_bytes']} bytes\n")

        self.console.print(
            Panel(
                header,
                title="[bold blue]Disassembly Info[/bold blue]",
                border_style="blue",
            )
        )

        if not instructions:
            self.console.print("[yellow]No instructions found[/yellow]")
            return

        # Create assembly code view
        table = Table(
            show_header=True,
            header_style="bold magenta",
            show_lines=False,
            box=None,
            padding=(0, 1),
        )

        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Bytes", style="dim yellow", min_width=20)
        table.add_column("Mnemonic", style="bold green", no_wrap=True)
        table.add_column("Operands", style="white")
        table.add_column("Comments", style="dim italic")

        for inst in instructions:
            addr = format_hex(inst.get("address", 0))

            # Format bytes as hex string
            bytes_raw = inst.get("bytes", "")
            if isinstance(bytes_raw, (list, tuple)):
                bytes_str = " ".join(f"{b:02x}" for b in bytes_raw)
            else:
                bytes_str = bytes_raw

            mnemonic = inst.get("mnemonic", "")

            # Format operands
            operands = inst.get("operands", [])
            if isinstance(operands, list):
                operands_str = ", ".join(str(op) for op in operands)
            else:
                operands_str = str(operands)

            # Comments (if any)
            comment = inst.get("comment", "")

            # Style certain instructions differently
            if mnemonic.lower() in ["call", "jmp", "je", "jne", "jz", "jnz", "ret"]:
                mnemonic_style = "[bold cyan]" + mnemonic + "[/bold cyan]"
            elif mnemonic.lower() in ["push", "pop"]:
                mnemonic_style = "[yellow]" + mnemonic + "[/yellow]"
            elif mnemonic.lower().startswith("mov"):
                mnemonic_style = "[green]" + mnemonic + "[/green]"
            else:
                mnemonic_style = mnemonic

            table.add_row(addr, bytes_str, mnemonic_style, operands_str, comment)

        self.console.print(table)

        # Show truncation notice if present
        if metadata.get("truncated"):
            self.console.print()
            self.console.print("[dim yellow]Note: Output truncated[/dim yellow]")
            if metadata.get("truncated_bytes"):
                self.console.print(
                    f"[dim]- Read only first {metadata['window_bytes']} bytes of file[/dim]"
                )
            if metadata.get("truncated_instructions"):
                self.console.print(
                    f"[dim]- Stopped after {metadata['max_instructions']} instructions[/dim]"
                )
            self.console.print("[dim]Hints:[/dim]")
            self.console.print(
                "[dim]- Increase output: --window-bytes 4096 --max-instructions 512[/dim]"
            )
            self.console.print(
                "[dim]- Start from specific address: --addr 0x<address>[/dim]"
            )

    def _format_plain(self, data: Dict[str, Any]) -> None:
        """Format disassembly as plain text."""
        lines = []

        engine = data.get("engine", "unknown")
        arch = data.get("arch", "unknown")
        lines.append(f"engine: {engine} arch: {arch}")

        instructions = data.get("instructions", [])
        for inst in instructions:
            addr = format_hex(inst.get("address", 0), prefix=True)

            # Format bytes
            bytes_raw = inst.get("bytes", "")
            if isinstance(bytes_raw, (list, tuple)):
                bytes_str = " ".join(f"{b:02x}" for b in bytes_raw)
            else:
                bytes_str = bytes_raw

            mnemonic = inst.get("mnemonic", "")

            # Format operands
            operands = inst.get("operands", [])
            if isinstance(operands, list):
                operands_str = ", ".join(str(op) for op in operands)
            else:
                operands_str = str(operands)

            # Build line
            line = f"{addr}: {bytes_str:<20} {mnemonic} {operands_str}"

            # Add comment if present
            comment = inst.get("comment", "")
            if comment:
                line += f"    ; {comment}"

            lines.append(line)

        # Add metadata notes
        metadata = data.get("metadata", {})
        if metadata.get("truncated"):
            lines.append("")
            lines.append("note: truncated preview output.")
            if metadata.get("truncated_bytes"):
                lines.append(
                    f"- Read only first {metadata['window_bytes']} bytes of file"
                )
            if metadata.get("truncated_instructions"):
                lines.append(
                    f"- Stopped after {metadata['max_instructions']} instructions"
                )
            lines.append("hints:")
            lines.append(
                "- Increase output: e.g., --window-bytes 4096 --max-instructions 512"
            )
            lines.append(
                "- Start from a specific VA: --addr 0x<address> (e.g., entrypoint)"
            )
            lines.append(
                "- This command is a quick preview; it does not linearly sweep all code"
            )

        self.output_plain("\n".join(lines))


class AssemblyCodeFormatter(BaseFormatter):
    """Specialized formatter for assembly code with advanced highlighting."""

    def __init__(self, format_type: OutputFormat = OutputFormat.PLAIN):
        """Initialize formatter."""
        super().__init__(format_type)
        self.show_addresses = True
        self.show_bytes = True
        self.show_comments = True
        self.syntax_theme = "monokai"

    def format_assembly(self, code: str, language: str = "asm") -> None:
        """Format assembly code with syntax highlighting."""
        if self.format_type == OutputFormat.RICH:
            from rich.syntax import Syntax

            syntax = Syntax(
                code,
                language,
                theme=self.syntax_theme,
                line_numbers=self.show_addresses,
                word_wrap=False,
            )
            self.console.print(syntax)
        else:
            self.output_plain(code)

    def format_instruction_list(self, instructions: List[Dict]) -> None:
        """Format a list of instructions with annotations."""
        if self.format_type == OutputFormat.RICH:
            self._format_rich_instructions(instructions)
        else:
            self._format_plain_instructions(instructions)

    def _format_rich_instructions(self, instructions: List[Dict]) -> None:
        """Format instructions with Rich styling."""
        from rich.table import Table
        from rich.text import Text

        table = Table(show_header=False, box=None, padding=(0, 1))

        if self.show_addresses:
            table.add_column("Address", style="cyan", no_wrap=True)
        if self.show_bytes:
            table.add_column("Bytes", style="dim yellow")
        table.add_column("Instruction", style="white")
        if self.show_comments:
            table.add_column("Comment", style="dim italic green")

        for inst in instructions:
            row = []

            if self.show_addresses:
                row.append(format_hex(inst.get("address", 0)))

            if self.show_bytes:
                bytes_val = inst.get("bytes", "")
                if isinstance(bytes_val, (list, tuple)):
                    bytes_str = " ".join(f"{b:02x}" for b in bytes_val)
                else:
                    bytes_str = bytes_val
                row.append(bytes_str)

            # Build instruction text with styling
            mnemonic = inst.get("mnemonic", "")
            operands = inst.get("operands", [])

            if isinstance(operands, list):
                operands_str = ", ".join(str(op) for op in operands)
            else:
                operands_str = str(operands)

            inst_text = Text()

            # Color mnemonics by category
            if mnemonic.lower() in [
                "call",
                "jmp",
                "je",
                "jne",
                "jz",
                "jnz",
                "ret",
                "jg",
                "jl",
            ]:
                inst_text.append(mnemonic, style="bold cyan")
            elif mnemonic.lower() in ["push", "pop"]:
                inst_text.append(mnemonic, style="yellow")
            elif mnemonic.lower().startswith("mov"):
                inst_text.append(mnemonic, style="green")
            elif mnemonic.lower() in ["add", "sub", "mul", "div", "xor", "and", "or"]:
                inst_text.append(mnemonic, style="magenta")
            else:
                inst_text.append(mnemonic)

            if operands_str:
                inst_text.append(" ")
                inst_text.append(operands_str)

            row.append(inst_text)

            if self.show_comments:
                row.append(inst.get("comment", ""))

            table.add_row(*row)

        self.console.print(table)

    def _format_plain_instructions(self, instructions: List[Dict]) -> None:
        """Format instructions as plain text."""
        lines = []

        for inst in instructions:
            parts = []

            if self.show_addresses:
                parts.append(format_hex(inst.get("address", 0)) + ":")

            if self.show_bytes:
                bytes_val = inst.get("bytes", "")
                if isinstance(bytes_val, (list, tuple)):
                    bytes_str = " ".join(f"{b:02x}" for b in bytes_val)
                else:
                    bytes_str = bytes_val
                parts.append(f"{bytes_str:<20}")

            mnemonic = inst.get("mnemonic", "")
            operands = inst.get("operands", [])

            if isinstance(operands, list):
                operands_str = ", ".join(str(op) for op in operands)
            else:
                operands_str = str(operands)

            parts.append(f"{mnemonic} {operands_str}")

            if self.show_comments and inst.get("comment"):
                parts.append(f"; {inst['comment']}")

            lines.append(" ".join(parts))

        self.output_plain("\n".join(lines))
