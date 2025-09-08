"""Control Flow Graph command implementation."""

import argparse
from typing import List, Optional

import glaurung as g
from .base import BaseCommand
from ..formatters.cfg import CFGFormatter
from ..formatters.base import OutputFormat


class CFGCommand(BaseCommand):
    """Command for CFG analysis."""

    def get_name(self) -> str:
        """Return the command name."""
        return "cfg"

    def get_help(self) -> str:
        """Return the command help text."""
        return "Discover functions and build a bounded CFG"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-specific arguments."""
        parser.add_argument("path", help="Path to file")
        parser.add_argument(
            "--max-read-bytes", type=int, default=10_485_760, help="Max bytes to read"
        )
        parser.add_argument(
            "--max-file-size", type=int, default=104_857_600, help="Max file size"
        )
        parser.add_argument(
            "--max-functions", type=int, default=16, help="Max functions to analyze"
        )
        parser.add_argument(
            "--max-blocks", type=int, default=2048, help="Max basic blocks"
        )
        parser.add_argument(
            "--max-instructions",
            type=int,
            default=50_000,
            help="Max instructions to process",
        )
        parser.add_argument(
            "--timeout-ms",
            type=int,
            default=100,
            help="Analysis timeout in milliseconds",
        )
        parser.add_argument(
            "--dot",
            action="store_true",
            help="Output DOT graph for first function's CFG",
        )
        parser.add_argument(
            "--dump", type=int, default=0, help="Dump first N instructions per function"
        )
        parser.add_argument(
            "--annotate",
            action="store_true",
            help="Print annotated ASM with calls/strings and truncation notes",
        )
        parser.add_argument(
            "--annotate-json",
            action="store_true",
            help="Emit JSON evidence bundle for prioritized functions",
        )

    def execute(self, args: argparse.Namespace, formatter: CFGFormatter) -> int:
        """Execute the CFG command."""
        # Validate file path
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        # Perform CFG analysis
        try:
            funcs, callgraph = g.analysis.analyze_functions_path(
                str(path),
                args.max_read_bytes,
                args.max_file_size,
                args.max_functions,
                args.max_blocks,
                args.max_instructions,
                args.timeout_ms,
            )
        except Exception as e:
            formatter.output_plain(f"Error during analysis: {e}")
            return 3

        # If annotation requested, build and emit it directly
        if args.annotate or args.annotate_json:
            from glaurung.llm.evidence import annotate_functions_path, AnnotateBudgets

            budgets = AnnotateBudgets(max_functions=min(args.max_functions, 16))
            ev = annotate_functions_path(str(path), budgets)
            if args.annotate_json or formatter.format_type == OutputFormat.JSON:
                formatter.output_json(ev.model_dump())
                return 0
            if formatter.format_type == OutputFormat.JSONL:
                # Emit JSONL: one metadata header + one line per function
                meta = {
                    "path": ev.path,
                    "arch": ev.arch,
                    "format": ev.format,
                    "endianness": ev.endianness,
                    "notes": ev.notes,
                }
                formatter.output_jsonl({"type": "metadata", "data": meta})
                for f in ev.functions:
                    formatter.output_jsonl(
                        {
                            "type": "function_annotated",
                            "data": f.model_dump(),
                        }
                    )
                return 0
            else:
                self._output_annotated(str(path), ev, formatter)
                return 0

        # Build output data for non-annotated path
        data = {
            "functions": [],
            "callgraph": {
                "function_count": callgraph.function_count(),
                "edge_count": callgraph.edge_count(),
                "edges": [],  # Will populate if needed
            },
            "metadata": {
                "max_functions": args.max_functions,
                "max_blocks": args.max_blocks,
                "max_instructions": args.max_instructions,
            },
        }

        # Convert functions to dict format
        for func in funcs:
            size = func.size or func.calculate_size()
            edge_count = sum(len(bb.successor_ids) for bb in func.basic_blocks)

            func_dict = {
                "name": func.name,
                "entry_point": func.entry_point.value,
                "basic_blocks": len(func.basic_blocks),
                "edges": edge_count,
                "size": size,
            }

            # Add disassembly dump if requested
            if args.dump > 0:
                from glaurung.disasm import disassemble_window_at

                try:
                    ins = disassemble_window_at(
                        str(path),
                        int(func.entry_point.value),
                        window_bytes=1024,
                        max_instructions=args.dump,
                    )
                    func_dict["disassembly"] = [
                        {
                            "address": i.address.value,
                            "mnemonic": i.mnemonic,
                            "operands": [str(op) for op in i.operands],
                        }
                        for i in ins[: args.dump]
                    ]
                except Exception:
                    func_dict["disassembly"] = []

            data["functions"].append(func_dict)

        # Add callgraph edges for visualization
        # Note: This would need to be extracted from the actual callgraph object
        # For now, we'll leave it empty

        # Handle DOT output separately
        if args.dot and formatter.format_type == OutputFormat.PLAIN:
            self._output_dot(funcs, formatter)
            return 0

        # Format and output results
        formatter.format_output(data)

        return 0

    def _output_annotated(self, path: str, ev, formatter) -> None:
        """Print annotated ASM with comments for each function.

        Shows calls, strings, and truncation notes.
        """
        from ..utils.formatting import format_hex

        # Rich output
        if formatter.format_type == OutputFormat.RICH and formatter.console:
            from rich.table import Table
            from rich.panel import Panel
            from rich.text import Text

            if ev.notes:
                note_text = Text(
                    "\n".join(f"note: {n}" for n in ev.notes), style="yellow"
                )
                formatter.console.print(
                    Panel(note_text, title="Notes", border_style="yellow")
                )

            for f in ev.functions:
                header = Text(justify="left")
                header.append("Function: ", style="bold")
                header.append(f"{f.name} ")
                header.append(f"@ {format_hex(f.entry_va)}\n", style="cyan")
                if f.instruction_count_provided is not None:
                    if f.instruction_count_total:
                        header.append(
                            f"instr {f.instruction_count_provided}/{f.instruction_count_total}\n",
                            style="dim",
                        )
                    else:
                        header.append(
                            f"instr {f.instruction_count_provided}\n", style="dim"
                        )

                calls = [
                    c.target_name or format_hex(c.target_va or 0)
                    for c in (f.calls or [])
                ][:8]
                strs = [repr(s.text) for s in (f.strings or [])][:6]
                meta_bits: List[str] = []
                if calls:
                    meta_bits.append("calls: " + ", ".join(calls))
                if strs:
                    meta_bits.append("strings: " + ", ".join(strs))
                if meta_bits:
                    header.append("; ".join(meta_bits), style="dim")

                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Address", style="yellow", no_wrap=True)
                table.add_column("Bytes", style="white", no_wrap=True)
                table.add_column("Disassembly", style="white")
                table.add_column("Anno", style="green")

                for ins in f.instructions:
                    annos: List[str] = []
                    if ins.call_target_name:
                        annos.append(f"call → {ins.call_target_name}")
                    elif ins.call_target_va is not None:
                        annos.append(f"call → {format_hex(ins.call_target_va)}")
                    if ins.string_text:
                        annos.append("str: " + repr(ins.string_text))
                    table.add_row(
                        format_hex(ins.va),
                        ins.bytes_hex,
                        ins.text,
                        " | ".join(annos),
                    )

                formatter.console.print(Panel(header, border_style="blue"))
                formatter.console.print(table)
            return

        # Plain output
        lines: List[str] = []
        lines.append(f"Annotated disassembly for: {path}")
        if ev.notes:
            for n in ev.notes:
                lines.append(f"note: {n}")
        for f in ev.functions:
            hdr = f"Function: {f.name} @ {format_hex(f.entry_va)}"
            counts = []
            if f.instruction_count_provided is not None:
                if f.instruction_count_total:
                    counts.append(
                        f"instr {f.instruction_count_provided}/{f.instruction_count_total}"
                    )
                else:
                    counts.append(f"instr {f.instruction_count_provided}")
            if counts:
                hdr += " (" + ", ".join(counts) + ")"
            lines.append(hdr)
            calls = [
                c.target_name or format_hex(c.target_va or 0) for c in (f.calls or [])
            ][:8]
            strs = [repr(s.text) for s in (f.strings or [])][:6]
            meta = []
            if calls:
                meta.append("calls: " + ", ".join(calls))
            if strs:
                meta.append("strings: " + ", ".join(strs))
            if meta:
                lines.append("  " + "; ".join(meta))
            for ins in f.instructions:
                cmt: List[str] = []
                if ins.call_target_name:
                    cmt.append(f"call → {ins.call_target_name}")
                elif ins.call_target_va is not None:
                    cmt.append(f"call → {format_hex(ins.call_target_va)}")
                if ins.string_text:
                    cmt.append("str: " + repr(ins.string_text))
                cmts = ("  ; " + " | ".join(cmt)) if cmt else ""
                lines.append(
                    f"  {format_hex(ins.va)}: {ins.bytes_hex:<20}  {ins.text}{cmts}"
                )
            lines.append("")
        formatter.output_plain("\n".join(lines))

    def _output_dot(self, funcs: List, formatter) -> None:
        """Output DOT graph for the first function."""
        if not funcs:
            return

        func = funcs[0]

        # Build block map
        blocks = []
        for bb in func.basic_blocks:
            blocks.append((bb.start_address.value, bb.end_address.value, bb.id))

        def block_id_for_addr(addr: int) -> Optional[str]:
            for s, e, bid in blocks:
                if addr >= s and addr < e:
                    return bid
            return None

        def dot_escape(s: str) -> str:
            return s.replace('"', '\\"')

        lines = ["digraph cfg {"]
        lines.append("  node [shape=box, fontname=monospace];")

        for _s, _e, bid in blocks:
            lines.append(f'  "{dot_escape(bid)}";')

        for src, dst in func.edges:
            sid = block_id_for_addr(src.value) or f"addr_{src.value:x}"
            did = block_id_for_addr(dst.value) or f"addr_{dst.value:x}"
            lines.append(f'  "{dot_escape(sid)}" -> "{dot_escape(did)}";')

        lines.append("}")

        formatter.output_plain("\n".join(lines))
