"""Cross-references CLI subcommand (#219).

`glaurung xrefs <db> <va>` prints every xref to (or from) a VA, with
the source function name resolved and a one-line disasm snippet at
each src_va — so the analyst can scan callers, readers, and writers
the way IDA's "X" panel scans them.
"""

import argparse
from pathlib import Path
from typing import Optional

import glaurung as g

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


def _disasm_one(file_path: str, va: int) -> str:
    """Return the single instruction at ``va`` as 'mnemonic op1, op2',
    or an empty string if the disassembler can't reach it (e.g. the VA
    is in data, or the binary moved)."""
    try:
        instrs = g.disasm.disassemble_window_at(
            file_path, int(va), window_bytes=16, max_instructions=1,
        )
    except Exception:
        return ""
    if not instrs:
        return ""
    ins = instrs[0]
    ops = ", ".join(str(o) for o in getattr(ins, "operands", []) or [])
    return f"{ins.mnemonic} {ops}".rstrip()


def _func_name(kb, entry_va: Optional[int]) -> str:
    if entry_va is None:
        return "<no function>"
    from glaurung.llm.kb import xref_db
    fn = xref_db.get_function_name(kb, int(entry_va))
    if fn is None:
        return f"sub_{int(entry_va):x}"
    return fn.display


class XrefsCommand(BaseCommand):
    """List xrefs to/from a VA — IDA-style cross-references panel."""

    def get_name(self) -> str:
        return "xrefs"

    def get_help(self) -> str:
        return "List xrefs to/from a VA (callers, readers, writers, jumps)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("db", help="Path to .glaurung project file")
        parser.add_argument("va", help="Target VA (hex with 0x or decimal)")
        parser.add_argument(
            "--direction", choices=("to", "from", "both"), default="to",
            help="`to` = who references this VA (callers/readers/writers); "
                 "`from` = what this VA references; `both` = union",
        )
        parser.add_argument(
            "--kind", choices=("call", "jump", "data_read", "data_write",
                               "struct_field", "all"),
            default="all",
            help="Filter by xref kind (default all)",
        )
        parser.add_argument(
            "--limit", type=int, default=64,
            help="Max rows to return (default 64)",
        )
        parser.add_argument(
            "--binary", type=Path, default=None,
            help="Optional: binary path the KB was opened against. "
                 "Required if the DB tracks multiple binaries.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        db_path = Path(args.db)
        if not db_path.exists():
            formatter.output_plain(f"Error: db not found: {db_path}")
            return 2
        try:
            va = int(args.va, 0)
        except ValueError:
            formatter.output_plain(f"Error: bad VA: {args.va!r}")
            return 2

        from glaurung.llm.kb import xref_db
        from glaurung.llm.kb.persistent import PersistentKnowledgeBase

        try:
            kb = PersistentKnowledgeBase.open(
                db_path, binary_path=args.binary,
            )
        except Exception as e:
            formatter.output_plain(f"Error opening db: {e}")
            return 3

        kinds = None if args.kind == "all" else (args.kind,)

        rows = []
        try:
            if args.direction in ("to", "both"):
                rows.extend(
                    ("to", r)
                    for r in xref_db.list_xrefs_to(
                        kb, va, kinds=kinds, limit=args.limit,
                    )
                )
            if args.direction in ("from", "both"):
                rows.extend(
                    ("from", r)
                    for r in xref_db.list_xrefs_from(
                        kb, va, kinds=kinds, limit=args.limit,
                    )
                )

            if not rows:
                formatter.output_plain(
                    f"(no {args.direction} xrefs at 0x{va:x})"
                )
                return 0

            # Resolve function names + snippets per source VA. For "to"
            # rows the snippet lives at src_va (the caller); for "from"
            # rows the snippet still lives at src_va (which equals the
            # query VA itself).
            file_path = None
            if args.binary is not None:
                file_path = str(args.binary)
            else:
                # Fall back to the binary path recorded in the DB.
                rows_bins = kb.list_binaries()
                if rows_bins:
                    _, _, p = rows_bins[0]
                    file_path = p
            display = []
            for direction, r in rows:
                src_func = _func_name(kb, r.src_function_va)
                snippet = _disasm_one(file_path, r.src_va) if file_path else ""
                display.append({
                    "direction": direction,
                    "src_va": r.src_va,
                    "dst_va": r.dst_va,
                    "kind": r.kind,
                    "src_function_va": r.src_function_va,
                    "src_function": src_func,
                    "snippet": snippet,
                })

            if formatter.format_type == OutputFormat.JSON:
                formatter.output_json(display)
                return 0

            # Sort: by direction, then by src_va.
            display.sort(key=lambda d: (d["direction"], d["src_va"]))

            header = (
                f"{'dir':<5} {'src_va':<12} {'kind':<13} "
                f"{'function':<32} snippet"
            )
            formatter.output_plain(header)
            formatter.output_plain("-" * len(header))
            for d in display:
                formatter.output_plain(
                    f"{d['direction']:<5} 0x{d['src_va']:<10x} "
                    f"{d['kind']:<13} {d['src_function']:<32} "
                    f"{d['snippet']}"
                )
        finally:
            kb.close()
        return 0
