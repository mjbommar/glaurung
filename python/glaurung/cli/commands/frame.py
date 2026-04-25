"""Stack-frame editor CLI subcommand (#221).

`glaurung frame <db> <fn-va>` lists stack slots — offset, size, type,
name, set_by — formatted the way IDA's stack-frame editor lists
them. Inline subcommands (`rename` / `retype` / `discover`) drive the
analyst's typical edits without needing the REPL.
"""

import argparse
from pathlib import Path
from typing import Optional

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


def _slot_size(prev_offset: Optional[int], offset: int) -> Optional[int]:
    """Best-effort gap between this slot and the next one. Returns
    None when the next slot's offset is unknown — common for the
    last entry. The persistent table doesn't track size today; the
    gap is the analyst's go-to estimate."""
    if prev_offset is None:
        return None
    return abs(offset - prev_offset)


def _format_table(rows) -> str:
    lines = [
        f"{'offset':>8}  {'name':<24}  {'type':<24}  {'size':>5}  "
        f"{'uses':>4}  set_by"
    ]
    lines.append("-" * len(lines[0]))
    sorted_rows = sorted(rows, key=lambda r: r.offset)
    prev_off: Optional[int] = None
    for r in sorted_rows:
        sz = _slot_size(prev_off, r.offset)
        sz_str = f"{sz}" if sz is not None else ""
        type_str = r.c_type or "(unknown)"
        lines.append(
            f"{r.offset:+#06x}  {r.name:<24}  {type_str:<24}  "
            f"{sz_str:>5}  {r.use_count:>4}  {r.set_by or ''}"
        )
        prev_off = r.offset
    return "\n".join(lines)


class FrameCommand(BaseCommand):
    """List + edit stack-frame slots for a function."""

    def get_name(self) -> str:
        return "frame"

    def get_help(self) -> str:
        return "List or edit a function's stack frame (slots, types, names)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("db", help="Path to .glaurung project file")
        parser.add_argument("fn_va", help="Function entry VA (hex with 0x or decimal)")
        parser.add_argument(
            "action", nargs="?", default="list",
            choices=("list", "rename", "retype", "discover"),
            help="`list` (default), `rename`, `retype`, or `discover`",
        )
        parser.add_argument(
            "rest", nargs="*",
            help="For `rename`: <offset> <name>. "
                 "For `retype`: <offset> <c-type>. "
                 "Offsets accept hex (0x10) or signed decimal (-16).",
        )
        parser.add_argument(
            "--binary", type=Path, default=None,
            help="Optional: binary path the KB was opened against",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        db_path = Path(args.db)
        if not db_path.exists():
            formatter.output_plain(f"Error: db not found: {db_path}")
            return 2
        try:
            fn_va = int(args.fn_va, 0)
        except ValueError:
            formatter.output_plain(f"Error: bad fn_va: {args.fn_va!r}")
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

        try:
            if args.action == "discover":
                # Need a binary path to disassemble.
                bp = args.binary
                if bp is None:
                    bins = kb.list_binaries()
                    if bins:
                        bp = bins[0][2]
                if not bp:
                    formatter.output_plain(
                        "Error: --binary required for discover (no path in DB)"
                    )
                    return 4
                n = xref_db.discover_stack_vars(kb, str(bp), fn_va)
                formatter.output_plain(
                    f"discovered {n} stack-frame slot(s) in fn@{fn_va:#x}"
                )
                return 0

            if args.action == "rename":
                if len(args.rest) < 2:
                    formatter.output_plain("Usage: frame <db> <fn_va> rename <offset> <name>")
                    return 2
                try:
                    off = int(args.rest[0], 0)
                except ValueError:
                    formatter.output_plain(f"Error: bad offset: {args.rest[0]!r}")
                    return 2
                # Preserve existing c_type; only changing the name.
                existing = xref_db.get_stack_var(kb, fn_va, off)
                xref_db.set_stack_var(
                    kb, function_va=fn_va, offset=off, name=args.rest[1],
                    c_type=existing.c_type if existing else None,
                    use_count=existing.use_count if existing else 0,
                    set_by="manual",
                )
                formatter.output_plain(
                    f"  fn@{fn_va:#x} {off:+#06x} -> {args.rest[1]}"
                )
                return 0

            if args.action == "retype":
                if len(args.rest) < 2:
                    formatter.output_plain("Usage: frame <db> <fn_va> retype <offset> <c-type>")
                    return 2
                try:
                    off = int(args.rest[0], 0)
                except ValueError:
                    formatter.output_plain(f"Error: bad offset: {args.rest[0]!r}")
                    return 2
                existing = xref_db.get_stack_var(kb, fn_va, off)
                if existing is None:
                    formatter.output_plain(
                        f"no slot at fn@{fn_va:#x} {off:+#06x}; "
                        f"run `frame ... discover` first"
                    )
                    return 5
                xref_db.set_stack_var(
                    kb, function_va=fn_va, offset=off, name=existing.name,
                    c_type=args.rest[1],
                    use_count=existing.use_count, set_by="manual",
                )
                formatter.output_plain(
                    f"  fn@{fn_va:#x} {off:+#06x} {existing.name}: {args.rest[1]}"
                )
                return 0

            # list (default)
            rows = xref_db.list_stack_vars(kb, function_va=fn_va)
            if not rows:
                formatter.output_plain(
                    f"(no stack vars yet for fn@{fn_va:#x}; "
                    f"run `frame ... discover` first)"
                )
                return 0

            if formatter.format_type == OutputFormat.JSON:
                formatter.output_json([
                    {
                        "function_va": r.function_va, "offset": r.offset,
                        "name": r.name, "c_type": r.c_type,
                        "use_count": r.use_count, "set_by": r.set_by,
                    }
                    for r in rows
                ])
                return 0

            formatter.output_plain(_format_table(rows))
        finally:
            kb.close()
        return 0
