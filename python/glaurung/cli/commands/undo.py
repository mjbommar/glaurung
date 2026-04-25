"""Undo / redo CLI subcommands (#228).

Reverts the most recent N analyst-driven KB writes (rename / retype /
comment / data label / stack-var). Patches and other byte-level edits
join the same log once #224 lands.

`glaurung undo <db>` walks the latest undo_log entry, restores the
prior row state, and marks it undone. `glaurung redo <db>` re-applies
the most recently undone entry. `glaurung undo <db> --list` prints
recent history without mutating anything.
"""

import argparse
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


def _format_entry(e) -> str:
    state = "[undone] " if e.undone else ""
    key_str = " ".join(f"{k}={v:#x}" if isinstance(v, int) else f"{k}={v}"
                       for k, v in e.key.items())
    old = e.old_value or {}
    new = e.new_value or {}
    # Lead with the field that actually changed — usually `name`,
    # `body`, or `c_type` — to keep the row a glanceable diff.
    diff_field = None
    for cand in ("canonical", "name", "body", "c_type"):
        if old.get(cand) != new.get(cand) and (
            cand in old or cand in new
        ):
            diff_field = cand
            break
    if diff_field:
        old_v = old.get(diff_field, "<none>")
        new_v = new.get(diff_field, "<deleted>")
        diff = f"{diff_field}: {old_v!r} → {new_v!r}"
    else:
        diff = "(no field-level diff)"
    return f"{state}#{e.undo_id} {e.table_name} {key_str}  {diff}"


class UndoCommand(BaseCommand):
    """Revert the most recent analyst KB writes."""

    def get_name(self) -> str:
        return "undo"

    def get_help(self) -> str:
        return "Revert the most recent analyst KB writes (rename, comment, label, stack var)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("db", help="Path to .glaurung project file")
        parser.add_argument(
            "-n", type=int, default=1,
            help="Number of writes to undo (default 1)",
        )
        parser.add_argument(
            "--list", action="store_true",
            help="Print recent undo_log entries without reverting anything",
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
            if args.list:
                entries = xref_db.list_undo_log(kb, limit=max(args.n, 50))
                if not entries:
                    formatter.output_plain("(undo log empty)")
                    return 0
                if formatter.format_type == OutputFormat.JSON:
                    formatter.output_json([
                        {
                            "undo_id": e.undo_id, "table": e.table_name,
                            "key": e.key, "old": e.old_value, "new": e.new_value,
                            "set_by": e.set_by, "ts": e.ts, "undone": e.undone,
                        }
                        for e in entries
                    ])
                    return 0
                for e in entries:
                    formatter.output_plain(_format_entry(e))
                return 0

            applied = xref_db.undo(kb, n=args.n)
            if not applied:
                formatter.output_plain("(nothing to undo)")
                return 0
            for e in applied:
                formatter.output_plain(f"undo {_format_entry(e)}")
        finally:
            kb.close()
        return 0


class RedoCommand(BaseCommand):
    """Re-apply the most recent undone analyst KB writes."""

    def get_name(self) -> str:
        return "redo"

    def get_help(self) -> str:
        return "Re-apply the most recent undone analyst KB writes"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("db", help="Path to .glaurung project file")
        parser.add_argument(
            "-n", type=int, default=1,
            help="Number of writes to redo (default 1)",
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
            applied = xref_db.redo(kb, n=args.n)
            if not applied:
                formatter.output_plain("(nothing to redo)")
                return 0
            for e in applied:
                formatter.output_plain(f"redo {_format_entry(e)}")
        finally:
            kb.close()
        return 0
