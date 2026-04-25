"""Bookmarks and analyst journal CLI subcommands (#226).

`glaurung bookmark` is the "I'll come back to this" workflow —
distinct from per-VA comments because bookmarks index by id (not by
VA) and survive multiple notes per address.

`glaurung journal` is a project-level dated free-form log: "today I
learned X about this binary" entries that are too broad to attach
to one VA.
"""

import argparse
import datetime
from pathlib import Path

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


def _format_ts(ts: int) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


class BookmarkCommand(BaseCommand):
    """Add / list / delete bookmarks at VAs."""

    def get_name(self) -> str:
        return "bookmark"

    def get_help(self) -> str:
        return "Add / list / delete bookmarks at VAs (the 'come back to this' workflow)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("db", help="Path to .glaurung project file")
        parser.add_argument(
            "action", choices=("add", "list", "delete"),
            help="`add`, `list`, or `delete`",
        )
        parser.add_argument(
            "rest", nargs="*",
            help="For `add`: <va> <note...>. "
                 "For `delete`: <bookmark_id>. "
                 "For `list`: optional --va <va> filter (no positional).",
        )
        parser.add_argument(
            "--va", default=None,
            help="For `list`: filter to a specific VA (hex or decimal)",
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
            if args.action == "add":
                if len(args.rest) < 2:
                    formatter.output_plain(
                        "Usage: bookmark <db> add <va> <note...>"
                    )
                    return 2
                try:
                    va = int(args.rest[0], 0)
                except ValueError:
                    formatter.output_plain(f"Error: bad VA: {args.rest[0]!r}")
                    return 2
                note = " ".join(args.rest[1:])
                bid = xref_db.add_bookmark(kb, va, note)
                formatter.output_plain(
                    f"  bookmark #{bid}  0x{va:x}  {note}"
                )
                return 0

            if args.action == "delete":
                if not args.rest:
                    formatter.output_plain(
                        "Usage: bookmark <db> delete <bookmark_id>"
                    )
                    return 2
                try:
                    bid = int(args.rest[0], 0)
                except ValueError:
                    formatter.output_plain(f"Error: bad id: {args.rest[0]!r}")
                    return 2
                ok = xref_db.delete_bookmark(kb, bid)
                if ok:
                    formatter.output_plain(f"  deleted bookmark #{bid}")
                else:
                    formatter.output_plain(f"  no bookmark with id {bid}")
                    return 4
                return 0

            # list
            va_filter = None
            if args.va is not None:
                try:
                    va_filter = int(args.va, 0)
                except ValueError:
                    formatter.output_plain(f"Error: bad --va: {args.va!r}")
                    return 2

            bookmarks = xref_db.list_bookmarks(kb, va=va_filter)
            if not bookmarks:
                formatter.output_plain("(no bookmarks)")
                return 0

            if formatter.format_type == OutputFormat.JSON:
                formatter.output_json([
                    {
                        "bookmark_id": b.bookmark_id, "va": b.va,
                        "note": b.note, "set_by": b.set_by,
                        "created_at": b.created_at,
                    }
                    for b in bookmarks
                ])
                return 0

            header = f"{'id':>4}  {'va':<12}  {'when':<19}  note"
            formatter.output_plain(header)
            formatter.output_plain("-" * 60)
            for b in bookmarks:
                formatter.output_plain(
                    f"{b.bookmark_id:>4}  0x{b.va:<10x}  "
                    f"{_format_ts(b.created_at):<19}  {b.note}"
                )
        finally:
            kb.close()
        return 0


class JournalCommand(BaseCommand):
    """Add / list / delete free-form journal entries."""

    def get_name(self) -> str:
        return "journal"

    def get_help(self) -> str:
        return "Project-level dated free-form journal entries"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("db", help="Path to .glaurung project file")
        parser.add_argument(
            "action", choices=("add", "list", "delete"),
            help="`add`, `list`, or `delete`",
        )
        parser.add_argument(
            "rest", nargs="*",
            help="For `add`: <body...>. For `delete`: <entry_id>. "
                 "`list` takes no positionals.",
        )
        parser.add_argument(
            "--limit", type=int, default=50,
            help="For `list`: max entries (default 50)",
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
            if args.action == "add":
                if not args.rest:
                    formatter.output_plain("Usage: journal <db> add <body...>")
                    return 2
                body = " ".join(args.rest)
                eid = xref_db.add_journal_entry(kb, body)
                formatter.output_plain(f"  journal #{eid}  {body}")
                return 0

            if args.action == "delete":
                if not args.rest:
                    formatter.output_plain(
                        "Usage: journal <db> delete <entry_id>"
                    )
                    return 2
                try:
                    eid = int(args.rest[0], 0)
                except ValueError:
                    formatter.output_plain(f"Error: bad id: {args.rest[0]!r}")
                    return 2
                ok = xref_db.delete_journal_entry(kb, eid)
                if ok:
                    formatter.output_plain(f"  deleted journal entry #{eid}")
                else:
                    formatter.output_plain(f"  no journal entry with id {eid}")
                    return 4
                return 0

            # list
            entries = xref_db.list_journal(kb, limit=args.limit)
            if not entries:
                formatter.output_plain("(no journal entries)")
                return 0

            if formatter.format_type == OutputFormat.JSON:
                formatter.output_json([
                    {
                        "entry_id": e.entry_id, "body": e.body,
                        "set_by": e.set_by, "created_at": e.created_at,
                    }
                    for e in entries
                ])
                return 0

            for e in entries:
                formatter.output_plain(
                    f"#{e.entry_id}  {_format_ts(e.created_at)}\n  {e.body}"
                )
        finally:
            kb.close()
        return 0
