"""Search-across-everything CLI subcommand (#225).

`glaurung find <db> <query>` performs a substring search across every
KB-indexed table — function names, comments, data labels, stack
vars, types, and disassembly mnemonic+operand text — and prints a
unified table: kind | location | snippet.

Each backing table is searchable via its existing list_* function;
this command just unions them so the analyst doesn't need to remember
which API holds what.
"""

import argparse
import re
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


# (kind, location, snippet) — what every row in the union table looks like.
SearchHit = Tuple[str, str, str]


def _matcher(query: str, *, regex: bool, case_sensitive: bool):
    """Compile a predicate ``str -> bool`` from the query options."""
    if regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            pat = re.compile(query, flags)
        except re.error as e:
            raise ValueError(f"invalid regex: {e}")
        return lambda s: bool(pat.search(s))
    if not case_sensitive:
        q = query.lower()
        return lambda s: q in s.lower()
    return lambda s: query in s


def _function_names_hits(kb, match) -> Iterable[SearchHit]:
    from glaurung.llm.kb import xref_db
    for fn in xref_db.list_function_names(kb):
        for field in (fn.canonical, fn.demangled or "", " ".join(fn.aliases)):
            if field and match(field):
                disp = fn.display
                yield (
                    "function",
                    f"0x{fn.entry_va:x}",
                    f"{disp}  (set_by={fn.set_by})",
                )
                break


def _comments_hits(kb, match) -> Iterable[SearchHit]:
    from glaurung.llm.kb import xref_db
    for va, body in xref_db.list_comments(kb):
        if match(body):
            yield ("comment", f"0x{va:x}", body[:140])


def _data_labels_hits(kb, match) -> Iterable[SearchHit]:
    from glaurung.llm.kb import xref_db
    for d in xref_db.list_data_labels(kb):
        if match(d.name) or (d.c_type and match(d.c_type)):
            piece = d.name + (f": {d.c_type}" if d.c_type else "")
            yield ("data", f"0x{d.va:x}", piece)


def _types_hits(kb, match) -> Iterable[SearchHit]:
    from glaurung.llm.kb import type_db
    for t in type_db.list_types(kb):
        if match(t.name) or match(t.kind):
            yield ("type", t.name, f"{t.kind}  (set_by={t.set_by})")


def _stack_vars_hits(kb, match) -> Iterable[SearchHit]:
    from glaurung.llm.kb import xref_db
    for sv in xref_db.list_stack_vars(kb):
        if match(sv.name) or (sv.c_type and match(sv.c_type)):
            piece = (
                f"fn@0x{sv.function_va:x} {sv.offset:+#06x}  "
                f"{sv.name}" + (f": {sv.c_type}" if sv.c_type else "")
            )
            yield ("stack_var", f"0x{sv.function_va:x}", piece)


def _strings_hits(binary_path: Optional[str], match) -> Iterable[SearchHit]:
    if not binary_path:
        return
    try:
        import glaurung as g
        art = g.triage.analyze_path(
            binary_path, str_min_len=4, str_max_samples=10_000,
        )
    except Exception:
        return
    for s in art.strings.strings:
        if match(s.text):
            yield (
                "string",
                f"file:{int(s.offset):#x}",
                s.text[:140],
            )


def _disasm_hits(kb, binary_path: Optional[str], match) -> Iterable[SearchHit]:
    """Walk every discovered function, disassemble a window per
    function, and surface instructions whose mnemonic+operand text
    matches. Bounded by max_per_function so a 5k-instruction function
    can't bury smaller hits in noise.
    """
    if not binary_path:
        return
    try:
        import glaurung as g
        funcs, _cg = g.analysis.analyze_functions_path(binary_path)
    except Exception:
        return
    for f in funcs:
        try:
            instrs = g.disasm.disassemble_window_at(
                binary_path, int(f.entry_point.value),
                window_bytes=2048, max_instructions=500,
            )
        except Exception:
            continue
        for ins in instrs:
            ops = ", ".join(str(o) for o in getattr(ins, "operands", []) or [])
            text = f"{ins.mnemonic} {ops}".strip()
            if match(text):
                yield (
                    "disasm",
                    f"0x{int(ins.address.value):x}",
                    text[:140],
                )


_KIND_DISPATCH = {
    "function": _function_names_hits,
    "comment": _comments_hits,
    "data": _data_labels_hits,
    "type": _types_hits,
    "stack_var": _stack_vars_hits,
}


class FindCommand(BaseCommand):
    """Search across every KB table for a substring or regex."""

    def get_name(self) -> str:
        return "find"

    def get_help(self) -> str:
        return "Search across function names, comments, labels, types, strings, disasm"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("db", help="Path to .glaurung project file")
        parser.add_argument("query", help="Substring or regex to search for")
        parser.add_argument(
            "--kind", default="all",
            choices=("function", "comment", "data", "type", "stack_var",
                     "string", "disasm", "all"),
            help="Filter to one kind (default: all)",
        )
        parser.add_argument(
            "--regex", action="store_true",
            help="Treat query as a Python regex (re.search)",
        )
        parser.add_argument(
            "--case-sensitive", action="store_true",
            help="Match case-sensitively (default: case-insensitive)",
        )
        parser.add_argument(
            "--limit", type=int, default=200,
            help="Max rows (default 200)",
        )
        parser.add_argument(
            "--binary", type=Path, default=None,
            help="Optional: binary path. Required for string/disasm "
                 "kinds when not stored in DB.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        db_path = Path(args.db)
        if not db_path.exists():
            formatter.output_plain(f"Error: db not found: {db_path}")
            return 2

        try:
            match = _matcher(
                args.query,
                regex=args.regex, case_sensitive=args.case_sensitive,
            )
        except ValueError as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        from glaurung.llm.kb.persistent import PersistentKnowledgeBase

        try:
            kb = PersistentKnowledgeBase.open(
                db_path, binary_path=args.binary,
            )
        except Exception as e:
            formatter.output_plain(f"Error opening db: {e}")
            return 3

        try:
            bin_path: Optional[str] = None
            if args.binary is not None:
                bin_path = str(args.binary)
            else:
                bins = kb.list_binaries()
                if bins:
                    bin_path = bins[0][2]

            kinds = (
                ("function", "comment", "data", "type", "stack_var",
                 "string", "disasm")
                if args.kind == "all" else (args.kind,)
            )

            hits: List[SearchHit] = []
            for k in kinds:
                if k in _KIND_DISPATCH:
                    hits.extend(_KIND_DISPATCH[k](kb, match))
                elif k == "string":
                    hits.extend(_strings_hits(bin_path, match))
                elif k == "disasm":
                    hits.extend(_disasm_hits(kb, bin_path, match))
                if len(hits) >= args.limit:
                    hits = hits[: args.limit]
                    break

            if not hits:
                formatter.output_plain(f"(no matches for {args.query!r})")
                return 0

            if formatter.format_type == OutputFormat.JSON:
                formatter.output_json([
                    {"kind": k, "location": loc, "snippet": snip}
                    for k, loc, snip in hits
                ])
                return 0

            header = f"{'kind':<10}  {'location':<14}  snippet"
            formatter.output_plain(header)
            formatter.output_plain("-" * 80)
            for k, loc, snip in hits:
                formatter.output_plain(f"{k:<10}  {loc:<14}  {snip}")
        finally:
            kb.close()
        return 0
