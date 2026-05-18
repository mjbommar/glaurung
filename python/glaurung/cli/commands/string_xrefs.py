"""Strings window with xrefs back to code (#222).

`glaurung strings-xrefs <db>` extracts strings from the binary, joins
each one with the data_read xrefs in the KB that point at its file
offset, and prints a panel: offset | encoding | length | text | used at.

Different from `glaurung strings`, which is a raw stats / distribution
view that doesn't talk to the KB. This one is the IDA "Strings"
window — every entry is jumpable to the call site that uses it.
"""

import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import glaurung as g

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


def _shorten(text: str, width: int = 80) -> str:
    text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def _build_offset_to_xref_map(
    kb, binary_path: str,
) -> Dict[int, List[Tuple[int, int, Optional[int]]]]:
    """Walk every data_read xref, translate its dst_va to a file
    offset, and group by file offset. Each value is a list of
    (src_va, dst_va, src_function_va) tuples.

    Translation failures (VA outside any mapped segment) are silently
    skipped — those xrefs target dynamic locations the strings panel
    can't resolve back to a literal.
    """
    from glaurung.llm.kb import xref_db
    xref_db._ensure_schema(kb._conn)
    out: Dict[int, List[Tuple[int, int, Optional[int]]]] = {}
    cur = kb._conn.cursor()
    cur.execute(
        "SELECT src_va, dst_va, src_function_va FROM xrefs "
        "WHERE binary_id = ? AND kind = 'data_read'",
        (kb.binary_id,),
    )
    for src_va, dst_va, src_fn in cur.fetchall():
        try:
            file_off = g.analysis.va_to_file_offset_path(binary_path, int(dst_va))
        except Exception:
            continue
        if file_off is None:
            continue
        out.setdefault(int(file_off), []).append((int(src_va), int(dst_va), src_fn))
    return out


def _string_storage_len(text: str, encoding: str) -> int:
    encoding = encoding.lower()
    if "16" in encoding:
        return max(2, len(text) * 2)
    return max(1, len(text))


def _xrefs_for_string_range(
    xref_map: Dict[int, List[Tuple[int, int, Optional[int]]]],
    start: int,
    end: int,
) -> List[Tuple[int, int, Optional[int]]]:
    used: List[Tuple[int, int, Optional[int]]] = []
    seen: set[Tuple[int, int, Optional[int]]] = set()
    for file_off, xrefs in xref_map.items():
        if not (start <= int(file_off) < end):
            continue
        for xref in xrefs:
            if xref in seen:
                continue
            seen.add(xref)
            used.append(xref)
    return used


class StringsXrefsCommand(BaseCommand):
    """Strings window with xrefs back to code."""

    def get_name(self) -> str:
        return "strings-xrefs"

    def get_help(self) -> str:
        return "List strings with their data_read xref sites (IDA-style strings window)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("db", help="Path to .glaurung project file")
        parser.add_argument(
            "--binary", type=Path, default=None,
            help="Optional: binary path the KB was opened against",
        )
        parser.add_argument(
            "--min-len", type=int, default=4, help="Minimum string length",
        )
        parser.add_argument(
            "--encoding", choices=("ascii", "utf8", "utf16le", "utf16be", "any"),
            default="any",
            help="Filter by encoding (default: any)",
        )
        parser.add_argument(
            "--used-only", action="store_true",
            help="Hide strings with no data_read xref pointing at them",
        )
        parser.add_argument(
            "--limit", type=int, default=200,
            help="Max rows to render (default 200)",
        )
        parser.add_argument(
            "--width", type=int, default=80,
            help="Truncate string text to this width (default 80)",
        )
        parser.add_argument(
            "--index-data-xrefs", action="store_true",
            help="Run native data-xref recovery into the KB before rendering",
        )
        parser.add_argument(
            "--force-index", action="store_true",
            help="Rebuild existing data_read xrefs when used with --index-data-xrefs",
        )
        parser.add_argument(
            "--max-functions", type=int, default=30_000,
            help="Function discovery budget for --index-data-xrefs",
        )
        parser.add_argument(
            "--max-blocks", type=int, default=1_000_000,
            help="Basic-block budget for --index-data-xrefs",
        )
        parser.add_argument(
            "--max-instructions", type=int, default=30_000_000,
            help="Instruction budget for --index-data-xrefs",
        )
        parser.add_argument(
            "--timeout-ms", type=int, default=600_000,
            help="Analysis timeout for --index-data-xrefs",
        )
        parser.add_argument(
            "--max-xrefs", type=int, default=1_000_000,
            help="Maximum data xrefs to recover with --index-data-xrefs",
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
            # Resolve binary path: explicit flag wins, else KB's first binary.
            bin_path = args.binary
            if bin_path is None:
                bins = kb.list_binaries()
                if bins:
                    bin_path = bins[0][2]
            if not bin_path:
                formatter.output_plain(
                    "Error: --binary required (no path stored in DB)"
                )
                return 4
            bin_str = str(bin_path)

            if args.index_data_xrefs:
                try:
                    xref_db.index_data_xrefs(
                        kb,
                        bin_str,
                        force=args.force_index,
                        max_functions=args.max_functions,
                        max_blocks=args.max_blocks,
                        max_instructions=args.max_instructions,
                        timeout_ms=args.timeout_ms,
                        max_xrefs=args.max_xrefs,
                    )
                except Exception as e:
                    formatter.output_plain(f"Error indexing data xrefs: {e}")
                    return 6

            # Extract strings via triage.
            try:
                art = g.triage.analyze_path(
                    bin_str, str_min_len=args.min_len, str_max_samples=10_000,
                )
            except Exception as e:
                formatter.output_plain(f"Error analysing binary: {e}")
                return 5

            xref_map = _build_offset_to_xref_map(kb, bin_str)

            rows = []
            for s in art.strings.strings:
                if args.encoding != "any" and s.encoding != args.encoding:
                    continue
                if len(s.text) < args.min_len:
                    continue
                start = int(s.offset)
                end = start + _string_storage_len(str(s.text), str(s.encoding))
                used = _xrefs_for_string_range(xref_map, start, end)
                if args.used_only and not used:
                    continue
                rows.append({
                    "offset": int(s.offset),
                    "encoding": s.encoding,
                    "length": len(s.text),
                    "text": s.text,
                    "uses": len(used),
                    "used_at": [
                        {"src_va": sv, "dst_va": dv, "src_function_va": sf}
                        for sv, dv, sf in used
                    ],
                })

            rows.sort(key=lambda r: r["offset"])
            rows = rows[: args.limit]

            if formatter.format_type == OutputFormat.JSON:
                # Resolve function names for richness.
                for r in rows:
                    for u in r["used_at"]:
                        if u["src_function_va"] is not None:
                            fn = xref_db.get_function_name(kb, u["src_function_va"])
                            u["src_function"] = fn.display if fn else None
                formatter.output_json(rows)
                return 0

            if not rows:
                formatter.output_plain("(no strings matched)")
                return 0

            header = (
                f"{'offset':>8}  {'enc':<7}  {'len':>4}  "
                f"{'uses':>4}  text  →  used_at"
            )
            formatter.output_plain(header)
            formatter.output_plain("-" * 80)
            for r in rows:
                use_str = ""
                if r["used_at"]:
                    pieces = []
                    for u in r["used_at"][:3]:
                        if u["src_function_va"] is not None:
                            fn = xref_db.get_function_name(kb, u["src_function_va"])
                            tag = fn.display if fn else f"sub_{u['src_function_va']:x}"
                            pieces.append(f"{tag}@{u['src_va']:#x}")
                        else:
                            pieces.append(f"{u['src_va']:#x}")
                    use_str = ", ".join(pieces)
                    if len(r["used_at"]) > 3:
                        use_str += f", +{len(r['used_at']) - 3} more"
                formatter.output_plain(
                    f"{r['offset']:>8}  {r['encoding']:<7}  {r['length']:>4}  "
                    f"{r['uses']:>4}  {_shorten(r['text'], args.width)}"
                    + (f"  →  {use_str}" if use_str else "")
                )
        finally:
            kb.close()
        return 0
