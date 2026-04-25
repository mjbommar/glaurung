"""Export the persistent KB to JSON / Markdown / .h header (#165 v0).

Dumps the full state of a `.glaurung` project file in one of three
shapes:

  - **JSON**: machine-readable; every persisted table emits its rows
    verbatim. The schema_version on the top object lets downstream
    consumers detect format drift.
  - **Markdown**: human-readable summary, suitable for chat-UI
    embedding or README generation. Truncates aggressively to keep
    the output viewable.
  - **C header**: extracts the type DB only and renders it as a
    `.h` file with #defines / typedefs / structs / enums. Drop-in
    for downstream code that wants to consume Glaurung's recovered
    types without parsing JSON.

v0 covers: function_names + comments + data_labels +
stack_frame_vars + function_prototypes + types + xrefs +
evidence_log. Future schemas added to the KB land here automatically
when their `list_*` API exists.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from . import type_db as _type_db
from . import xref_db as _xref_db
from .persistent import PersistentKnowledgeBase


def export_kb(kb: PersistentKnowledgeBase) -> dict:
    """Collect every persistent KB table into a single dict suitable
    for json.dumps. Stable schema; never remove fields, only add new
    ones with sane defaults."""
    function_names = [
        {
            "entry_va": fn.entry_va,
            "canonical": fn.canonical,
            "demangled": fn.demangled,
            "flavor": fn.flavor,
            "aliases": fn.aliases,
            "set_by": fn.set_by,
        }
        for fn in _xref_db.list_function_names(kb)
    ]

    prototypes = [
        {
            "function_name": p.function_name,
            "return_type": p.return_type,
            "params": [{"name": pp.name, "c_type": pp.c_type} for pp in p.params],
            "is_variadic": p.is_variadic,
            "set_by": p.set_by,
        }
        for p in _xref_db.list_function_prototypes(kb)
    ]

    comments = [
        {"va": va, "body": body}
        for (va, body) in _xref_db.list_comments(kb)
    ]

    data_labels = [
        {
            "va": d.va, "name": d.name,
            "c_type": d.c_type, "size": d.size,
            "set_by": d.set_by,
        }
        for d in _xref_db.list_data_labels(kb)
    ]

    stack_vars = [
        {
            "function_va": s.function_va,
            "offset": s.offset,
            "name": s.name,
            "c_type": s.c_type,
            "use_count": s.use_count,
            "set_by": s.set_by,
        }
        for s in _xref_db.list_stack_vars(kb)
    ]

    types = [
        {
            "name": t.name,
            "kind": t.kind,
            "body": t.body,
            "confidence": t.confidence,
            "set_by": t.set_by,
        }
        for t in _type_db.list_types(kb)
    ]

    evidence = [
        {
            "cite_id": e.cite_id, "tool": e.tool,
            "args": e.args, "summary": e.summary,
            "va_start": e.va_start, "va_end": e.va_end,
            "file_offset": e.file_offset,
            "output": e.output,
            "created_at": e.created_at,
        }
        for e in _xref_db.list_evidence(kb, limit=10_000)
    ]

    return {
        "schema_version": "1",
        "summary": {
            "function_names": len(function_names),
            "prototypes": len(prototypes),
            "comments": len(comments),
            "data_labels": len(data_labels),
            "stack_vars": len(stack_vars),
            "types": len(types),
            "evidence": len(evidence),
        },
        "function_names": function_names,
        "function_prototypes": prototypes,
        "comments": comments,
        "data_labels": data_labels,
        "stack_frame_vars": stack_vars,
        "types": types,
        "evidence_log": evidence,
    }


def export_to_json(kb: PersistentKnowledgeBase) -> str:
    """Serialize the full KB as pretty-printed JSON."""
    return json.dumps(export_kb(kb), indent=2, sort_keys=True, default=str)


def export_to_markdown(kb: PersistentKnowledgeBase) -> str:
    """Render a human-readable summary of the KB suitable for
    chat-UI embedding or README generation. Truncates per-section
    to keep the output viewable."""
    data = export_kb(kb)
    summary = data["summary"]
    lines: list[str] = []
    lines.append("# Glaurung KB export")
    lines.append("")
    lines.append(f"- function_names: **{summary['function_names']}**")
    lines.append(f"- prototypes: **{summary['prototypes']}**")
    lines.append(f"- comments: **{summary['comments']}**")
    lines.append(f"- data_labels: **{summary['data_labels']}**")
    lines.append(f"- stack_vars: **{summary['stack_vars']}**")
    lines.append(f"- types: **{summary['types']}**")
    lines.append(f"- evidence rows: **{summary['evidence']}**")
    lines.append("")

    if data["function_names"]:
        lines.append("## Functions (first 32)")
        lines.append("")
        lines.append("| entry | name | demangled | set_by |")
        lines.append("|---|---|---|---|")
        for fn in data["function_names"][:32]:
            pretty = fn["demangled"] or fn["canonical"]
            lines.append(
                f"| `{fn['entry_va']:#x}` | `{fn['canonical']}` | "
                f"{pretty if fn['demangled'] else '—'} | {fn['set_by']} |"
            )
        if summary["function_names"] > 32:
            lines.append(f"_… {summary['function_names'] - 32} more_")
        lines.append("")

    if data["types"]:
        lines.append("## Types (first 16)")
        lines.append("")
        for t in data["types"][:16]:
            lines.append(
                f"- `{t['name']}` ({t['kind']}, set_by={t['set_by']}, "
                f"confidence={t['confidence']:.2f})"
            )
        if summary["types"] > 16:
            lines.append(f"_… {summary['types'] - 16} more_")
        lines.append("")

    if data["function_prototypes"]:
        lines.append(f"## Prototypes ({summary['prototypes']} total)")
        lines.append("")
        sample = data["function_prototypes"][:8]
        for p in sample:
            params = ", ".join(
                f"{pp['c_type']} {pp['name']}".strip()
                for pp in p["params"]
            ) or "void"
            lines.append(f"- `{p['return_type']} {p['function_name']}({params})`")
        if summary["prototypes"] > 8:
            lines.append(f"_… {summary['prototypes'] - 8} more_")
        lines.append("")

    if data["evidence_log"]:
        lines.append(f"## Recent evidence (last 16 of {summary['evidence']})")
        lines.append("")
        for e in data["evidence_log"][:16]:
            rng = ""
            if e["va_start"] is not None:
                rng = f"`{e['va_start']:#x}`"
            lines.append(f"- `#{e['cite_id']}` `{e['tool']}` — {e['summary']} {rng}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def export_to_c_header(kb: PersistentKnowledgeBase) -> str:
    """Render the type DB only as a C header file. Reuses the
    existing `render_all_as_header` from type_db so the output is
    consistent with the REPL's `show` command."""
    return _type_db.render_all_as_header(kb)
