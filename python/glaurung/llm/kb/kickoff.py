"""One-shot first-touch analysis pipeline (#206).

When the agent (or a human user) opens a fresh binary, the canonical
first sequence is:

    detect_packer
    analyze_functions_path
    index_callgraph        (auto-demangles in the same call)
    for each named function:
        discover_stack_vars
        propagate_types_at_callsites
        discover_struct_candidates

That's six tool calls minimum, and on a chat UI's latency budget each
round-trip costs the user real time. This module collapses the whole
sequence into one function call that returns a structured summary.

Design constraints:
  - Deterministic; no LLM calls inside.
  - Bounded; analysis caps prevent runaway work on huge binaries.
  - Idempotent against the persistent KB; safe to call repeatedly.
  - Pure-Python; no new Rust surface area.
  - Output schema is stable and JSON-serializable.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from . import type_db as _type_db
from . import xref_db as _xref_db
from .packer_detect import PackerVerdict, detect_packer
from .persistent import PersistentKnowledgeBase


@dataclass
class KickoffSummary:
    """Structured result of a first-touch analysis run."""
    binary_path: str
    binary_size: int

    # detect_packer
    packer: dict

    # triage
    format: Optional[str] = None
    arch: Optional[str] = None
    entry_va: Optional[int] = None

    # analyze_functions_path / index_callgraph
    functions_total: int = 0
    functions_named: int = 0
    functions_with_blocks: int = 0
    callgraph_edges: int = 0

    # symbol provenance counts
    by_set_by: dict = field(default_factory=dict)

    # type-KB lift across the whole binary
    stack_slots_discovered: int = 0
    types_propagated: int = 0
    auto_structs_emitted: int = 0
    stdlib_prototypes_loaded: int = 0
    dwarf_types_imported: int = 0

    # timings
    elapsed_ms: dict = field(default_factory=dict)

    # diagnostic notes the agent can surface
    notes: List[str] = field(default_factory=list)

    # cite_id of the evidence_log row recording this kickoff invocation;
    # the chat UI quotes the kickoff turn as `[cite #N]` and renders
    # this row's output as the expandable evidence pane.
    cite_id: Optional[int] = None


def kickoff_analysis(
    binary_path: str,
    *,
    db_path: Optional[str] = None,
    session: str = "main",
    max_functions_for_kb_lift: int = 64,
    skip_if_packed: bool = True,
) -> KickoffSummary:
    """Run the full first-touch pipeline on `binary_path`.

    Persists everything into the project-DB at `db_path` (or a
    temporary file if not given). When the binary is detected as
    packed AND `skip_if_packed=True`, the deeper analyses are
    short-circuited — running FLIRT / type propagation against
    encrypted code wastes budget and produces noise.

    Returns a :class:`KickoffSummary` the caller can serialize to JSON
    or render to Markdown for the chat UI.
    """
    import glaurung as g

    binary = Path(binary_path)
    summary = KickoffSummary(
        binary_path=str(binary),
        binary_size=binary.stat().st_size if binary.exists() else 0,
        packer={},
    )
    if not binary.exists():
        summary.notes.append(f"file not found: {binary_path}")
        return summary

    timings: dict = {}

    # 1. Packer detection — first because everything below this is
    # noise on encrypted code.
    t0 = time.perf_counter()
    pv = detect_packer(str(binary))
    timings["detect_packer_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    summary.packer = asdict(pv)

    if pv.is_packed and skip_if_packed:
        summary.notes.append(
            f"binary detected as {pv.packer_name or pv.family or 'packed'}; "
            "skipping deep analysis (re-run with skip_if_packed=False to override)"
        )
        summary.elapsed_ms = timings
        return summary

    # 2. Triage — format/arch/entry.
    t0 = time.perf_counter()
    try:
        art = g.triage.analyze_path(str(binary), 10_000_000, 100_000_000, 1)
    except Exception as e:
        summary.notes.append(f"triage failed: {e}")
        summary.elapsed_ms = timings
        return summary
    timings["triage_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    if art and art.verdicts:
        v = art.verdicts[0]
        summary.format = str(getattr(v, "format", None))
        summary.arch = str(getattr(v, "arch", None))
    try:
        ent = g.analysis.detect_entry_path(str(binary))
        if ent:
            summary.entry_va = int(ent[3])
    except Exception:
        pass

    # 3. Open the persistent KB with stdlib bundles auto-loaded.
    if db_path is None:
        # In-memory-ish: tmp file the caller is expected to discard.
        import tempfile
        td = tempfile.mkdtemp(prefix="glaurung-kickoff-")
        db_path = str(Path(td) / "kickoff.glaurung")
    kb = PersistentKnowledgeBase.open(
        Path(db_path), binary_path=binary, session=session,
        auto_load_stdlib=True,
    )
    try:
        summary.stdlib_prototypes_loaded = len(_xref_db.list_function_prototypes(kb))

        # 4. Index callgraph (also runs the demangle pass automatically).
        t0 = time.perf_counter()
        try:
            edges = _xref_db.index_callgraph(kb, str(binary))
        except Exception as e:
            summary.notes.append(f"index_callgraph failed: {e}")
            edges = 0
        summary.callgraph_edges = edges
        timings["index_callgraph_ms"] = round((time.perf_counter() - t0) * 1000, 1)

        # 5. Optional: import DWARF types into type_db.
        t0 = time.perf_counter()
        try:
            dwarf_summary = _type_db.import_dwarf_types(kb, str(binary))
            summary.dwarf_types_imported = (
                int(dwarf_summary.get("imported_struct", 0))
                + int(dwarf_summary.get("imported_enum", 0))
                + int(dwarf_summary.get("imported_typedef", 0))
            )
        except Exception:
            pass
        timings["dwarf_types_ms"] = round((time.perf_counter() - t0) * 1000, 1)

        # 6. Per-function lifts: stack slots, propagation, struct
        # candidates. Capped because the bench-style work scales.
        t0 = time.perf_counter()
        funcs, _cg = g.analysis.analyze_functions_path(str(binary))
        summary.functions_total = len(funcs)
        summary.functions_with_blocks = sum(1 for f in funcs if f.basic_blocks)
        summary.functions_named = sum(
            1 for f in funcs if not f.name.startswith("sub_")
        )

        # Count provenance sources from the freshly-populated function_names.
        names = _xref_db.list_function_names(kb)
        by_set_by: dict = {}
        for n in names:
            tag = n.set_by or "unknown"
            by_set_by[tag] = by_set_by.get(tag, 0) + 1
        summary.by_set_by = by_set_by
        timings["analyze_functions_ms"] = round((time.perf_counter() - t0) * 1000, 1)

        t0 = time.perf_counter()
        targets = funcs[: max_functions_for_kb_lift]
        slots_total = 0
        propagated_total = 0
        autos_total = 0
        for f in targets:
            if not f.basic_blocks:
                continue
            try:
                slots = _xref_db.discover_stack_vars(
                    kb, str(binary), int(f.entry_point.value),
                )
            except Exception:
                slots = 0
            slots_total += slots
            try:
                propagated_total += _xref_db.propagate_types_at_callsites(
                    kb, str(binary), int(f.entry_point.value),
                )
            except Exception:
                pass
            try:
                autos_total += _type_db.discover_struct_candidates(
                    kb, str(binary), int(f.entry_point.value),
                )
            except Exception:
                pass
        summary.stack_slots_discovered = slots_total
        summary.types_propagated = propagated_total
        summary.auto_structs_emitted = autos_total
        timings["per_function_lift_ms"] = round(
            (time.perf_counter() - t0) * 1000, 1
        )

        # Record this whole invocation as a single evidence row so
        # the chat UI can cite the agent's first-turn summary back
        # to a structured artifact in the KB. Done before kb.close
        # so the row commits.
        try:
            short_summary = (
                f"kickoff: {summary.functions_total} fns, "
                f"{summary.functions_named} named, "
                f"{summary.stack_slots_discovered} slots, "
                f"{summary.types_propagated} propagated, "
                f"{summary.auto_structs_emitted} structs"
            )
            cite_id = _xref_db.record_evidence(
                kb,
                tool="kickoff_analysis",
                args={
                    "binary_path": str(binary),
                    "max_functions_for_kb_lift": max_functions_for_kb_lift,
                    "skip_if_packed": skip_if_packed,
                },
                summary=short_summary,
                output={
                    "functions_total": summary.functions_total,
                    "functions_named": summary.functions_named,
                    "stack_slots_discovered": summary.stack_slots_discovered,
                    "types_propagated": summary.types_propagated,
                    "auto_structs_emitted": summary.auto_structs_emitted,
                    "stdlib_prototypes_loaded": summary.stdlib_prototypes_loaded,
                    "dwarf_types_imported": summary.dwarf_types_imported,
                    "callgraph_edges": summary.callgraph_edges,
                    "by_set_by": summary.by_set_by,
                    "packer": summary.packer,
                    "format": summary.format,
                    "arch": summary.arch,
                    "entry_va": summary.entry_va,
                },
            )
            summary.cite_id = cite_id
        except Exception:
            # Evidence-logging is best-effort; never block kickoff.
            pass
    finally:
        kb.close()

    summary.elapsed_ms = timings
    return summary


def render_kickoff_markdown(summary: KickoffSummary) -> str:
    """Render a KickoffSummary as Markdown for the chat UI / CLI."""
    p = Path(summary.binary_path).name
    lines: list[str] = []
    lines.append(f"# Kickoff analysis — {p}")
    lines.append("")

    pv = summary.packer or {}
    if pv.get("is_packed"):
        label = pv.get("packer_name") or pv.get("family") or "unknown packer"
        conf = pv.get("confidence") or 0
        lines.append(f"⚠️  **PACKED**: {label} (confidence {conf:.0%})")
        for ind in pv.get("indicators", []) or []:
            lines.append(f"  - indicator: `{ind}`")
        if summary.notes:
            lines.append("")
            for n in summary.notes:
                lines.append(f"_{n}_")
        return "\n".join(lines) + "\n"

    lines.append(f"- format: **{summary.format}**, arch: **{summary.arch}**, "
                 f"size: **{summary.binary_size}** bytes")
    if summary.entry_va is not None:
        lines.append(f"- entry: **{summary.entry_va:#x}**")
    lines.append("")
    lines.append("## Functions")
    lines.append(f"- discovered: **{summary.functions_total}** "
                 f"(with blocks: {summary.functions_with_blocks}, "
                 f"named: {summary.functions_named})")
    lines.append(f"- callgraph edges: **{summary.callgraph_edges}**")
    if summary.by_set_by:
        sources = ", ".join(
            f"{k}={v}" for k, v in sorted(
                summary.by_set_by.items(), key=lambda kv: -kv[1],
            )
        )
        lines.append(f"- name sources: {sources}")
    lines.append("")
    lines.append("## Type system")
    lines.append(f"- stdlib prototypes loaded: **{summary.stdlib_prototypes_loaded}**")
    lines.append(f"- DWARF types imported: **{summary.dwarf_types_imported}**")
    lines.append(f"- stack slots discovered: **{summary.stack_slots_discovered}**")
    lines.append(f"- types propagated: **{summary.types_propagated}**")
    lines.append(f"- auto-struct candidates: **{summary.auto_structs_emitted}**")
    lines.append("")
    if summary.elapsed_ms:
        ms_total = sum(v for v in summary.elapsed_ms.values())
        lines.append(f"_completed in {ms_total:.0f} ms_")
    if summary.notes:
        lines.append("")
        for n in summary.notes:
            lines.append(f"- note: {n}")
    return "\n".join(lines).rstrip() + "\n"
