"""Pure-deterministic metric functions for the benchmark harness (#159).

Each function takes already-collected analysis output (functions list,
callgraph, decompile attempts) and returns a small dict of numbers. No
LLM calls. No I/O beyond what the caller has already done. Safe to run
in CI on every commit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence


@dataclass
class FunctionDiscoveryMetrics:
    total: int
    named_from_symbols: int
    auto_named_sub: int
    with_basic_blocks: int
    with_chunks_gt_one: int           # multi-chunk functions (e.g. main + .cold)
    cold_orphans: int                  # `<x>.cold` that did NOT get folded into a parent
    name_match_rate: float             # named_from_symbols / total
    chunk_merge_evidence: int          # functions whose chunk-count > 1


def _is_sub_placeholder(name: str) -> bool:
    return name.startswith("sub_") and all(
        c in "0123456789abcdefABCDEF" for c in name[4:]
    )


def discovery_metrics(funcs: Sequence) -> FunctionDiscoveryMetrics:
    """Function discovery + naming + chunk-merge evidence."""
    total = len(funcs)
    named = 0
    sub_only = 0
    with_blocks = 0
    multi_chunk = 0
    cold_orphans = 0

    for f in funcs:
        name = f.name
        if _is_sub_placeholder(name):
            sub_only += 1
        else:
            named += 1
        if getattr(f, "basic_blocks", None):
            with_blocks += 1
        chunks = getattr(f, "chunks", None) or []
        if len(chunks) > 1:
            multi_chunk += 1
        # Any `<name>.cold` that survives discovery is an orphan — the
        # chunk-merge pass should have folded it into a parent.
        if name.endswith(".cold") or any(
            name.endswith(s) for s in (".cold.0", ".cold.1", ".cold.2", ".cold.3", ".part.0", ".part.1", ".part.2")
        ):
            cold_orphans += 1

    name_match_rate = (named / total) if total else 0.0

    return FunctionDiscoveryMetrics(
        total=total,
        named_from_symbols=named,
        auto_named_sub=sub_only,
        with_basic_blocks=with_blocks,
        with_chunks_gt_one=multi_chunk,
        cold_orphans=cold_orphans,
        name_match_rate=round(name_match_rate, 4),
        chunk_merge_evidence=multi_chunk,
    )


@dataclass
class CallgraphMetrics:
    nodes: int
    edges: int
    avg_out_degree: float
    has_main_node: bool


def callgraph_metrics(cg, has_main: bool) -> CallgraphMetrics:
    if hasattr(cg, "function_count"):
        nodes = int(cg.function_count())
    elif hasattr(cg, "node_count"):
        nodes = int(cg.node_count())
    elif hasattr(cg, "nodes"):
        try:
            nodes = len(list(cg.nodes()))
        except Exception:
            nodes = 0
    else:
        nodes = 0
    edges = int(cg.edge_count()) if hasattr(cg, "edge_count") else 0
    avg = (edges / nodes) if nodes else 0.0
    return CallgraphMetrics(
        nodes=nodes,
        edges=edges,
        avg_out_degree=round(avg, 3),
        has_main_node=has_main,
    )


@dataclass
class DecompileMetrics:
    attempted: int
    succeeded: int
    failed: int
    timed_out: int
    total_pseudocode_lines: int
    success_rate: float


def decompile_metrics(
    *,
    attempted: int,
    succeeded: int,
    failed: int,
    timed_out: int,
    total_lines: int,
) -> DecompileMetrics:
    rate = (succeeded / attempted) if attempted else 0.0
    return DecompileMetrics(
        attempted=attempted,
        succeeded=succeeded,
        failed=failed,
        timed_out=timed_out,
        total_pseudocode_lines=total_lines,
        success_rate=round(rate, 4),
    )


@dataclass
class TriageMetrics:
    detected_format: Optional[str]
    detected_arch: Optional[str]
    detected_language: Optional[str]
    expected_language: Optional[str]
    language_match: bool


_EXT_TO_LANG = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".f90": "fortran",
    ".f": "fortran",
    ".f95": "fortran",
    ".rs": "rust",
    ".go": "go",
    ".py": "python",
    ".java": "java",
    ".cs": "csharp",
}


def language_from_source_path(source_path: Optional[str]) -> Optional[str]:
    if not source_path:
        return None
    lower = source_path.lower()
    for ext, lang in _EXT_TO_LANG.items():
        if lower.endswith(ext):
            return lang
    return None


@dataclass
class TypeKBMetrics:
    """Counts from the persistent type / xref tables a fresh KB
    builds when `auto_load_stdlib=True` runs on this binary. Tracks
    everything #172/#163/#195 produce: stdlib prototypes, propagated
    slot types, auto-discovered struct candidates."""
    stdlib_prototypes: int = 0
    propagated_slots: int = 0
    auto_struct_candidates: int = 0
    functions_scanned: int = 0


def type_kb_metrics(
    binary_path: str, funcs, *, max_functions: int = 16
) -> "TypeKBMetrics":
    """Open a temp KB with stdlib auto-load, run propagation +
    struct-discovery on the first `max_functions` named functions,
    return aggregate counts. All values zero on any internal failure."""
    try:
        import tempfile
        from pathlib import Path as _Path

        from glaurung.llm.kb import type_db as _type_db
        from glaurung.llm.kb import xref_db as _xref_db
        from glaurung.llm.kb.persistent import PersistentKnowledgeBase

        named = [f for f in funcs if f.basic_blocks][:max_functions]
        if not named:
            return TypeKBMetrics()
        with tempfile.TemporaryDirectory() as td:
            db = _Path(td) / "bench-typekb.glaurung"
            kb = PersistentKnowledgeBase.open(
                db, binary_path=_Path(binary_path), auto_load_stdlib=True,
            )
            stdlib_protos = len(_xref_db.list_function_prototypes(kb))
            _xref_db.index_callgraph(kb, binary_path)

            propagated = 0
            auto_structs = 0
            for f in named:
                try:
                    _xref_db.discover_stack_vars(
                        kb, binary_path, int(f.entry_point.value),
                    )
                    propagated += _xref_db.propagate_types_at_callsites(
                        kb, binary_path, int(f.entry_point.value),
                    )
                    auto_structs += _type_db.discover_struct_candidates(
                        kb, binary_path, int(f.entry_point.value),
                    )
                except Exception:
                    continue
            kb.close()
        return TypeKBMetrics(
            stdlib_prototypes=stdlib_protos,
            propagated_slots=propagated,
            auto_struct_candidates=auto_structs,
            functions_scanned=len(named),
        )
    except Exception:
        return TypeKBMetrics()


@dataclass
class StackFrameMetrics:
    """Counts of stack-frame slots discoverable across the analysed
    functions. Drives a regression signal for #191/#192/#194 — every
    decompiler improvement should lift the count of recoverable slots
    or shrink the number of functions with zero-slot frames."""
    functions_scanned: int = 0
    total_slots: int = 0
    functions_with_slots: int = 0
    avg_slots_per_function: float = 0.0


def stack_frame_metrics(
    binary_path: str, funcs, *, max_functions: int = 16
) -> StackFrameMetrics:
    """Sample up to `max_functions` named functions in the binary, run
    the auto-discovery pass on each, return aggregate counts. Sampling
    keeps the bench fast — full-coverage discovery is for actual
    analysis sessions, not the per-commit harness.

    Skipped (returns zeros) if anything raises — auto-discovery must
    not be load-bearing for the bench."""
    try:
        from .._sandbox_xref_db import _open_volatile_kb_for_metrics
    except Exception:
        # Use the public xref_db directly via a tmp-path KB.
        pass
    try:
        import tempfile
        from pathlib import Path as _Path

        from glaurung.llm.kb import xref_db as _xref_db
        from glaurung.llm.kb.persistent import PersistentKnowledgeBase

        named = [f for f in funcs if not f.name.startswith("sub_")][:max_functions]
        if not named:
            return StackFrameMetrics()
        with tempfile.TemporaryDirectory() as td:
            db = _Path(td) / "bench-stack.glaurung"
            kb = PersistentKnowledgeBase.open(db, binary_path=_Path(binary_path))
            total = 0
            with_any = 0
            for f in named:
                try:
                    n = _xref_db.discover_stack_vars(
                        kb, binary_path, int(f.entry_point.value),
                    )
                except Exception:
                    n = 0
                total += n
                if n > 0:
                    with_any += 1
            kb.close()
        avg = (total / len(named)) if named else 0.0
        return StackFrameMetrics(
            functions_scanned=len(named),
            total_slots=total,
            functions_with_slots=with_any,
            avg_slots_per_function=round(avg, 2),
        )
    except Exception:
        return StackFrameMetrics()


@dataclass
class DebugInfoMetrics:
    """Counts of structured types recoverable from debug info.

    Only DWARF for now (PDB ingestion is a Tier-B follow-up). Zeros
    are the expected baseline for stripped or non-debug binaries —
    the metric exists so a future regression that breaks DWARF
    ingestion shows up immediately.
    """
    dwarf_types_total: int = 0
    dwarf_structs: int = 0
    dwarf_enums: int = 0
    dwarf_typedefs: int = 0
    dwarf_structs_with_fields: int = 0


def debug_info_metrics(binary_path: str) -> DebugInfoMetrics:
    """Pull DWARF type counts via the native bridge. No-op (zeros) if
    the binary has no debug info or the bridge raises."""
    try:
        import glaurung as g
        types = g.debug.extract_dwarf_types_path(binary_path)
    except Exception:
        return DebugInfoMetrics()
    structs = sum(1 for t in types if t.get("kind") == "struct")
    enums = sum(1 for t in types if t.get("kind") == "enum")
    typedefs = sum(1 for t in types if t.get("kind") == "typedef")
    structs_with_fields = sum(
        1 for t in types
        if t.get("kind") == "struct" and t.get("fields")
    )
    return DebugInfoMetrics(
        dwarf_types_total=len(types),
        dwarf_structs=structs,
        dwarf_enums=enums,
        dwarf_typedefs=typedefs,
        dwarf_structs_with_fields=structs_with_fields,
    )


def triage_metrics(
    artifact, expected_source_path: Optional[str], detected_language: Optional[str]
) -> TriageMetrics:
    expected = language_from_source_path(expected_source_path)
    fmt = None
    arch = None
    if artifact is not None:
        verdicts = getattr(artifact, "verdicts", None) or []
        if verdicts:
            v = verdicts[0]
            fmt = getattr(v, "format", None)
            arch = getattr(v, "arch", None)
    match = bool(
        expected and detected_language and detected_language.lower() == expected.lower()
    )
    return TriageMetrics(
        detected_format=str(fmt) if fmt else None,
        detected_arch=str(arch) if arch else None,
        detected_language=detected_language,
        expected_language=expected,
        language_match=match,
    )
