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
