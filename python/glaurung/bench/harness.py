"""Core benchmark harness (#159).

Runs Glaurung's deterministic analysis pipeline on each sample binary
and emits a typed scorecard. No LLM, no recovery rewriter — just the
parts that have to keep working as the engine evolves.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

import glaurung as g

from .metrics import (
    CallgraphMetrics,
    DebugInfoMetrics,
    DecompileMetrics,
    FunctionDiscoveryMetrics,
    StackFrameMetrics,
    TriageMetrics,
    TypeKBMetrics,
    callgraph_metrics,
    debug_info_metrics,
    decompile_metrics,
    discovery_metrics,
    language_from_source_path,
    stack_frame_metrics,
    triage_metrics,
    type_kb_metrics,
)

# Default per-function decompile timeout. Generous enough to survive a
# slow CI runner but tight enough that a misbehaving binary can't stall
# the suite.
DECOMPILE_TIMEOUT_MS = 800
DEFAULT_MAX_FUNCTIONS = 64
DEFAULT_MAX_DECOMPILE_FUNCTIONS = 24


@dataclass
class BinaryScorecard:
    """One row per binary. Stable, additive schema — never remove fields,
    only add new ones with defaults."""
    binary_path: str
    metadata_path: Optional[str]
    source_path: Optional[str]
    compiler: Optional[str]
    flags: Optional[str]
    platform: Optional[str]
    architecture: Optional[str]

    triage: dict
    discovery: dict
    callgraph: dict
    decompile: dict
    debug_info: dict = field(default_factory=dict)
    stack_frame: dict = field(default_factory=dict)
    type_kb: dict = field(default_factory=dict)
    packer: dict = field(default_factory=dict)

    elapsed_ms: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class BenchSummary:
    schema_version: str
    glaurung_commit: Optional[str]
    timestamp: str
    scorecards: List[BinaryScorecard]

    @property
    def total(self) -> int:
        return len(self.scorecards)

    @property
    def errored(self) -> int:
        return sum(1 for s in self.scorecards if s.error)

    def aggregate(self) -> dict:
        """Whole-suite roll-up — mean of headline metrics across binaries."""
        if not self.scorecards:
            return {}
        ok = [s for s in self.scorecards if not s.error]
        if not ok:
            return {"binaries": len(self.scorecards), "errored": self.errored}

        def avg(field_path: str) -> float:
            total = 0.0
            n = 0
            for s in ok:
                obj: dict | None = getattr(s, field_path.split(".", 1)[0], None)
                if obj is None:
                    continue
                if "." in field_path:
                    obj = obj.get(field_path.split(".", 1)[1])
                if isinstance(obj, (int, float)):
                    total += float(obj)
                    n += 1
            return round(total / n, 4) if n else 0.0

        # Sums (totals are clearer than averages for "did anything happen")
        def total_int(field_dot_key: str) -> int:
            top, key = field_dot_key.split(".", 1)
            return sum(int(getattr(s, top).get(key, 0) or 0) for s in ok)

        return {
            "binaries": len(self.scorecards),
            "errored": self.errored,
            "ok": len(ok),
            "totals": {
                "functions_discovered": total_int("discovery.total"),
                "functions_named": total_int("discovery.named_from_symbols"),
                "multi_chunk_functions": total_int("discovery.with_chunks_gt_one"),
                "cold_orphans": total_int("discovery.cold_orphans"),
                "decompiled_ok": total_int("decompile.succeeded"),
                "decompiled_failed": total_int("decompile.failed"),
                "dwarf_types": total_int("debug_info.dwarf_types_total"),
                "dwarf_structs_with_fields": total_int(
                    "debug_info.dwarf_structs_with_fields"
                ),
                "stack_frame_slots": total_int("stack_frame.total_slots"),
                "functions_with_stack_slots": total_int(
                    "stack_frame.functions_with_slots"
                ),
                "propagated_slots": total_int("type_kb.propagated_slots"),
                "auto_struct_candidates": total_int(
                    "type_kb.auto_struct_candidates"
                ),
            },
            "rates": {
                "name_match_rate_avg": avg("discovery.name_match_rate"),
                "decompile_success_rate_avg": avg("decompile.success_rate"),
                "language_match_rate": round(
                    sum(1 for s in ok if s.triage.get("language_match")) / len(ok), 4
                ),
            },
        }


# ---------------------------------------------------------------------------
# Per-binary runner
# ---------------------------------------------------------------------------


def _resolve_metadata(binary: Path) -> Optional[Path]:
    """Locate the metadata sidecar for a binary by walking up the export
    tree to a sibling `metadata/` directory."""
    cur = binary.parent
    while cur != cur.parent:
        cand = cur / "metadata" / f"{binary.name}.json"
        if cand.exists():
            return cand
        # Some sample roots place metadata as a sibling at every level.
        cand = cur.parent / "metadata" / f"{binary.name}.json"
        if cand.exists():
            return cand
        cur = cur.parent
    return None


def _resolve_source(metadata: dict, repo_root: Path) -> Optional[Path]:
    """Translate a metadata source_file (often `/workspace/source/...`) to
    an actual path inside this checkout."""
    src = metadata.get("source_file")
    if not src:
        return None
    p = Path(src)
    if p.exists():
        return p
    # `/workspace/source/cpp/hello.cpp` → `<repo_root>/samples/source/cpp/hello.cpp`
    if "/source/" in src:
        rel = src.split("/source/", 1)[1]
        cand = repo_root / "samples" / "source" / rel
        if cand.exists():
            return cand
    return None


def run_one_binary(
    binary: Path,
    *,
    repo_root: Optional[Path] = None,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_decompile_functions: int = DEFAULT_MAX_DECOMPILE_FUNCTIONS,
    decompile_timeout_ms: int = DECOMPILE_TIMEOUT_MS,
) -> BinaryScorecard:
    """Run the full deterministic pipeline against `binary` and score it."""
    repo_root = repo_root or Path.cwd()
    binary = Path(binary)

    # Packer detection runs before triage — we want to know the
    # binary is packed BEFORE deeper passes spend time on shells.
    # When packed, kickoff_analysis already short-circuits; the
    # bench harness keeps running so the scorecard captures the
    # detection signal even if downstream metrics are mostly zero.
    packer_dict: dict = {}
    try:
        from glaurung.llm.kb.packer_detect import detect_packer
        verdict = detect_packer(str(binary))
        packer_dict = {
            "is_packed": verdict.is_packed,
            "packer_name": verdict.packer_name,
            "family": verdict.family,
            "confidence": verdict.confidence,
            "overall_entropy": round(verdict.overall_entropy, 4),
            "indicator_count": len(verdict.indicators),
        }
    except Exception:
        packer_dict = {}

    meta_path = _resolve_metadata(binary)
    metadata: dict = {}
    if meta_path:
        try:
            metadata = json.loads(meta_path.read_text())
        except Exception:
            metadata = {}

    source_path = _resolve_source(metadata, repo_root) if metadata else None

    triage_started = time.perf_counter()
    art = None
    try:
        art = g.triage.analyze_path(str(binary), 10_000_000, 100_000_000, 1)
    except Exception as e:
        return BinaryScorecard(
            binary_path=str(binary),
            metadata_path=str(meta_path) if meta_path else None,
            source_path=str(source_path) if source_path else None,
            compiler=metadata.get("compiler"),
            flags=metadata.get("compilation_flags"),
            platform=metadata.get("platform"),
            architecture=metadata.get("architecture"),
            triage={},
            discovery={},
            callgraph={},
            decompile={},
            packer=packer_dict,
            error=f"triage: {e}",
        )
    triage_ms = (time.perf_counter() - triage_started) * 1000

    # Detected language: deterministic, symbol-driven heuristic.
    # Order matters — gfortran-built binaries also import libstdc++ glue
    # in some configurations, so check Fortran first; same for C++ vs C.
    detected_language: Optional[str] = None
    try:
        if art and getattr(art, "symbols", None):
            syms = art.symbols
            imp_names: list[str] = []
            for bucket in (
                "import_names",
                "export_names",
                "demangled_import_names",
                "demangled_export_names",
                "runpaths",
                "rpaths",
            ):
                vals = getattr(syms, bucket, None) or []
                for v in vals:
                    imp_names.append(str(v))
            haystack = " ".join(imp_names).lower()

            if "_gfortran_" in haystack or "libgfortran" in haystack:
                detected_language = "fortran"
            elif "go.buildid" in haystack or "runtime.gostartcallfn" in haystack:
                detected_language = "go"
            elif (
                "_znst" in haystack         # mangled std:: symbols
                or "_znk" in haystack
                or "__cxa_throw" in haystack
                or "__cxa_begin_catch" in haystack
                or "libstdc++" in haystack
                or "libc++" in haystack
            ):
                detected_language = "cpp"
            elif (
                "__libc_start_main" in haystack
                or "puts" in haystack
                or "printf" in haystack
                or "fprintf" in haystack
                or "libc.so" in haystack
            ):
                detected_language = "c"
    except Exception:
        detected_language = None

    tri = triage_metrics(
        art, str(source_path) if source_path else None, detected_language
    )

    analysis_started = time.perf_counter()
    funcs: List = []
    cg = None
    try:
        funcs, cg = g.analysis.analyze_functions_path(str(binary))
    except Exception as e:
        return BinaryScorecard(
            binary_path=str(binary),
            metadata_path=str(meta_path) if meta_path else None,
            source_path=str(source_path) if source_path else None,
            compiler=metadata.get("compiler"),
            flags=metadata.get("compilation_flags"),
            platform=metadata.get("platform"),
            architecture=metadata.get("architecture"),
            triage=asdict(tri),
            discovery={},
            callgraph={},
            decompile={},
            packer=packer_dict,
            elapsed_ms={"triage_ms": round(triage_ms, 1)},
            error=f"analysis: {e}",
        )
    analysis_ms = (time.perf_counter() - analysis_started) * 1000

    # Cap the function set so a wildly oversized binary (libssl etc) doesn't
    # turn the harness into a 30-minute job.
    funcs_for_metrics = funcs[:max_functions]
    disc = discovery_metrics(funcs_for_metrics)

    has_main = any(f.name == "main" for f in funcs_for_metrics)
    cgm = callgraph_metrics(cg, has_main)

    # Decompile a bounded subset — never every function. Pick the named
    # ones first, then fill with sub_* by entry VA so we always sample.
    decompile_started = time.perf_counter()
    targets = sorted(
        funcs_for_metrics,
        key=lambda f: (1 if f.name.startswith("sub_") else 0, f.entry_point.value),
    )[:max_decompile_functions]
    succ = fail = tmo = 0
    total_lines = 0
    for f in targets:
        try:
            txt = g.ir.decompile_at(
                str(binary),
                int(f.entry_point.value),
                timeout_ms=decompile_timeout_ms,
                style="c",
            )
        except TimeoutError:
            tmo += 1
            continue
        except Exception:
            fail += 1
            continue
        if isinstance(txt, str) and txt.strip():
            succ += 1
            total_lines += txt.count("\n")
        else:
            fail += 1
    decompile_ms = (time.perf_counter() - decompile_started) * 1000

    dec = decompile_metrics(
        attempted=len(targets),
        succeeded=succ,
        failed=fail,
        timed_out=tmo,
        total_lines=total_lines,
    )

    debug_started = time.perf_counter()
    dbg = debug_info_metrics(str(binary))
    debug_ms = (time.perf_counter() - debug_started) * 1000

    stack_started = time.perf_counter()
    sf = stack_frame_metrics(str(binary), funcs_for_metrics)
    stack_ms = (time.perf_counter() - stack_started) * 1000

    typekb_started = time.perf_counter()
    tkb = type_kb_metrics(str(binary), funcs_for_metrics)
    typekb_ms = (time.perf_counter() - typekb_started) * 1000

    return BinaryScorecard(
        binary_path=str(binary),
        metadata_path=str(meta_path) if meta_path else None,
        source_path=str(source_path) if source_path else None,
        compiler=metadata.get("compiler"),
        flags=metadata.get("compilation_flags"),
        platform=metadata.get("platform"),
        architecture=metadata.get("architecture"),
        triage=asdict(tri),
        discovery=asdict(disc),
        callgraph=asdict(cgm),
        decompile=asdict(dec),
        debug_info=asdict(dbg),
        stack_frame=asdict(sf),
        type_kb=asdict(tkb),
        packer=packer_dict,
        elapsed_ms={
            "triage_ms": round(triage_ms, 1),
            "analysis_ms": round(analysis_ms, 1),
            "decompile_ms": round(decompile_ms, 1),
            "debug_info_ms": round(debug_ms, 1),
            "stack_frame_ms": round(stack_ms, 1),
            "type_kb_ms": round(typekb_ms, 1),
        },
    )


# ---------------------------------------------------------------------------
# Multi-binary runner
# ---------------------------------------------------------------------------


SCHEMA_VERSION = "1"


def _git_head() -> Optional[str]:
    import subprocess
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=2, check=False,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        return None
    return None


def run_harness(
    binaries: Iterable[Path],
    *,
    repo_root: Optional[Path] = None,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_decompile_functions: int = DEFAULT_MAX_DECOMPILE_FUNCTIONS,
    decompile_timeout_ms: int = DECOMPILE_TIMEOUT_MS,
    progress: bool = False,
) -> BenchSummary:
    """Run :func:`run_one_binary` on every input and bundle the results."""
    from datetime import datetime, timezone

    cards: List[BinaryScorecard] = []
    bins = list(binaries)
    for i, b in enumerate(bins, 1):
        if progress:
            print(f"[{i}/{len(bins)}] {b}")
        card = run_one_binary(
            b,
            repo_root=repo_root,
            max_functions=max_functions,
            max_decompile_functions=max_decompile_functions,
            decompile_timeout_ms=decompile_timeout_ms,
        )
        cards.append(card)

    return BenchSummary(
        schema_version=SCHEMA_VERSION,
        glaurung_commit=_git_head(),
        timestamp=datetime.now(timezone.utc).isoformat(),
        scorecards=cards,
    )


def to_json(summary: BenchSummary) -> str:
    payload = {
        "schema_version": summary.schema_version,
        "glaurung_commit": summary.glaurung_commit,
        "timestamp": summary.timestamp,
        "summary": summary.aggregate(),
        "scorecards": [asdict(c) for c in summary.scorecards],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def to_markdown(summary: BenchSummary) -> str:
    """Human-friendly summary. Compact table + per-binary highlights."""
    agg = summary.aggregate()
    lines: list[str] = []
    lines.append(f"# Glaurung benchmark — {summary.timestamp}")
    if summary.glaurung_commit:
        lines.append(f"_glaurung HEAD: `{summary.glaurung_commit[:12]}`_")
    lines.append("")
    if agg:
        lines.append("## Aggregate")
        lines.append(f"- Binaries scored: **{agg['ok']}** (errored: {agg['errored']})")
        totals = agg.get("totals", {})
        rates = agg.get("rates", {})
        lines.append(f"- Functions discovered: **{totals.get('functions_discovered', 0)}** "
                     f"(named: {totals.get('functions_named', 0)})")
        lines.append(f"- Multi-chunk functions: **{totals.get('multi_chunk_functions', 0)}** "
                     f"(cold orphans: {totals.get('cold_orphans', 0)})")
        lines.append(f"- Decompiled OK: **{totals.get('decompiled_ok', 0)}** "
                     f"(failed: {totals.get('decompiled_failed', 0)})")
        lines.append(f"- DWARF types: **{totals.get('dwarf_types', 0)}** "
                     f"(structs with fields: {totals.get('dwarf_structs_with_fields', 0)})")
        lines.append(f"- Stack-frame slots: **{totals.get('stack_frame_slots', 0)}** "
                     f"(across {totals.get('functions_with_stack_slots', 0)} functions)")
        lines.append(f"- Type-KB lift: **{totals.get('propagated_slots', 0)}** propagated, "
                     f"**{totals.get('auto_struct_candidates', 0)}** auto-struct candidates")
        # Packer-detection signal: when ANY scorecard came back with
        # is_packed=True, surface the count so packed-matrix runs
        # produce a regression-trackable line (#213).
        packed_count = sum(
            1 for c in summary.scorecards
            if c.packer and c.packer.get("is_packed")
        )
        if packed_count:
            families: dict = {}
            for c in summary.scorecards:
                if c.packer and c.packer.get("is_packed"):
                    fam = c.packer.get("packer_name") or "(generic)"
                    families[fam] = families.get(fam, 0) + 1
            fam_str = ", ".join(
                f"{n}×{c}" for n, c in sorted(families.items())
            )
            lines.append(
                f"- Packed binaries: **{packed_count}** "
                f"(by family: {fam_str})"
            )
        lines.append("")
        lines.append("## Rates")
        lines.append(f"- Symbol-name resolution (avg): **{rates.get('name_match_rate_avg', 0):.1%}**")
        lines.append(f"- Decompile success (avg): **{rates.get('decompile_success_rate_avg', 0):.1%}**")
        lines.append(f"- Language detection match: **{rates.get('language_match_rate', 0):.1%}**")
        lines.append("")

    has_packed = any(
        c.packer and c.packer.get("is_packed") for c in summary.scorecards
    )
    lines.append("## Per binary")
    lines.append("")
    if has_packed:
        lines.append(
            "| binary | funcs | named | chunks>1 | cold orphans | "
            "decompiled | packer | entropy | ms |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---|---:|---:|")
    else:
        lines.append(
            "| binary | funcs | named | chunks>1 | cold orphans | "
            "decompiled | ms |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for c in summary.scorecards:
        if c.error:
            if has_packed:
                lines.append(
                    f"| `{Path(c.binary_path).name}` | — | — | — | — | "
                    f"error: {c.error} | — | — | — |"
                )
            else:
                lines.append(
                    f"| `{Path(c.binary_path).name}` | — | — | — | — | "
                    f"error: {c.error} | — |"
                )
            continue
        d = c.discovery
        de = c.decompile
        ms = sum(v for v in (c.elapsed_ms or {}).values())
        if has_packed:
            pk = c.packer or {}
            pk_name = pk.get("packer_name") or ("yes" if pk.get("is_packed") else "—")
            ent = pk.get("overall_entropy")
            ent_str = f"{ent:.2f}" if ent is not None else "—"
            lines.append(
                f"| `{Path(c.binary_path).name}` "
                f"| {d.get('total', 0)} "
                f"| {d.get('named_from_symbols', 0)} "
                f"| {d.get('with_chunks_gt_one', 0)} "
                f"| {d.get('cold_orphans', 0)} "
                f"| {de.get('succeeded', 0)}/{de.get('attempted', 0)} "
                f"| {pk_name} | {ent_str} | {ms:.0f} |"
            )
        else:
            lines.append(
                f"| `{Path(c.binary_path).name}` "
                f"| {d.get('total', 0)} "
                f"| {d.get('named_from_symbols', 0)} "
                f"| {d.get('with_chunks_gt_one', 0)} "
                f"| {d.get('cold_orphans', 0)} "
                f"| {de.get('succeeded', 0)}/{de.get('attempted', 0)} "
                f"| {ms:.0f} |"
            )

    return "\n".join(lines) + "\n"
