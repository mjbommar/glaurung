from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


FunctionStartState = Literal[
    "strict_function",
    "ghidra_only",
    "glaurung_only",
    "code_label",
    "candidate",
    "no_evidence",
]
DiagnosticKind = Literal["missing", "extra", "none"]
Confidence = Literal["high", "medium", "low", "unknown"]


DEFAULT_COMPARISON = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
)
DEFAULT_DIAGNOSTICS = Path(
    "docs/windows-port/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
)


class WindowsFunctionStartExplainArgs(BaseModel):
    comparison_path: str | None = Field(
        None,
        description=(
            "Path to a Glaurung/Ghidra comparison JSON. Defaults to the "
            "30-file post-tiny-stub-gate dashboard in docs/windows-port."
        ),
    )
    diagnostics_path: str | None = Field(
        None,
        description=(
            "Path to per-address diagnostics JSON. Defaults to the 30-file "
            "diagnostics artifact in docs/windows-port."
        ),
    )
    file: str = Field(
        ...,
        description=(
            "Binary filename or unique path substring from the comparison artifact."
        ),
    )
    va: int | None = Field(
        None,
        description="Virtual address to explain. Use either va or address.",
    )
    address: str | None = Field(
        None,
        description="Hex virtual address to explain, such as 0x180033b20.",
    )
    max_refs: int = Field(
        8,
        ge=0,
        le=64,
        description="Maximum labels, provenance rows, and code-pointer refs to return.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact function-start explanation evidence node.",
    )


class FunctionStartBytes(BaseModel):
    va: int
    address: str
    file_offset: int | None = None
    hex: str
    size: int


class GhidraFunctionFact(BaseModel):
    entry_va: int
    entry: str
    body_size: int
    thunk: bool = False


class PdataRelation(BaseModel):
    is_pdata_start: bool = False
    containing_count: int = 0
    pdata_body_overlap_starts: int = 0


class ContainingFunctionSummary(BaseModel):
    entry_va: int
    entry: str
    name: str | None = None
    kind: str | None = None
    seed_kind: str | None = None
    size: int | None = None
    total_size: int | None = None
    basic_block_count: int = 0


class FunctionStartLabel(BaseModel):
    va: int
    address: str
    function_va: int | None = None
    function: str | None = None
    name: str | None = None
    kind: str | None = None


class FunctionStartProvenance(BaseModel):
    kind: str
    detail: str | None = None
    source_va: int | None = None
    source: str | None = None


class CodePointerRef(BaseModel):
    pointer_va: int
    pointer: str
    target_va: int
    target: str
    section: str | None = None
    slot_size: int | None = None
    table_index: int | None = None
    table_length: int | None = None
    confidence: str | None = None
    relocation_backed: bool | None = None


class FunctionStartScanRejection(BaseModel):
    va: int
    address: str
    source_va: int | None = None
    source: str | None = None
    reason: str
    detail: str | None = None


class WindowsFunctionStartExplainResult(BaseModel):
    file: str
    path: str
    source_label: str | None = None
    va: int
    address: str
    final_state: FunctionStartState
    confidence: Confidence
    in_glaurung_function: bool
    in_ghidra: bool
    is_code_label: bool
    diagnostic_kind: DiagnosticKind
    seed_kinds: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    recommended_action: str
    bytes: FunctionStartBytes | None = None
    ghidra: GhidraFunctionFact | None = None
    pdata: PdataRelation | None = None
    containing_function: ContainingFunctionSummary | None = None
    labels: list[FunctionStartLabel] = Field(default_factory=list)
    provenance: list[FunctionStartProvenance] = Field(default_factory=list)
    code_pointer_refs: list[CodePointerRef] = Field(default_factory=list)
    scan_rejections: list[FunctionStartScanRejection] = Field(default_factory=list)
    comparison_summary: dict[str, int | float | str | bool | None] = Field(
        default_factory=dict
    )
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsFunctionStartExplainTool(
    MemoryTool[
        WindowsFunctionStartExplainArgs,
        WindowsFunctionStartExplainResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_function_start_explain",
                description=(
                    "Explain why one Windows VA is a strict function, "
                    "Ghidra-only start, Glaurung-only start, code label, "
                    "candidate, or no-evidence address using cached "
                    "Glaurung/Ghidra parity artifacts."
                ),
                tags=("windows", "pe", "ghidra", "function-start", "agentic"),
            ),
            WindowsFunctionStartExplainArgs,
            WindowsFunctionStartExplainResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsFunctionStartExplainArgs,
    ) -> WindowsFunctionStartExplainResult:
        comparison_path = _resolve_path(args.comparison_path, DEFAULT_COMPARISON)
        diagnostics_path = _resolve_path(args.diagnostics_path, DEFAULT_DIAGNOSTICS)
        va = _parse_va(args.va, args.address)

        comparison_rows = _load_json_list(comparison_path)
        diagnostics_rows = _load_json_list(diagnostics_path)
        comparison = _select_row(comparison_rows, args.file, comparison_path)
        diagnostics = _select_row(diagnostics_rows, args.file, diagnostics_path)

        context = _StartContext.from_rows(comparison, diagnostics, va, args.max_refs)
        result = context.to_result()

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_function_start_explain",
                    props={
                        "file": result.file,
                        "address": result.address,
                        "final_state": result.final_state,
                        "confidence": result.confidence,
                        "recommended_action": result.recommended_action,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
            result = result.model_copy(update={"evidence_node_id": evidence_node_id})

        return result


class _StartContext:
    def __init__(
        self,
        *,
        comparison: dict[str, Any],
        diagnostics: dict[str, Any],
        va: int,
        max_refs: int,
        seed_kind: str | None,
        ghidra: dict[str, Any] | None,
        labels: list[dict[str, Any]],
        provenance: list[dict[str, Any]],
        scan_rejections: list[dict[str, Any]],
        diagnostic_kind: DiagnosticKind,
        diagnostic_entry: dict[str, Any] | None,
    ) -> None:
        self.comparison = comparison
        self.diagnostics = diagnostics
        self.va = va
        self.max_refs = max_refs
        self.seed_kind = seed_kind
        self.ghidra_raw = ghidra
        self.labels_raw = labels
        self.provenance_raw = provenance
        self.scan_rejections_raw = scan_rejections
        self.diagnostic_kind = diagnostic_kind
        self.diagnostic_entry = diagnostic_entry

    @classmethod
    def from_rows(
        cls,
        comparison: dict[str, Any],
        diagnostics: dict[str, Any],
        va: int,
        max_refs: int,
    ) -> _StartContext:
        stats = comparison.get("glaurung", {}).get("stats", {})
        seed_kind = next(
            (
                str(row.get("kind"))
                for row in stats.get("function_seed_kinds") or []
                if row.get("va") == va
            ),
            None,
        )
        ghidra = next(
            (
                row
                for row in comparison.get("ghidra", {}).get("functions") or []
                if _parse_hex_or_int(row.get("entry")) == va
            ),
            None,
        )
        labels = [row for row in stats.get("code_labels") or [] if row.get("va") == va][
            :max_refs
        ]
        provenance = [
            row
            for row in stats.get("seed_provenance") or []
            if row.get("target_va") == va
        ][:max_refs]
        scan_rejections = [
            row
            for row in stats.get("scan_rejections") or []
            if row.get("va") == va
        ][:max_refs]
        diagnostic_kind: DiagnosticKind = "none"
        diagnostic_entry: dict[str, Any] | None = None
        for row in diagnostics.get("missing") or []:
            if row.get("va") == va:
                diagnostic_kind = "missing"
                diagnostic_entry = row
                break
        if diagnostic_entry is None:
            for row in diagnostics.get("extra") or []:
                if row.get("va") == va:
                    diagnostic_kind = "extra"
                    diagnostic_entry = row
                    break
        return cls(
            comparison=comparison,
            diagnostics=diagnostics,
            va=va,
            max_refs=max_refs,
            seed_kind=seed_kind,
            ghidra=ghidra,
            labels=labels,
            provenance=provenance,
            scan_rejections=scan_rejections,
            diagnostic_kind=diagnostic_kind,
            diagnostic_entry=diagnostic_entry,
        )

    def to_result(self) -> WindowsFunctionStartExplainResult:
        file_name = str(
            self.comparison.get("file") or Path(self.comparison["path"]).name
        )
        in_glaurung = self.seed_kind is not None
        in_ghidra = self.ghidra_raw is not None
        is_label = bool(self.labels_raw)
        final_state = _final_state(
            in_glaurung=in_glaurung,
            in_ghidra=in_ghidra,
            is_label=is_label,
            has_scan_rejection=bool(self.scan_rejections_raw),
            diagnostic_kind=self.diagnostic_kind,
        )
        diagnostic_entry = self.diagnostic_entry or {}
        reason_codes = _reason_codes(
            final_state=final_state,
            seed_kind=self.seed_kind,
            ghidra=self.ghidra_raw,
            diagnostic_entry=diagnostic_entry,
            labels=self.labels_raw,
            provenance=self.provenance_raw,
            scan_rejections=self.scan_rejections_raw,
        )
        notes = _notes(
            diagnostic_kind=self.diagnostic_kind,
            final_state=final_state,
            in_glaurung=in_glaurung,
            in_ghidra=in_ghidra,
        )
        return WindowsFunctionStartExplainResult(
            file=file_name,
            path=str(self.comparison.get("path") or ""),
            source_label=self.comparison.get("source_label"),
            va=self.va,
            address=_hex(self.va),
            final_state=final_state,
            confidence=_confidence(final_state, reason_codes),
            in_glaurung_function=in_glaurung,
            in_ghidra=in_ghidra,
            is_code_label=is_label,
            diagnostic_kind=self.diagnostic_kind,
            seed_kinds=_seed_kinds(
                self.seed_kind, diagnostic_entry, self.provenance_raw
            ),
            reason_codes=reason_codes,
            recommended_action=_recommended_action(final_state, reason_codes),
            bytes=_bytes_model(diagnostic_entry.get("bytes")),
            ghidra=_ghidra_model(self.ghidra_raw or diagnostic_entry.get("ghidra")),
            pdata=_pdata_model(diagnostic_entry.get("pdata")),
            containing_function=_containing_function_model(
                diagnostic_entry.get("containing_function")
            ),
            labels=_label_models(
                self.labels_raw or diagnostic_entry.get("labels") or [],
                self.max_refs,
            ),
            provenance=_provenance_models(
                self.provenance_raw or diagnostic_entry.get("provenance") or [],
                self.max_refs,
            ),
            code_pointer_refs=_code_pointer_models(
                diagnostic_entry.get("code_pointer_refs") or [],
                self.max_refs,
            ),
            scan_rejections=_scan_rejection_models(
                self.scan_rejections_raw,
                self.max_refs,
            ),
            comparison_summary=_comparison_summary(self.comparison),
            notes=notes,
        )


def _resolve_path(explicit: str | None, default_relative: Path) -> Path:
    raw = Path(explicit).expanduser() if explicit else default_relative
    candidates: list[Path] = []
    candidates.append(raw if raw.is_absolute() else Path.cwd() / raw)
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidates.append(parent / raw)
        candidates.append(parent / default_relative)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"could not resolve {explicit or default_relative}")


def _load_json_list(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: row {idx} is not a mapping")
        out.append(cast(dict[str, Any], entry))
    return out


def _select_row(
    rows: list[dict[str, Any]], file_filter: str, path: Path
) -> dict[str, Any]:
    needle = file_filter.lower()
    exact = [
        row
        for row in rows
        if str(row.get("file") or "").lower() == needle
        or Path(str(row.get("path") or "")).name.lower() == needle
    ]
    if len(exact) == 1:
        return exact[0]
    matches = [
        row
        for row in rows
        if needle in str(row.get("file") or "").lower()
        or needle in str(row.get("path") or "").lower()
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches and not exact:
        raise ValueError(f"{path}: no row matches file filter {file_filter!r}")
    raise ValueError(f"{path}: file filter {file_filter!r} matched multiple rows")


def _parse_va(va: int | None, address: str | None) -> int:
    if va is not None and address is not None:
        parsed = _parse_hex_or_int(address)
        if parsed != va:
            raise ValueError(f"va {va:#x} does not match address {address!r}")
        return va
    if va is not None:
        if va < 0:
            raise ValueError("va must be non-negative")
        return va
    if address is not None:
        return _parse_hex_or_int(address)
    raise ValueError("either va or address is required")


def _parse_hex_or_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        base = 16 if text.startswith("0x") else 10
        return int(text, base)
    raise ValueError(f"cannot parse VA from {value!r}")


def _hex(va: int | None) -> str:
    return f"0x{int(va or 0):x}"


def _final_state(
    *,
    in_glaurung: bool,
    in_ghidra: bool,
    is_label: bool,
    has_scan_rejection: bool,
    diagnostic_kind: DiagnosticKind,
) -> FunctionStartState:
    if in_glaurung and in_ghidra:
        return "strict_function"
    if in_ghidra:
        return "ghidra_only"
    if in_glaurung:
        return "glaurung_only"
    if is_label:
        return "code_label"
    if diagnostic_kind == "missing":
        return "ghidra_only"
    if diagnostic_kind == "extra":
        return "glaurung_only"
    if has_scan_rejection:
        return "candidate"
    return "no_evidence"


def _reason_codes(
    *,
    final_state: FunctionStartState,
    seed_kind: str | None,
    ghidra: dict[str, Any] | None,
    diagnostic_entry: dict[str, Any],
    labels: list[dict[str, Any]],
    provenance: list[dict[str, Any]],
    scan_rejections: list[dict[str, Any]],
) -> list[str]:
    codes: list[str] = [final_state]
    if seed_kind:
        codes.append(f"{seed_kind}_seed")
    for row in provenance:
        kind = row.get("kind")
        if kind:
            codes.append(f"{kind}_provenance")
    for row in scan_rejections:
        reason = row.get("reason")
        if isinstance(reason, str) and reason:
            codes.append(f"scan_rejection:{reason}")
    if labels or diagnostic_entry.get("labels"):
        codes.append("label_present")
    pdata = diagnostic_entry.get("pdata") or {}
    if pdata.get("is_pdata_start"):
        codes.append("pdata_start")
    if int(pdata.get("pdata_body_overlap_starts") or 0) > 0:
        codes.append("pdata_body_overlap")
    code_refs = diagnostic_entry.get("code_pointer_refs") or []
    if code_refs:
        codes.append("code_pointer_ref")
    effective_ghidra = ghidra or diagnostic_entry.get("ghidra") or {}
    if effective_ghidra.get("thunk"):
        codes.append("ghidra_thunk")
    hex_bytes = str((diagnostic_entry.get("bytes") or {}).get("hex") or "").lower()
    if hex_bytes.startswith("48ff25"):
        codes.append("rex_import_jump_thunk")
    elif hex_bytes.startswith("ff25"):
        codes.append("import_jump_thunk")
    if hex_bytes.startswith("0f10"):
        codes.append("simd_head")
    if hex_bytes.startswith("cccccccc") or hex_bytes.startswith("cccccc"):
        codes.append("padding_run")
    cause = diagnostic_entry.get("suspected_cause")
    if isinstance(cause, str) and cause:
        codes.append(cause)
    return _dedupe(codes)


def _confidence(state: FunctionStartState, reason_codes: list[str]) -> Confidence:
    if state == "strict_function":
        return "high"
    if "padding_run" in reason_codes:
        return "high"
    if "code_pointer_ref" in reason_codes or "pdata_body_overlap" in reason_codes:
        return "medium"
    if state in {"ghidra_only", "glaurung_only", "code_label"}:
        return "medium"
    return "unknown"


def _recommended_action(state: FunctionStartState, reason_codes: list[str]) -> str:
    if state == "strict_function":
        return "keep_strict_function"
    if state == "ghidra_only":
        if "ghidra_thunk" in reason_codes or "rex_import_jump_thunk" in reason_codes:
            return "promote_thunk_or_function_start"
        if "pdata_body_overlap" in reason_codes:
            return "evaluate_body_split"
        if "simd_head" in reason_codes:
            return "evaluate_contextual_simd_start"
        return "investigate_missing_start"
    if state == "glaurung_only":
        if "padding_run" in reason_codes:
            return "demote_to_rejected_start"
        if "label_present" in reason_codes:
            return "demote_to_code_label"
        return "keep_as_candidate_pending_provenance"
    if state == "code_label":
        return "keep_code_label"
    if state == "candidate":
        if any(code.startswith("scan_rejection:") for code in reason_codes):
            return "keep_rejected_start_record"
        return "collect_more_boundary_evidence"
    return "no_action_without_evidence"


def _notes(
    *,
    diagnostic_kind: DiagnosticKind,
    final_state: FunctionStartState,
    in_glaurung: bool,
    in_ghidra: bool,
) -> list[str]:
    notes: list[str] = [
        "Ghidra comparison is a reference signal, not an authority by itself."
    ]
    if diagnostic_kind == "missing" and final_state == "strict_function":
        notes.append(
            "Historical diagnostics marked this VA missing; post-fix comparison "
            "marks it recovered."
        )
    if diagnostic_kind == "extra" and in_glaurung and not in_ghidra:
        notes.append(
            "This address remains Glaurung-only in the selected comparison artifact."
        )
    return notes


def _seed_kinds(
    seed_kind: str | None,
    diagnostic_entry: dict[str, Any],
    provenance: list[dict[str, Any]],
) -> list[str]:
    kinds: list[str] = []
    if seed_kind:
        kinds.append(seed_kind)
    diag_seed = diagnostic_entry.get("seed_kind")
    if isinstance(diag_seed, str) and diag_seed:
        kinds.append(diag_seed)
    for row in diagnostic_entry.get("provenance") or []:
        kind = row.get("kind")
        if isinstance(kind, str) and kind:
            kinds.append(kind)
    for row in provenance:
        kind = row.get("kind")
        if isinstance(kind, str) and kind:
            kinds.append(kind)
    return _dedupe(kinds)


def _bytes_model(raw: Any) -> FunctionStartBytes | None:
    if not isinstance(raw, dict):
        return None
    return FunctionStartBytes(
        va=int(raw.get("va") or 0),
        address=str(raw.get("address") or _hex(raw.get("va"))),
        file_offset=raw.get("file_offset"),
        hex=str(raw.get("hex") or ""),
        size=int(raw.get("size") or 0),
    )


def _ghidra_model(raw: Any) -> GhidraFunctionFact | None:
    if not isinstance(raw, dict):
        return None
    entry_va = _parse_hex_or_int(raw.get("entry"))
    return GhidraFunctionFact(
        entry_va=entry_va,
        entry=_hex(entry_va),
        body_size=int(raw.get("body") or 0),
        thunk=bool(raw.get("thunk")),
    )


def _pdata_model(raw: Any) -> PdataRelation | None:
    if not isinstance(raw, dict):
        return None
    containing = raw.get("containing_pdata") or []
    return PdataRelation(
        is_pdata_start=bool(raw.get("is_pdata_start")),
        containing_count=len(containing) if isinstance(containing, list) else 0,
        pdata_body_overlap_starts=int(raw.get("pdata_body_overlap_starts") or 0),
    )


def _containing_function_model(raw: Any) -> ContainingFunctionSummary | None:
    if not isinstance(raw, dict):
        return None
    entry_va = int(raw.get("entry_va") or 0)
    blocks = raw.get("basic_blocks") or []
    return ContainingFunctionSummary(
        entry_va=entry_va,
        entry=str(raw.get("entry") or _hex(entry_va)),
        name=raw.get("name"),
        kind=raw.get("kind"),
        seed_kind=raw.get("seed_kind"),
        size=raw.get("size"),
        total_size=raw.get("total_size"),
        basic_block_count=len(blocks) if isinstance(blocks, list) else 0,
    )


def _label_models(raw: list[Any], max_refs: int) -> list[FunctionStartLabel]:
    out: list[FunctionStartLabel] = []
    for row in raw[:max_refs]:
        if not isinstance(row, dict):
            continue
        va = int(row.get("va") or 0)
        out.append(
            FunctionStartLabel(
                va=va,
                address=str(row.get("address") or _hex(va)),
                function_va=row.get("function_va"),
                function=row.get("function"),
                name=row.get("name"),
                kind=row.get("kind"),
            )
        )
    return out


def _provenance_models(raw: list[Any], max_refs: int) -> list[FunctionStartProvenance]:
    out: list[FunctionStartProvenance] = []
    for row in raw[:max_refs]:
        if not isinstance(row, dict):
            continue
        out.append(
            FunctionStartProvenance(
                kind=str(row.get("kind") or ""),
                detail=row.get("detail"),
                source_va=row.get("source_va"),
                source=row.get("source"),
            )
        )
    return out


def _code_pointer_models(raw: list[Any], max_refs: int) -> list[CodePointerRef]:
    out: list[CodePointerRef] = []
    for row in raw[:max_refs]:
        if not isinstance(row, dict):
            continue
        pointer_va = int(row.get("pointer_va") or 0)
        target_va = int(row.get("target_va") or 0)
        out.append(
            CodePointerRef(
                pointer_va=pointer_va,
                pointer=str(row.get("pointer") or _hex(pointer_va)),
                target_va=target_va,
                target=str(row.get("target") or _hex(target_va)),
                section=row.get("section"),
                slot_size=row.get("slot_size"),
                table_index=row.get("table_index"),
                table_length=row.get("table_length"),
                confidence=row.get("confidence"),
                relocation_backed=row.get("relocation_backed"),
            )
        )
    return out


def _scan_rejection_models(
    raw: list[Any],
    max_refs: int,
) -> list[FunctionStartScanRejection]:
    out: list[FunctionStartScanRejection] = []
    for row in raw[:max_refs]:
        if not isinstance(row, dict):
            continue
        va = int(row.get("va") or 0)
        source_va = row.get("source_va")
        out.append(
            FunctionStartScanRejection(
                va=va,
                address=_hex(va),
                source_va=source_va,
                source=None if source_va is None else _hex(int(source_va)),
                reason=str(row.get("reason") or "unknown"),
                detail=row.get("detail"),
            )
        )
    return out


def _comparison_summary(
    row: dict[str, Any],
) -> dict[str, int | float | str | bool | None]:
    gap = row.get("address_gap") or {}
    glaurung = row.get("glaurung") or {}
    ghidra = row.get("ghidra") or {}
    return {
        "glaurung_functions": glaurung.get("functions"),
        "ghidra_functions": (ghidra.get("metrics") or {}).get("internal_functions"),
        "missing_entries": gap.get("missing_entries"),
        "extra_entries": gap.get("extra_entries"),
        "missing_thunks": gap.get("missing_thunks"),
        "suspected_reason": row.get("suspected_reason"),
        "glaurung_truncated": (glaurung.get("stats") or {}).get("truncated"),
        "ghidra_timed_out": ghidra.get("timed_out"),
    }


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def build_tool() -> WindowsFunctionStartExplainTool:
    return WindowsFunctionStartExplainTool()
