from __future__ import annotations

import hashlib
from pathlib import Path
from collections.abc import Iterable
from typing import Literal, cast

import yaml
from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.binary_diff import BinaryDiff, diff_binaries
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


SimilarityPairStatus = Literal["same", "changed", "added", "removed"]


class WindowsFunctionSimilarityRecord(BaseModel):
    function: str
    matched_function: str | None = None
    status: SimilarityPairStatus
    similarity_score: float = Field(ge=0.0, le=1.0)
    similarity_algorithm: str
    a_entry_va: int | None = None
    b_entry_va: int | None = None
    a_size: int | None = None
    b_size: int | None = None
    opcode_ngram_jaccard: float | None = Field(None, ge=0.0, le=1.0)
    byte_ngram_jaccard: float | None = Field(None, ge=0.0, le=1.0)
    size_ratio: float | None = Field(None, ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class WindowsFunctionSimilarityManifestArgs(BaseModel):
    binary_a: str = Field(..., description="Pre-change binary path.")
    binary_b: str = Field(..., description="Post-change binary path.")
    output_path: str | None = Field(
        None,
        description=(
            "Optional YAML path to write a similarities manifest consumable by "
            "windows_patch_function_identity_extract.external_similarity_manifest_path."
        ),
    )
    ngram_size: int = Field(
        3,
        ge=1,
        le=8,
        description="Opcode and byte n-gram size used for deterministic scoring.",
    )
    min_similarity_score: float = Field(
        0.55,
        ge=0.0,
        le=1.0,
        description="Minimum score to emit a similarity record.",
    )
    max_functions: int = Field(
        2048,
        ge=1,
        description="Maximum functions to signature per binary.",
    )
    max_rows: int = Field(
        128,
        ge=0,
        description="Maximum emitted records. Use 0 for summary only.",
    )
    include_same: bool = Field(
        False,
        description="If true, include same-hash same-name rows.",
    )
    match_added_removed: bool = Field(
        True,
        description="If true, best-match added/removed functions by similarity.",
    )
    skip_anonymous: bool = Field(
        True,
        description="Skip sub_<hex> placeholder names during diff/signature indexing.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact similarity-manifest evidence node.",
    )


class WindowsFunctionSimilarityManifestResult(BaseModel):
    binary_a: str
    binary_b: str
    functions_a: int
    functions_b: int
    diff_rows: int
    similarity_record_count: int
    output_path: str | None = None
    similarities: list[WindowsFunctionSimilarityRecord]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class _FunctionSignature(BaseModel):
    name: str
    entry_va: int
    size: int
    body_hash: str
    opcode_ngrams: set[tuple[str, ...]] = Field(default_factory=set)
    byte_ngrams: set[bytes] = Field(default_factory=set)


class WindowsFunctionSimilarityManifestTool(
    MemoryTool[
        WindowsFunctionSimilarityManifestArgs,
        WindowsFunctionSimilarityManifestResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_function_similarity_manifest",
                description=(
                    "Compute a deterministic Glaurung function-similarity "
                    "manifest for a Windows patch pair using normalized opcode "
                    "n-grams, byte n-grams, and size ratio."
                ),
                tags=("windows", "pe", "patch", "diff", "similarity"),
            ),
            WindowsFunctionSimilarityManifestArgs,
            WindowsFunctionSimilarityManifestResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsFunctionSimilarityManifestArgs,
    ) -> WindowsFunctionSimilarityManifestResult:
        diff = diff_binaries(
            args.binary_a,
            args.binary_b,
            skip_anonymous=args.skip_anonymous,
        )
        signatures_a = _function_signatures(
            args.binary_a,
            ngram_size=args.ngram_size,
            max_functions=args.max_functions,
            skip_anonymous=args.skip_anonymous,
        )
        signatures_b = _function_signatures(
            args.binary_b,
            ngram_size=args.ngram_size,
            max_functions=args.max_functions,
            skip_anonymous=args.skip_anonymous,
        )
        similarities = _similarity_records(
            diff,
            signatures_a=signatures_a,
            signatures_b=signatures_b,
            ngram_size=args.ngram_size,
            min_similarity_score=args.min_similarity_score,
            include_same=args.include_same,
            match_added_removed=args.match_added_removed,
        )
        similarity_record_count = len(similarities)
        emitted = similarities[: args.max_rows] if args.max_rows else []
        output_path = _write_manifest(args.output_path, similarities)
        coverage = ["function_similarity_manifest"] if similarities else []
        if any(record.opcode_ngram_jaccard is not None for record in similarities):
            coverage.append("opcode_ngram_similarity")
        if any(record.byte_ngram_jaccard is not None for record in similarities):
            coverage.append("byte_ngram_similarity")
        if any(record.status in {"added", "removed"} for record in similarities):
            coverage.append("added_removed_best_match")
        missing = [] if similarities else ["function_similarity_manifest"]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_function_similarity_manifest",
                    props={
                        "binary_a": args.binary_a,
                        "binary_b": args.binary_b,
                        "similarity_record_count": similarity_record_count,
                        "output_path": output_path,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsFunctionSimilarityManifestResult(
            binary_a=args.binary_a,
            binary_b=args.binary_b,
            functions_a=len(signatures_a),
            functions_b=len(signatures_b),
            diff_rows=len(diff.rows),
            similarity_record_count=similarity_record_count,
            output_path=output_path,
            similarities=emitted,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "Glaurung opcode n-gram similarity is deterministic patch-triage metadata, not BSim equivalence.",
                "For high-confidence n-day work, prefer PDB-backed identity or external BSim when available.",
            ],
        )


def _function_signatures(
    binary_path: str,
    *,
    ngram_size: int,
    max_functions: int,
    skip_anonymous: bool,
) -> dict[str, _FunctionSignature]:
    analysis = getattr(g, "analysis")
    funcs, _ = analysis.analyze_functions_path(str(binary_path))
    signatures: dict[str, _FunctionSignature] = {}
    for func in funcs:
        if len(signatures) >= max_functions:
            break
        name = str(func.name)
        if skip_anonymous and name.startswith("sub_"):
            continue
        signature = _signature_for_function(binary_path, func, ngram_size=ngram_size)
        if signature is None:
            continue
        signatures.setdefault(signature.name, signature)
    return signatures


def _signature_for_function(
    binary_path: str,
    func,
    *,
    ngram_size: int,
) -> _FunctionSignature | None:
    rng = getattr(func, "range", None)
    if rng is None or int(rng.size) <= 0:
        return None
    entry_va = int(func.entry_point.value)
    size = int(rng.size)
    body = _function_bytes(binary_path, int(rng.start.value), size)
    if not body:
        return None
    tokens = _opcode_tokens(binary_path, entry_va, size)
    return _FunctionSignature(
        name=str(func.name),
        entry_va=entry_va,
        size=size,
        body_hash=hashlib.sha256(body).hexdigest()[:16],
        opcode_ngrams=set(_tuple_ngrams(tokens, ngram_size)),
        byte_ngrams=set(_byte_ngrams(body, ngram_size)),
    )


def _function_bytes(binary_path: str, va: int, size: int) -> bytes:
    try:
        analysis = getattr(g, "analysis")
        offset = analysis.va_to_file_offset_path(
            str(binary_path),
            int(va),
            100_000_000,
            100_000_000,
        )
    except Exception:
        return b""
    if offset is None:
        return b""
    try:
        with open(binary_path, "rb") as handle:
            handle.seek(int(offset))
            return handle.read(size)
    except OSError:
        return b""


def _opcode_tokens(binary_path: str, entry_va: int, size: int) -> list[str]:
    try:
        disasm = getattr(g, "disasm")
        instructions = disasm.disassemble_window_at(
            str(binary_path),
            int(entry_va),
            window_bytes=max(1, int(size)),
            max_instructions=4096,
            max_time_ms=2000,
        )
    except Exception:
        return []
    return [
        str(getattr(instruction, "mnemonic", "")).lower()
        for instruction in instructions
        if str(getattr(instruction, "mnemonic", "")).strip()
    ]


def _similarity_records(
    diff: BinaryDiff,
    *,
    signatures_a: dict[str, _FunctionSignature],
    signatures_b: dict[str, _FunctionSignature],
    ngram_size: int,
    min_similarity_score: float,
    include_same: bool,
    match_added_removed: bool,
) -> list[WindowsFunctionSimilarityRecord]:
    records: list[WindowsFunctionSimilarityRecord] = []
    for row in diff.rows:
        if row.status == "same" and not include_same:
            continue
        if row.status in {"same", "changed"}:
            a = signatures_a.get(row.name)
            b = signatures_b.get(row.name)
            if a is None or b is None:
                continue
            status = cast(SimilarityPairStatus, row.status)
            record = _score_pair(
                row.name,
                row.name,
                status,
                a,
                b,
                ngram_size=ngram_size,
            )
        elif row.status == "added" and match_added_removed:
            b = signatures_b.get(row.name)
            if b is None:
                continue
            record = _best_match_record(
                row.name,
                "added",
                b,
                signatures_a.values(),
                ngram_size=ngram_size,
            )
        elif row.status == "removed" and match_added_removed:
            a = signatures_a.get(row.name)
            if a is None:
                continue
            record = _best_match_record(
                row.name,
                "removed",
                a,
                signatures_b.values(),
                ngram_size=ngram_size,
            )
        else:
            continue
        if record is not None and record.similarity_score >= min_similarity_score:
            records.append(record)
    records.sort(key=lambda item: (-item.similarity_score, item.function))
    return records


def _best_match_record(
    function_name: str,
    status: SimilarityPairStatus,
    source: _FunctionSignature,
    candidates: Iterable[_FunctionSignature],
    *,
    ngram_size: int,
) -> WindowsFunctionSimilarityRecord | None:
    best: WindowsFunctionSimilarityRecord | None = None
    for candidate in candidates:
        if not isinstance(candidate, _FunctionSignature):
            continue
        if status == "added":
            record = _score_pair(
                function_name,
                candidate.name,
                status,
                candidate,
                source,
                ngram_size=ngram_size,
            )
        else:
            record = _score_pair(
                function_name,
                candidate.name,
                status,
                source,
                candidate,
                ngram_size=ngram_size,
            )
        if best is None or record.similarity_score > best.similarity_score:
            best = record
    return best


def _score_pair(
    function_name: str,
    matched_function: str,
    status: SimilarityPairStatus,
    a: _FunctionSignature,
    b: _FunctionSignature,
    *,
    ngram_size: int,
) -> WindowsFunctionSimilarityRecord:
    opcode_score = _jaccard(a.opcode_ngrams, b.opcode_ngrams)
    byte_score = _jaccard(a.byte_ngrams, b.byte_ngrams)
    size_score = _size_ratio(a.size, b.size)
    if a.body_hash == b.body_hash:
        score = 1.0
    elif opcode_score is not None:
        score = (
            (opcode_score * 0.72) + ((byte_score or 0.0) * 0.18) + (size_score * 0.10)
        )
    else:
        score = ((byte_score or 0.0) * 0.85) + (size_score * 0.15)
    score = round(max(0.0, min(1.0, score)), 4)
    return WindowsFunctionSimilarityRecord(
        function=function_name,
        matched_function=matched_function,
        status=status,
        similarity_score=score,
        similarity_algorithm=f"glaurung_opcode_{ngram_size}gram",
        a_entry_va=a.entry_va,
        b_entry_va=b.entry_va,
        a_size=a.size,
        b_size=b.size,
        opcode_ngram_jaccard=None if opcode_score is None else round(opcode_score, 4),
        byte_ngram_jaccard=None if byte_score is None else round(byte_score, 4),
        size_ratio=round(size_score, 4),
        evidence=[
            "windows_function_similarity_manifest",
            f"status:{status}",
            f"opcode_ngram_size:{ngram_size}",
            f"a_hash:{a.body_hash}",
            f"b_hash:{b.body_hash}",
        ],
    )


def _tuple_ngrams(tokens: list[str], ngram_size: int) -> list[tuple[str, ...]]:
    if len(tokens) < ngram_size:
        return [tuple(tokens)] if tokens else []
    return [
        tuple(tokens[index : index + ngram_size])
        for index in range(0, len(tokens) - ngram_size + 1)
    ]


def _byte_ngrams(body: bytes, ngram_size: int) -> list[bytes]:
    if len(body) < ngram_size:
        return [body] if body else []
    return [
        body[index : index + ngram_size] for index in range(len(body) - ngram_size + 1)
    ]


def _jaccard(left: set, right: set) -> float | None:
    if not left or not right:
        return None
    return len(left & right) / len(left | right)


def _size_ratio(left: int, right: int) -> float:
    larger = max(left, right)
    if larger <= 0:
        return 0.0
    return min(left, right) / larger


def _write_manifest(
    path_text: str | None,
    records: list[WindowsFunctionSimilarityRecord],
) -> str | None:
    if not path_text:
        return None
    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"similarities": [record.model_dump(mode="json") for record in records]}
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return str(path)


def build_tool() -> WindowsFunctionSimilarityManifestTool:
    return WindowsFunctionSimilarityManifestTool()
