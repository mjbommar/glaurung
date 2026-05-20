from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb import xref_db
from ..kb.export import export_to_ghidra_script, export_to_ida_script
from ..kb.models import Edge, Node, NodeKind
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_agent_evidence_bundle import (
    WindowsEvidenceBundle,
    WindowsEvidenceCoverage,
    WindowsEvidenceSubject,
    evidence_ref,
    make_windows_evidence_bundle,
)


NotebookMode = Literal["export", "import"]
NotebookDecisionKind = Literal[
    "function_name",
    "comment",
    "data_label",
    "function_start_decision",
    "demotion",
    "suppression",
]
FunctionStartDecisionState = Literal[
    "strict_function",
    "code_label",
    "candidate",
    "rejected_start",
    "suppressed_false_start",
]


class WindowsNotebookDecision(BaseModel):
    kind: NotebookDecisionKind
    va: int
    va_hex: str | None = None
    name: str | None = None
    comment: str | None = None
    state: FunctionStartDecisionState | None = None
    reason: str | None = None
    c_type: str | None = None
    size: int | None = None
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    set_by: str = "manual"
    provenance: list[str] = Field(default_factory=list)


class WindowsAnalystNotebook(BaseModel):
    schema_version: str = "1"
    project_path: str
    binary_id: int | None = None
    decisions: list[WindowsNotebookDecision] = Field(default_factory=list)
    transcript: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WindowsAnalystNotebookArgs(BaseModel):
    mode: NotebookMode = Field(
        "export",
        description="Export a .glaurung project to a notebook or import notebook decisions.",
    )
    project_path: str = Field(..., description="Path to a .glaurung project.")
    notebook_path: str | None = Field(
        None,
        description="Optional JSON notebook path to read in import mode or write in export mode.",
    )
    decisions: list[WindowsNotebookDecision] = Field(
        default_factory=list,
        description="Notebook decisions to append on export or apply on import.",
    )
    include_scripts: bool = Field(
        True,
        description="If true, include IDAPython and Ghidra script exports.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact notebook evidence node to the in-memory KB.",
    )


class WindowsAnalystNotebookResult(BaseModel):
    notebook: WindowsAnalystNotebook
    notebook_json: str
    ida_script: str | None = None
    ghidra_script: str | None = None
    applied_count: int = 0
    unsupported_count: int = 0
    evidence_bundle: WindowsEvidenceBundle
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsAnalystNotebookTool(
    MemoryTool[WindowsAnalystNotebookArgs, WindowsAnalystNotebookResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_analyst_notebook",
                description=(
                    "Import/export analyst notebook decisions for Windows "
                    ".glaurung projects, including IDA/Ghidra scripts, names, "
                    "comments, data labels, and visible function-start demotions."
                ),
                tags=("windows", "pe", "notebook", "ida", "ghidra", "agentic"),
            ),
            WindowsAnalystNotebookArgs,
            WindowsAnalystNotebookResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsAnalystNotebookArgs,
    ) -> WindowsAnalystNotebookResult:
        project_path = Path(args.project_path).expanduser()
        if not project_path.exists():
            raise ValueError(f"{project_path}: .glaurung project does not exist")

        if args.mode == "import":
            result = _import_notebook(project_path, args)
        else:
            result = _export_notebook(project_path, args)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_analyst_notebook",
                    props={
                        "mode": args.mode,
                        "project_path": str(project_path),
                        "decision_count": len(result.notebook.decisions),
                        "applied_count": result.applied_count,
                        "unsupported_count": result.unsupported_count,
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))
        result.evidence_node_id = evidence_node_id
        return result


def _export_notebook(
    project_path: Path,
    args: WindowsAnalystNotebookArgs,
) -> WindowsAnalystNotebookResult:
    kb = PersistentKnowledgeBase.open(project_path)
    try:
        decisions = [
            *_export_function_names(kb),
            *_export_comments(kb),
            *_export_data_labels(kb),
            *_export_bookmark_decisions(kb),
            *[_normalize_decision(decision) for decision in args.decisions],
        ]
        notebook = WindowsAnalystNotebook(
            project_path=str(project_path),
            binary_id=kb.binary_id,
            decisions=decisions,
            transcript=_transcript(decisions),
            notes=[
                "notebook export preserves analyst decisions; generated scripts are not executed",
                "function-start demotions are exported as visible decisions/bookmarks",
            ],
        )
        ida_script = export_to_ida_script(kb) if args.include_scripts else None
        ghidra_script = export_to_ghidra_script(kb) if args.include_scripts else None
    finally:
        kb.close()

    notebook_json = _notebook_json(notebook)
    if args.notebook_path:
        Path(args.notebook_path).expanduser().write_text(
            notebook_json, encoding="utf-8"
        )
    return WindowsAnalystNotebookResult(
        notebook=notebook,
        notebook_json=notebook_json,
        ida_script=ida_script,
        ghidra_script=ghidra_script,
        evidence_bundle=_evidence_bundle(
            notebook=notebook,
            mode="export",
            applied_count=0,
            unsupported_count=0,
        ),
        notes=[
            "export mode is a handoff only; import mode must apply decisions explicitly"
        ],
    )


def _import_notebook(
    project_path: Path,
    args: WindowsAnalystNotebookArgs,
) -> WindowsAnalystNotebookResult:
    notebook = _load_or_build_notebook(project_path, args)
    applied_count = 0
    unsupported_count = 0
    kb = PersistentKnowledgeBase.open(project_path)
    try:
        for decision in notebook.decisions:
            applied = _apply_decision(kb, _normalize_decision(decision))
            if applied:
                applied_count += 1
            else:
                unsupported_count += 1
        ida_script = export_to_ida_script(kb) if args.include_scripts else None
        ghidra_script = export_to_ghidra_script(kb) if args.include_scripts else None
    finally:
        kb.close()

    notebook = notebook.model_copy(
        update={
            "project_path": str(project_path),
            "transcript": _transcript(notebook.decisions),
            "notes": [
                "import mode applied supported decisions to the .glaurung project",
                "function-start demotions are persisted as comments and bookmarks",
            ],
        }
    )
    notebook_json = _notebook_json(notebook)
    if args.notebook_path:
        Path(args.notebook_path).expanduser().write_text(
            notebook_json, encoding="utf-8"
        )
    return WindowsAnalystNotebookResult(
        notebook=notebook,
        notebook_json=notebook_json,
        ida_script=ida_script,
        ghidra_script=ghidra_script,
        applied_count=applied_count,
        unsupported_count=unsupported_count,
        evidence_bundle=_evidence_bundle(
            notebook=notebook,
            mode="import",
            applied_count=applied_count,
            unsupported_count=unsupported_count,
        ),
        notes=[
            "notebook import does not execute IDA/Ghidra scripts",
            "function-start decisions are analyst annotations until scanner rules consume them",
        ],
    )


def _export_function_names(
    kb: PersistentKnowledgeBase,
) -> list[WindowsNotebookDecision]:
    return [
        _normalize_decision(
            WindowsNotebookDecision(
                kind="function_name",
                va=item.entry_va,
                name=item.canonical,
                comment=item.demangled,
                set_by=item.set_by or "unknown",
                provenance=["glaurung:function_names"],
            )
        )
        for item in xref_db.list_function_names(kb)
    ]


def _export_comments(kb: PersistentKnowledgeBase) -> list[WindowsNotebookDecision]:
    return [
        _normalize_decision(
            WindowsNotebookDecision(
                kind="comment",
                va=va,
                comment=body,
                provenance=["glaurung:comments"],
            )
        )
        for va, body in xref_db.list_comments(kb)
    ]


def _export_data_labels(kb: PersistentKnowledgeBase) -> list[WindowsNotebookDecision]:
    return [
        _normalize_decision(
            WindowsNotebookDecision(
                kind="data_label",
                va=item.va,
                name=item.name,
                c_type=item.c_type,
                size=item.size,
                set_by=item.set_by or "unknown",
                provenance=["glaurung:data_labels"],
            )
        )
        for item in xref_db.list_data_labels(kb)
    ]


def _export_bookmark_decisions(
    kb: PersistentKnowledgeBase,
) -> list[WindowsNotebookDecision]:
    decisions: list[WindowsNotebookDecision] = []
    for bookmark in xref_db.list_bookmarks(kb):
        if not bookmark.note.startswith("function_start_decision:"):
            continue
        decisions.append(
            _normalize_decision(
                WindowsNotebookDecision(
                    kind="function_start_decision",
                    va=bookmark.va,
                    state=_state_from_note(bookmark.note),
                    reason=bookmark.note,
                    set_by=bookmark.set_by,
                    provenance=["glaurung:bookmarks"],
                )
            )
        )
    return decisions


def _load_or_build_notebook(
    project_path: Path,
    args: WindowsAnalystNotebookArgs,
) -> WindowsAnalystNotebook:
    if args.notebook_path:
        path = Path(args.notebook_path).expanduser()
        if path.exists():
            return WindowsAnalystNotebook(
                **json.loads(path.read_text(encoding="utf-8"))
            )
    return WindowsAnalystNotebook(
        project_path=str(project_path),
        decisions=[_normalize_decision(decision) for decision in args.decisions],
    )


def _apply_decision(
    kb: PersistentKnowledgeBase, decision: WindowsNotebookDecision
) -> bool:
    if decision.kind == "function_name" and decision.name:
        xref_db.set_function_name(
            kb,
            decision.va,
            decision.name,
            set_by=decision.set_by,
        )
        return True
    if decision.kind == "comment" and decision.comment is not None:
        xref_db.set_comment(
            kb,
            decision.va,
            decision.comment,
            set_by=decision.set_by,
        )
        return True
    if decision.kind == "data_label" and decision.name:
        xref_db.set_data_label(
            kb,
            decision.va,
            decision.name,
            c_type=decision.c_type,
            size=decision.size,
            set_by=decision.set_by,
        )
        return True
    if decision.kind in {
        "function_start_decision",
        "demotion",
        "suppression",
    }:
        note = _decision_note(decision)
        xref_db.add_bookmark(kb, decision.va, note, set_by=decision.set_by)
        xref_db.set_comment(kb, decision.va, note, set_by=decision.set_by)
        return True
    return False


def _evidence_bundle(
    *,
    notebook: WindowsAnalystNotebook,
    mode: NotebookMode,
    applied_count: int,
    unsupported_count: int,
) -> WindowsEvidenceBundle:
    refs = [
        evidence_ref(
            kind="project_fact",
            source="windows_analyst_notebook",
            summary=f"{decision.kind} at {decision.va_hex}",
            address=decision.va,
            confidence=decision.confidence,
            reason_codes=[decision.kind, decision.state or ""],
            provenance=decision.provenance,
        )
        for decision in notebook.decisions[:16]
    ]
    return make_windows_evidence_bundle(
        claim_level="triage_evidence_bundle_not_finding",
        subject=WindowsEvidenceSubject(
            kind="generic",
            binary=None,
            attributes={
                "project_path": notebook.project_path,
                "binary_id": notebook.binary_id,
                "mode": mode,
            },
        ),
        source_tools=["windows_analyst_notebook"],
        evidence_refs=refs,
        coverage=WindowsEvidenceCoverage(
            fact_coverage=["function_names", "comments", "data_labels", "bookmarks"],
            missing_facts=[],
        ),
        blockers=(
            [f"unsupported notebook decisions: {unsupported_count}"]
            if unsupported_count
            else []
        ),
        next_actions=["review imported decisions", "export IDA/Ghidra scripts"],
        notes=[
            f"mode={mode}",
            f"decision_count={len(notebook.decisions)}",
            f"applied_count={applied_count}",
        ],
    )


def _normalize_decision(decision: WindowsNotebookDecision) -> WindowsNotebookDecision:
    if decision.va_hex:
        return decision
    return decision.model_copy(update={"va_hex": f"0x{decision.va:x}"})


def _state_from_note(note: str) -> FunctionStartDecisionState | None:
    for state in (
        "strict_function",
        "code_label",
        "candidate",
        "rejected_start",
        "suppressed_false_start",
    ):
        if f"state={state}" in note:
            return state
    return None


def _decision_note(decision: WindowsNotebookDecision) -> str:
    state = decision.state or (
        "suppressed_false_start" if decision.kind == "suppression" else "code_label"
    )
    reason = decision.reason or decision.comment or "analyst notebook decision"
    return (
        f"function_start_decision: kind={decision.kind} state={state} "
        f"confidence={decision.confidence if decision.confidence is not None else 'unknown'} "
        f"reason={reason}"
    )


def _transcript(decisions: list[WindowsNotebookDecision]) -> list[str]:
    return [
        f"{decision.kind} {decision.va_hex or f'0x{decision.va:x}'} "
        f"{decision.name or decision.state or decision.comment or ''}".rstrip()
        for decision in decisions[:64]
    ]


def _notebook_json(notebook: WindowsAnalystNotebook) -> str:
    return json.dumps(notebook.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


def build_tool() -> WindowsAnalystNotebookTool:
    return WindowsAnalystNotebookTool()
