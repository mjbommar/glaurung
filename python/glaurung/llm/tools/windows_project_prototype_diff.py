from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb import xref_db
from ..kb.models import Edge, Node, NodeKind
from ..kb.persistent import PersistentKnowledgeBase
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


PrototypeDeltaStatus = Literal["added", "removed", "changed", "unchanged"]


class ProjectPrototypeSnapshot(BaseModel):
    function_name: str
    signature: str
    return_type: str | None = None
    params: list[dict[str, str]] = Field(default_factory=list)
    is_variadic: bool = False
    calling_convention: str | None = None
    module: str | None = None
    set_by: str | None = None
    confidence: float | None = None
    risk_tags: list[str] = Field(default_factory=list)


class ProjectPrototypeDelta(BaseModel):
    function_name: str
    status: PrototypeDeltaStatus
    before: ProjectPrototypeSnapshot | None = None
    after: ProjectPrototypeSnapshot | None = None
    changed_fields: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    security_relevance: list[str] = Field(default_factory=list)


class WindowsProjectPrototypeDiffArgs(BaseModel):
    before_project_path: str = Field(..., description="Pre-change .glaurung project.")
    after_project_path: str = Field(..., description="Post-change .glaurung project.")
    include_unchanged: bool = Field(
        False,
        description="If true, include unchanged prototypes in returned rows.",
    )
    function_name_contains: str | None = Field(
        None,
        description="Optional case-insensitive function-name substring filter.",
    )
    max_rows: int = Field(128, ge=0, description="Maximum prototype deltas to return.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact prototype-diff evidence node to the KB.",
    )


class WindowsProjectPrototypeDiffResult(BaseModel):
    before_project_path: str
    after_project_path: str
    before_prototype_count: int
    after_prototype_count: int
    added_count: int
    removed_count: int
    changed_count: int
    unchanged_count: int
    returned_count: int
    deltas: list[ProjectPrototypeDelta]
    coverage: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsProjectPrototypeDiffTool(
    MemoryTool[WindowsProjectPrototypeDiffArgs, WindowsProjectPrototypeDiffResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_project_prototype_diff",
                description=(
                    "Compare function_prototypes across two .glaurung Windows "
                    "projects and report Patch Tuesday style signature, parameter, "
                    "role, and calling-convention deltas."
                ),
                tags=("windows", "pe", "project", "patch", "diff", "prototypes"),
            ),
            WindowsProjectPrototypeDiffArgs,
            WindowsProjectPrototypeDiffResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsProjectPrototypeDiffArgs,
    ) -> WindowsProjectPrototypeDiffResult:
        before_path = Path(args.before_project_path).expanduser()
        after_path = Path(args.after_project_path).expanduser()
        if not before_path.exists():
            raise ValueError(f"{before_path}: before .glaurung project does not exist")
        if not after_path.exists():
            raise ValueError(f"{after_path}: after .glaurung project does not exist")

        before = _load_prototypes(before_path)
        after = _load_prototypes(after_path)
        deltas_all = _deltas(
            before,
            after,
            include_unchanged=args.include_unchanged,
            function_name_contains=args.function_name_contains,
        )
        deltas = deltas_all[: args.max_rows] if args.max_rows else []
        counts = _counts(deltas_all)
        coverage = _coverage(before, after, deltas_all)
        missing = _missing(before, after, deltas_all)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_project_prototype_diff",
                    props={
                        "before_project_path": str(before_path),
                        "after_project_path": str(after_path),
                        "before_prototype_count": len(before),
                        "after_prototype_count": len(after),
                        "changed_count": counts["changed"],
                        "added_count": counts["added"],
                        "removed_count": counts["removed"],
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsProjectPrototypeDiffResult(
            before_project_path=str(before_path),
            after_project_path=str(after_path),
            before_prototype_count=len(before),
            after_prototype_count=len(after),
            added_count=counts["added"],
            removed_count=counts["removed"],
            changed_count=counts["changed"],
            unchanged_count=counts["unchanged"],
            returned_count=len(deltas),
            deltas=deltas,
            coverage=coverage,
            missing_capabilities=missing,
            evidence_node_id=evidence_node_id,
            notes=[
                "project prototype diff is patch-triage metadata, not vulnerability evidence",
                "changed roles, buffer/length parameters, and risk tags should feed source/sink review",
            ],
        )


def _load_prototypes(path: Path) -> dict[str, xref_db.FunctionPrototype]:
    kb = PersistentKnowledgeBase.open(path)
    try:
        return {
            item.function_name: item for item in xref_db.list_function_prototypes(kb)
        }
    finally:
        kb.close()


def _deltas(
    before: dict[str, xref_db.FunctionPrototype],
    after: dict[str, xref_db.FunctionPrototype],
    *,
    include_unchanged: bool,
    function_name_contains: str | None,
) -> list[ProjectPrototypeDelta]:
    needle = function_name_contains.lower() if function_name_contains else None
    out: list[ProjectPrototypeDelta] = []
    for name in sorted(set(before) | set(after)):
        if needle and needle not in name.lower():
            continue
        old = before.get(name)
        new = after.get(name)
        if old is None and new is not None:
            out.append(
                ProjectPrototypeDelta(
                    function_name=name,
                    status="added",
                    after=_snapshot(new),
                    changed_fields=["prototype"],
                    reason_codes=["added_prototype"],
                    security_relevance=_security_relevance(None, new, ["prototype"]),
                )
            )
            continue
        if old is not None and new is None:
            out.append(
                ProjectPrototypeDelta(
                    function_name=name,
                    status="removed",
                    before=_snapshot(old),
                    changed_fields=["prototype"],
                    reason_codes=["removed_prototype"],
                    security_relevance=_security_relevance(old, None, ["prototype"]),
                )
            )
            continue
        if old is None or new is None:
            continue
        changed_fields = _changed_fields(old, new)
        if changed_fields or include_unchanged:
            status: PrototypeDeltaStatus = "changed" if changed_fields else "unchanged"
            out.append(
                ProjectPrototypeDelta(
                    function_name=name,
                    status=status,
                    before=_snapshot(old),
                    after=_snapshot(new),
                    changed_fields=changed_fields,
                    reason_codes=_reason_codes(status, changed_fields),
                    security_relevance=_security_relevance(old, new, changed_fields),
                )
            )
    return sorted(out, key=_sort_key)


def _snapshot(proto: xref_db.FunctionPrototype) -> ProjectPrototypeSnapshot:
    return ProjectPrototypeSnapshot(
        function_name=proto.function_name,
        signature=proto.render(),
        return_type=proto.return_type,
        params=[param.as_dict() for param in proto.params],
        is_variadic=proto.is_variadic,
        calling_convention=proto.calling_convention,
        module=proto.module,
        set_by=proto.set_by,
        confidence=proto.confidence,
        risk_tags=proto.risk_tags,
    )


def _changed_fields(
    before: xref_db.FunctionPrototype,
    after: xref_db.FunctionPrototype,
) -> list[str]:
    changed: list[str] = []
    if before.return_type != after.return_type:
        changed.append("return_type")
    before_params = [param.as_dict() for param in before.params]
    after_params = [param.as_dict() for param in after.params]
    if len(before_params) != len(after_params):
        changed.append("parameter_count")
    if [p.get("name") for p in before_params] != [p.get("name") for p in after_params]:
        changed.append("parameter_names")
    if [p.get("c_type") for p in before_params] != [
        p.get("c_type") for p in after_params
    ]:
        changed.append("parameter_types")
    if [p.get("role") for p in before_params] != [p.get("role") for p in after_params]:
        changed.append("parameter_roles")
    if before.is_variadic != after.is_variadic:
        changed.append("variadic")
    if before.calling_convention != after.calling_convention:
        changed.append("calling_convention")
    if before.module != after.module:
        changed.append("module")
    if sorted(before.risk_tags) != sorted(after.risk_tags):
        changed.append("risk_tags")
    return changed


def _reason_codes(
    status: PrototypeDeltaStatus,
    changed_fields: list[str],
) -> list[str]:
    if status == "added":
        return ["added_prototype"]
    if status == "removed":
        return ["removed_prototype"]
    if status == "unchanged":
        return ["unchanged_prototype"]
    return [f"changed_{field}" for field in changed_fields]


def _security_relevance(
    before: xref_db.FunctionPrototype | None,
    after: xref_db.FunctionPrototype | None,
    changed_fields: list[str],
) -> list[str]:
    relevance: list[str] = []
    if "parameter_roles" in changed_fields:
        relevance.append("parameter_role_delta")
    if "risk_tags" in changed_fields:
        relevance.append("risk_tag_delta")
    if "return_type" in changed_fields:
        relevance.append("return_contract_delta")
    if "parameter_types" in changed_fields or "parameter_names" in changed_fields:
        params = [*(before.params if before else []), *(after.params if after else [])]
        if any(_looks_pointer_param(param) for param in params):
            relevance.append("pointer_or_buffer_parameter_delta")
        if any(_looks_length_param(param) for param in params):
            relevance.append("length_or_count_parameter_delta")
    if "prototype" in changed_fields:
        proto = after or before
        if proto is not None:
            if proto.risk_tags:
                relevance.append("prototype_with_risk_tags_added_or_removed")
            if any(_looks_pointer_param(param) for param in proto.params):
                relevance.append("pointer_or_buffer_prototype_added_or_removed")
    return _dedupe(relevance)


def _looks_pointer_param(param: xref_db.FunctionParam) -> bool:
    haystack = f"{param.name} {param.c_type} {param.role or ''}".lower()
    return "*" in param.c_type or any(
        token in haystack for token in ("buffer", "ptr", "pointer", "irp", "mdl")
    )


def _looks_length_param(param: xref_db.FunctionParam) -> bool:
    haystack = f"{param.name} {param.c_type} {param.role or ''}".lower()
    return any(token in haystack for token in ("length", "size", "count", "bytes"))


def _counts(deltas: list[ProjectPrototypeDelta]) -> dict[str, int]:
    return {
        status: sum(1 for delta in deltas if delta.status == status)
        for status in ("added", "removed", "changed", "unchanged")
    }


def _coverage(
    before: dict[str, xref_db.FunctionPrototype],
    after: dict[str, xref_db.FunctionPrototype],
    deltas: list[ProjectPrototypeDelta],
) -> list[str]:
    coverage = []
    if before or after:
        coverage.append("function_prototypes")
    if any(delta.status != "unchanged" for delta in deltas):
        coverage.append("prototype_deltas")
    if any("parameter_roles" in delta.changed_fields for delta in deltas):
        coverage.append("parameter_role_deltas")
    if any(delta.security_relevance for delta in deltas):
        coverage.append("security_relevant_prototype_deltas")
    return coverage


def _missing(
    before: dict[str, xref_db.FunctionPrototype],
    after: dict[str, xref_db.FunctionPrototype],
    deltas: list[ProjectPrototypeDelta],
) -> list[str]:
    missing = []
    if not before:
        missing.append("before_function_prototypes")
    if not after:
        missing.append("after_function_prototypes")
    if before and after and not any(delta.status != "unchanged" for delta in deltas):
        missing.append("prototype_deltas")
    return missing


def _sort_key(delta: ProjectPrototypeDelta) -> tuple[int, str]:
    order = {"changed": 0, "added": 1, "removed": 2, "unchanged": 3}
    security_bias = 0 if delta.security_relevance else 1
    return (order[delta.status] * 2 + security_bias, delta.function_name)


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def build_tool() -> WindowsProjectPrototypeDiffTool:
    return WindowsProjectPrototypeDiffTool()
