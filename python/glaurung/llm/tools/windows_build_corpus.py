from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_surface_metadata import _resolve_metadata_path


class WindowsBuildCorpusArgs(BaseModel):
    manifest_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-build-corpus.yaml. Defaults to ASB_REPO "
            "or sibling repo."
        ),
    )
    corpus_root: str | None = Field(
        None,
        description=(
            "Optional Windows binary corpus root. Defaults to WINDOWS_CORPUS_ROOT "
            "when set."
        ),
    )
    project_root: str | None = Field(
        None,
        description=(
            "Optional .glaurung project root. Defaults to GLAURUNG_PROJECT_ROOT "
            "when set."
        ),
    )
    target_id: str | None = Field(None, description="Optional target id filter.")
    filename: str | None = Field(
        None,
        description="Optional filename filter, e.g. ntoskrnl.exe.",
    )
    surface: str | None = Field(
        None,
        description="Optional attacker-surface filter, e.g. network or syscall.",
    )
    priority: str | None = Field(
        None,
        description="Optional priority filter, e.g. critical or high.",
    )
    binary_kind: str | None = Field(
        None,
        description="Optional binary kind filter, e.g. kernel, win32k, driver.",
    )
    max_matches: int = Field(
        16,
        description="Maximum filesystem matches to return per target and artifact kind.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact corpus-target evidence node to the KB.",
    )


class WindowsCorpusPathMatch(BaseModel):
    kind: Literal["corpus", "project"]
    path: str
    relative_path: str
    matched_glob: str
    size_bytes: int


class WindowsBuildCorpusTarget(BaseModel):
    id: str
    filename: str
    binary_kind: str
    priority: str
    scan_roles: list[str]
    surfaces: list[str]
    architectures: list[str]
    corpus_globs: list[str]
    project_globs: list[str]
    notes: str | None = None
    corpus_matches: list[WindowsCorpusPathMatch] = Field(default_factory=list)
    project_matches: list[WindowsCorpusPathMatch] = Field(default_factory=list)


class WindowsBuildCorpusResult(BaseModel):
    manifest_path: str
    corpus_root: str | None = None
    project_root: str | None = None
    target_count_total: int
    targets: list[WindowsBuildCorpusTarget]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsBuildCorpusTool(
    MemoryTool[WindowsBuildCorpusArgs, WindowsBuildCorpusResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_build_corpus",
                description=(
                    "Load ASB high-value Windows PE corpus targets and "
                    "optionally resolve matching binary/project paths."
                ),
                tags=("windows", "pe", "metadata", "corpus", "projects"),
            ),
            WindowsBuildCorpusArgs,
            WindowsBuildCorpusResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsBuildCorpusArgs,
    ) -> WindowsBuildCorpusResult:
        manifest_path = _resolve_metadata_path(
            args.manifest_path,
            "data/kg/pe-build-corpus.yaml",
        )
        targets = [_target_record(entry, manifest_path) for entry in _load_yaml_list(manifest_path)]
        target_count_total = len(targets)
        targets = _filter_targets(targets, args)

        corpus_root = _optional_root(args.corpus_root, "WINDOWS_CORPUS_ROOT")
        project_root = _optional_root(args.project_root, "GLAURUNG_PROJECT_ROOT")
        targets = [
            _attach_matches(target, corpus_root, project_root, args.max_matches)
            for target in targets
        ]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_build_corpus",
                    props={
                        "target_id": args.target_id,
                        "filename": args.filename,
                        "surface": args.surface,
                        "priority": args.priority,
                        "binary_kind": args.binary_kind,
                        "target_matches": len(targets),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsBuildCorpusResult(
            manifest_path=str(manifest_path),
            corpus_root=str(corpus_root) if corpus_root else None,
            project_root=str(project_root) if project_root else None,
            target_count_total=target_count_total,
            targets=targets,
            evidence_node_id=evidence_node_id,
            notes=[
                "build corpus metadata is a scan-target manifest, not a complete file inventory"
            ],
        )


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: corpus target entry {idx} is not a mapping")
        out.append(entry)
    return out


def _target_record(entry: dict[str, Any], path: Path) -> WindowsBuildCorpusTarget:
    return WindowsBuildCorpusTarget(
        id=_required_str(entry, "id", path),
        filename=_required_str(entry, "filename", path),
        binary_kind=_required_str(entry, "binary_kind", path),
        priority=_required_str(entry, "priority", path),
        scan_roles=_required_str_list(entry, "scan_roles", path),
        surfaces=_required_str_list(entry, "surfaces", path),
        architectures=_required_str_list(entry, "architectures", path),
        corpus_globs=_required_str_list(entry, "corpus_globs", path),
        project_globs=_required_str_list(entry, "project_globs", path),
        notes=entry.get("notes"),
    )


def _filter_targets(
    targets: list[WindowsBuildCorpusTarget],
    args: WindowsBuildCorpusArgs,
) -> list[WindowsBuildCorpusTarget]:
    out = targets
    if args.target_id:
        out = [target for target in out if target.id == args.target_id]
    if args.filename:
        filename = args.filename.lower()
        out = [target for target in out if target.filename.lower() == filename]
    if args.surface:
        out = [target for target in out if args.surface in target.surfaces]
    if args.priority:
        out = [target for target in out if target.priority == args.priority]
    if args.binary_kind:
        out = [target for target in out if target.binary_kind == args.binary_kind]
    return out


def _optional_root(raw: str | None, env_name: str) -> Path | None:
    root = raw or os.environ.get(env_name)
    if not root:
        return None
    path = Path(root).expanduser()
    if not path.exists():
        raise FileNotFoundError(path)
    return path


def _attach_matches(
    target: WindowsBuildCorpusTarget,
    corpus_root: Path | None,
    project_root: Path | None,
    max_matches: int,
) -> WindowsBuildCorpusTarget:
    limit = max(0, max_matches)
    corpus_matches = (
        _glob_matches(corpus_root, target.corpus_globs, "corpus", limit)
        if corpus_root
        else []
    )
    project_matches = (
        _glob_matches(project_root, target.project_globs, "project", limit)
        if project_root
        else []
    )
    return target.model_copy(
        update={
            "corpus_matches": corpus_matches,
            "project_matches": project_matches,
        }
    )


def _glob_matches(
    root: Path,
    patterns: list[str],
    kind: Literal["corpus", "project"],
    limit: int,
) -> list[WindowsCorpusPathMatch]:
    if limit == 0:
        return []
    matches: list[WindowsCorpusPathMatch] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for path in sorted(root.glob(pattern)):
            if not path.is_file() or path in seen:
                continue
            seen.add(path)
            matches.append(
                WindowsCorpusPathMatch(
                    kind=kind,
                    path=str(path),
                    relative_path=str(path.relative_to(root)),
                    matched_glob=pattern,
                    size_bytes=path.stat().st_size,
                )
            )
            if len(matches) >= limit:
                return matches
    return matches


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def _required_str_list(entry: dict[str, Any], key: str, path: Path) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{path}: missing non-empty list field {key!r}")
    out = [str(value) for value in values if str(value)]
    if len(out) != len(set(out)):
        raise ValueError(f"{path}: duplicate values in {key!r}")
    return out


def build_tool() -> MemoryTool[WindowsBuildCorpusArgs, WindowsBuildCorpusResult]:
    return WindowsBuildCorpusTool()
