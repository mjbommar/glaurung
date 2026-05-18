from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_surface_metadata import _resolve_metadata_path


ExpectedFixtureCase = Literal["positive", "negative"]


class WindowsRegressionFixtureCase(BaseModel):
    id: str
    expected: ExpectedFixtureCase
    description: str | None = None
    pseudocode: str


class WindowsRegressionFixture(BaseModel):
    id: str
    bug_class: str
    primitive: str
    source_roles: list[str]
    sink_kinds: list[str]
    required_gates: list[str] = Field(default_factory=list)
    cases: list[WindowsRegressionFixtureCase]


class WindowsRegressionFixtureCatalogArgs(BaseModel):
    fixtures_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-regression-fixtures.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    bug_class: str | None = Field(None, description="Optional bug class filter.")
    primitive: str | None = Field(None, description="Optional primitive filter.")
    expected: ExpectedFixtureCase | None = Field(
        None,
        description="Optional case expectation filter.",
    )
    include_pseudocode: bool = Field(
        True,
        description="If false, omit case pseudocode while preserving metadata.",
    )
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact regression-fixture evidence node to the KB.",
    )


class WindowsRegressionFixtureCatalogResult(BaseModel):
    fixtures_path: str
    fixtures: list[WindowsRegressionFixture]
    fixture_count_total: int
    case_count_total: int
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsRegressionFixtureCatalogTool(
    MemoryTool[
        WindowsRegressionFixtureCatalogArgs,
        WindowsRegressionFixtureCatalogResult,
    ]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_regression_fixture_catalog",
                description=(
                    "Load ASB reduced Windows PE regression fixtures and "
                    "filter by bug class, primitive, or positive/negative case."
                ),
                tags=("windows", "pe", "fixtures", "regression", "metadata"),
            ),
            WindowsRegressionFixtureCatalogArgs,
            WindowsRegressionFixtureCatalogResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsRegressionFixtureCatalogArgs,
    ) -> WindowsRegressionFixtureCatalogResult:
        fixtures_path = _resolve_metadata_path(
            args.fixtures_path,
            "data/kg/pe-regression-fixtures.yaml",
        )
        fixtures = [_fixture_record(entry, fixtures_path) for entry in _load_yaml_list(fixtures_path)]
        fixture_count_total = len(fixtures)
        case_count_total = sum(len(fixture.cases) for fixture in fixtures)
        fixtures = _filter_fixtures(fixtures, args)

        if not args.include_pseudocode:
            fixtures = [_strip_pseudocode(fixture) for fixture in fixtures]

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_regression_fixture_catalog",
                    props={
                        "bug_class": args.bug_class,
                        "primitive": args.primitive,
                        "expected": args.expected,
                        "fixture_matches": len(fixtures),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsRegressionFixtureCatalogResult(
            fixtures_path=str(fixtures_path),
            fixtures=fixtures,
            fixture_count_total=fixture_count_total,
            case_count_total=case_count_total,
            evidence_node_id=evidence_node_id,
            notes=[
                "fixtures are reduced semantic shapes for rule regression, not exploit code"
            ],
        )


def _filter_fixtures(
    fixtures: list[WindowsRegressionFixture],
    args: WindowsRegressionFixtureCatalogArgs,
) -> list[WindowsRegressionFixture]:
    out = fixtures
    if args.bug_class:
        out = [fixture for fixture in out if fixture.bug_class == args.bug_class]
    if args.primitive:
        out = [fixture for fixture in out if fixture.primitive == args.primitive]
    if args.expected:
        filtered: list[WindowsRegressionFixture] = []
        for fixture in out:
            cases = [case for case in fixture.cases if case.expected == args.expected]
            if cases:
                filtered.append(fixture.model_copy(update={"cases": cases}))
        out = filtered
    return out


def _strip_pseudocode(
    fixture: WindowsRegressionFixture,
) -> WindowsRegressionFixture:
    cases = [
        case.model_copy(update={"pseudocode": ""})
        for case in fixture.cases
    ]
    return fixture.model_copy(update={"cases": cases})


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: fixture entry {idx} is not a mapping")
        out.append(entry)
    return out


def _fixture_record(entry: dict[str, Any], path: Path) -> WindowsRegressionFixture:
    cases = [_case_record(case, path, entry.get("id")) for case in entry.get("cases") or []]
    expected = {case.expected for case in cases}
    if not {"positive", "negative"} <= expected:
        raise ValueError(f"{path}: fixture {entry.get('id')!r} missing positive/negative cases")
    return WindowsRegressionFixture(
        id=_required_str(entry, "id", path),
        bug_class=_required_str(entry, "bug_class", path),
        primitive=_required_str(entry, "primitive", path),
        source_roles=_required_str_list(entry, "source_roles", path),
        sink_kinds=_required_str_list(entry, "sink_kinds", path),
        required_gates=[str(gate) for gate in entry.get("required_gates") or []],
        cases=cases,
    )


def _case_record(
    raw: Any,
    path: Path,
    owner: Any,
) -> WindowsRegressionFixtureCase:
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: case for fixture {owner!r} is not a mapping")
    expected = _required_str(raw, "expected", path)
    if expected not in {"positive", "negative"}:
        raise ValueError(f"{path}: case {raw.get('id')!r} has bad expected")
    return WindowsRegressionFixtureCase(
        id=_required_str(raw, "id", path),
        expected=expected,  # type: ignore[arg-type]
        description=str(raw.get("description") or ""),
        pseudocode=_required_str(raw, "pseudocode", path),
    )


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def _required_str_list(entry: dict[str, Any], key: str, path: Path) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{path}: missing non-empty list field {key!r}")
    return [str(value) for value in values if str(value)]


def build_tool() -> MemoryTool[
    WindowsRegressionFixtureCatalogArgs,
    WindowsRegressionFixtureCatalogResult,
]:
    return WindowsRegressionFixtureCatalogTool()
