from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Edge, Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from .windows_surface_metadata import _resolve_metadata_path


class WindowsValidationHarnessRecipeArgs(BaseModel):
    recipes_path: str | None = Field(
        None,
        description=(
            "Path to ASB data/kg/pe-validation-harness-recipes.yaml. "
            "Defaults to ASB_REPO or sibling repo."
        ),
    )
    profile_id: str | None = Field(None, description="Optional component profile id filter.")
    target_id: str | None = Field(None, description="Optional build-corpus target id filter.")
    component: str | None = Field(None, description="Optional component filename filter.")
    surface_id: str | None = Field(None, description="Optional attacker surface filter.")
    trigger_kind: str | None = Field(None, description="Optional trigger kind filter.")
    add_to_kb: bool = Field(
        False,
        description="If true, add a compact harness-recipe evidence node to the KB.",
    )


class WindowsValidationHarnessRecipe(BaseModel):
    id: str
    profile_id: str
    target_id: str
    component: str
    surfaces: list[str]
    trigger_kind: str
    setup_steps: list[str]
    stock_commands: list[str]
    current_commands: list[str]
    artifact_requirements: list[str]
    known_blockers: list[str] = Field(default_factory=list)
    operator_notes: list[str] = Field(default_factory=list)
    notes: str | None = None


class WindowsValidationHarnessRecipeResult(BaseModel):
    recipes_path: str
    recipe_count_total: int
    recipes: list[WindowsValidationHarnessRecipe]
    evidence_node_id: str | None = None
    notes: list[str] = Field(default_factory=list)


class WindowsValidationHarnessRecipeTool(
    MemoryTool[WindowsValidationHarnessRecipeArgs, WindowsValidationHarnessRecipeResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="windows_validation_harness_recipe",
                description=(
                    "Load ASB component-specific Windows validation harness recipes "
                    "with setup steps, stock/current command skeletons, artifact "
                    "requirements, and known blockers."
                ),
                tags=("windows", "pe", "validation", "harness", "metadata"),
            ),
            WindowsValidationHarnessRecipeArgs,
            WindowsValidationHarnessRecipeResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: WindowsValidationHarnessRecipeArgs,
    ) -> WindowsValidationHarnessRecipeResult:
        recipes_path = _resolve_metadata_path(
            args.recipes_path,
            "data/kg/pe-validation-harness-recipes.yaml",
        )
        recipes = [_recipe_record(entry, recipes_path) for entry in _load_yaml_list(recipes_path)]
        recipe_count_total = len(recipes)
        recipes = _filter_recipes(recipes, args)

        evidence_node_id = None
        if args.add_to_kb:
            node = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="windows_validation_harness_recipe",
                    props={
                        "profile_id": args.profile_id,
                        "target_id": args.target_id,
                        "component": args.component,
                        "surface_id": args.surface_id,
                        "trigger_kind": args.trigger_kind,
                        "recipe_matches": len(recipes),
                    },
                )
            )
            evidence_node_id = node.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=node.id, kind="has_evidence"))

        return WindowsValidationHarnessRecipeResult(
            recipes_path=str(recipes_path),
            recipe_count_total=recipe_count_total,
            recipes=recipes,
            evidence_node_id=evidence_node_id,
            notes=[
                "harness recipes are operator runbooks, not executed validation artifacts"
            ],
        )


def _load_yaml_list(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected top-level list")
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: harness recipe entry {idx} is not a mapping")
        out.append(entry)
    return out


def _recipe_record(entry: dict[str, Any], path: Path) -> WindowsValidationHarnessRecipe:
    return WindowsValidationHarnessRecipe(
        id=_required_str(entry, "id", path),
        profile_id=_required_str(entry, "profile_id", path),
        target_id=_required_str(entry, "target_id", path),
        component=_required_str(entry, "component", path),
        surfaces=_required_str_list(entry, "surfaces", path),
        trigger_kind=_required_str(entry, "trigger_kind", path),
        setup_steps=_required_str_list(entry, "setup_steps", path),
        stock_commands=_required_str_list(entry, "stock_commands", path),
        current_commands=_required_str_list(entry, "current_commands", path),
        artifact_requirements=_required_str_list(entry, "artifact_requirements", path),
        known_blockers=[str(value) for value in entry.get("known_blockers") or []],
        operator_notes=[str(value) for value in entry.get("operator_notes") or []],
        notes=str(entry.get("notes") or ""),
    )


def _filter_recipes(
    recipes: list[WindowsValidationHarnessRecipe],
    args: WindowsValidationHarnessRecipeArgs,
) -> list[WindowsValidationHarnessRecipe]:
    out = recipes
    if args.profile_id:
        out = [recipe for recipe in out if recipe.profile_id == args.profile_id]
    if args.target_id:
        out = [recipe for recipe in out if recipe.target_id == args.target_id]
    if args.component:
        needle = args.component.lower()
        out = [recipe for recipe in out if recipe.component.lower() == needle]
    if args.surface_id:
        out = [recipe for recipe in out if args.surface_id in recipe.surfaces]
    if args.trigger_kind:
        out = [recipe for recipe in out if recipe.trigger_kind == args.trigger_kind]
    return out


def _required_str(entry: dict[str, Any], key: str, path: Path) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: missing required string field {key!r}")
    return value


def _required_str_list(entry: dict[str, Any], key: str, path: Path) -> list[str]:
    values = entry.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{path}: missing non-empty {key!r}")
    out = [str(value) for value in values if str(value)]
    if len(out) != len(set(out)):
        raise ValueError(f"{path}: duplicate values in {key!r}")
    return out


def build_tool() -> WindowsValidationHarnessRecipeTool:
    return WindowsValidationHarnessRecipeTool()
