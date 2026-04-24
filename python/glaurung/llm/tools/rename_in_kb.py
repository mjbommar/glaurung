"""Tool: persist a function rename into the KB.

The naming agent produces a better label for a function — this tool
commits that decision so downstream tools (list_functions, search_kb,
decompile_function prompts) see the improved name. The KB is purely
in-memory per session, so "rename" here means "update the node label
and record the previous name as an alias in props."
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.models import Node, NodeKind
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class RenameInKBArgs(BaseModel):
    entry_va: int = Field(..., description="Entry VA identifying the function to rename")
    new_name: str = Field(..., description="Replacement label (e.g. 'parse_config')")
    rationale: Optional[str] = Field(
        None,
        description="Short note recorded alongside the rename — usually the "
                    "agent's justification. Stored in props.rename_rationale.",
    )
    create_if_missing: bool = Field(
        True,
        description="If no function node with this entry_va exists yet, create "
                    "one. Set False to refuse to rename functions that were "
                    "never enumerated.",
    )


class RenameInKBResult(BaseModel):
    node_id: str
    old_name: Optional[str]
    new_name: str
    aliases: List[str] = Field(
        default_factory=list,
        description="All names this function has ever been known by, including "
                    "the current one.",
    )
    created: bool = Field(False, description="True when a new node had to be created")


class RenameInKBTool(MemoryTool[RenameInKBArgs, RenameInKBResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="rename_in_kb",
                description="Rename a function in the session KB, preserving "
                            "the old name as an alias. Use this after "
                            "suggest_function_name picks a better label.",
                tags=("kb", "naming"),
            ),
            RenameInKBArgs,
            RenameInKBResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: RenameInKBArgs,
    ) -> RenameInKBResult:
        new_name = args.new_name.strip()
        if not new_name:
            # Soft-fail: returning a no-op result keeps the agent loop alive
            # (an empty-name proposal is a planner mistake, not a crash).
            return RenameInKBResult(
                node_id="",
                old_name=None,
                new_name="",
                aliases=[],
                created=False,
            )

        target: Optional[Node] = None
        for n in kb.nodes():
            if n.kind != NodeKind.function:
                continue
            if int(n.props.get("entry_va", -1)) == int(args.entry_va):
                target = n
                break

        created = False
        old_name: Optional[str] = None
        if target is None:
            if not args.create_if_missing:
                # Soft-fail with a sentinel — matches the empty-name branch
                # above so the agent sees a structured "no-op" reply.
                return RenameInKBResult(
                    node_id="",
                    old_name=None,
                    new_name=new_name,
                    aliases=[new_name],
                    created=False,
                )
            target = kb.add_node(
                Node(
                    kind=NodeKind.function,
                    label=new_name,
                    props={"entry_va": int(args.entry_va)},
                )
            )
            created = True
        else:
            old_name = target.label

        aliases: List[str] = list(target.props.get("aliases", []) or [])
        if old_name and old_name not in aliases and old_name != new_name:
            aliases.append(old_name)
        target.label = new_name
        target.props["aliases"] = aliases
        if args.rationale:
            target.props["rename_rationale"] = args.rationale

        # Re-index the new label so search_text can find it.
        kb._index_text(target)  # noqa: SLF001 — intentional internal use

        return RenameInKBResult(
            node_id=target.id,
            old_name=old_name,
            new_name=new_name,
            aliases=aliases + [new_name],
            created=created,
        )


def build_tool() -> MemoryTool[RenameInKBArgs, RenameInKBResult]:
    return RenameInKBTool()
