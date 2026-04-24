"""Tool #13: classify one function into a small role vocabulary.

Layer 2 function-level. The role label (``parser``, ``crypto_core``,
``file_io``, ``dispatch_table``, …) is a lever that steers every
downstream decision for this function:

- #14 ``rewrite_function_idiomatic`` uses it to pick a rewriting style
  (a parser's loop structure survives almost verbatim; a
  dispatch_table collapses to a ``switch`` even when the original was
  an indirect-call array).
- #16 ``propose_function_name`` uses it to weight naming choices (a
  validator is always named ``is_*`` or ``validate_*``).
- #18 ``cluster_functions_into_modules`` uses it as a seed feature
  for module clustering.

Heuristic pre-filter catches obvious stubs (one-line wrappers, empty
ctors) so the LLM is only consulted for the interesting middle
ground.
"""

from __future__ import annotations

import re
from typing import Literal, Optional

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta
from ._llm_helpers import run_structured_llm


FunctionRole = Literal[
    "parser",
    "serializer",
    "validator",
    "crypto_core",
    "network_io",
    "file_io",
    "dispatch_table",
    "wrapper",
    "entry_stub",
    "ctor_dtor",
    "ioctl_handler",
    "state_machine_step",
    "getter",
    "setter",
    "other",
]


class ClassifyFunctionRoleArgs(BaseModel):
    pseudocode: str = Field(..., description="Function's decompiled pseudocode")
    c_prototype: Optional[str] = Field(
        None, description="Recovered prototype from #10, for extra context"
    )
    use_llm: bool = True


class RoleLabel(BaseModel):
    role: FunctionRole
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class ClassifyFunctionRoleResult(BaseModel):
    label: RoleLabel
    source: str = Field(..., description="'llm' | 'heuristic'")


def _heuristic(pseudocode: str, proto: Optional[str]) -> RoleLabel:
    text = pseudocode.lower()
    # Split on both newlines and semicolons so pseudocode formatted as one
    # long line is still segmented into atomic statements.
    atoms = [a.strip() for a in re.split(r"[\n;]", pseudocode) if a.strip()]

    # Specific-role checks fire before the generic "short = wrapper" rule
    # so that a 3-line network_io function isn't misclassified as wrapper.
    if any(k in text for k in ("aes_", "sha_", "md5_", "rc4", "chacha", "s_box", "sbox")):
        return RoleLabel(role="crypto_core", confidence=0.7, rationale="crypto-family identifiers")
    if any(k in text for k in ("socket(", "connect(", "sendto(", "recvfrom(", "bind(")):
        return RoleLabel(role="network_io", confidence=0.7, rationale="socket-family calls")
    if any(k in text for k in ("fopen(", "fread(", "fwrite(", "open(", "read(", "write(")):
        return RoleLabel(role="file_io", confidence=0.65, rationale="POSIX file-IO calls")
    if re.search(r"switch\s*\(", text) and text.count("case") >= 3:
        return RoleLabel(
            role="dispatch_table",
            confidence=0.65,
            rationale="switch with ≥3 cases",
        )
    if (
        re.search(
            r"return\s+\*?\s*\(\s*\w+\s*\+\s*(?:0x[0-9a-f]+|\d+)\s*\)", text
        )
        and len(atoms) <= 5
    ):
        return RoleLabel(
            role="getter",
            confidence=0.65,
            rationale="short function returning a struct-field read",
        )
    if (
        re.search(r"\*\s*\(\s*\w+\s*\+\s*(?:0x[0-9a-f]+|\d+)\s*\)\s*=", text)
        and len(atoms) <= 5
        and "return" not in text.split("*")[0]
    ):
        return RoleLabel(
            role="setter",
            confidence=0.6,
            rationale="short function dominated by struct-field writes",
        )
    # Wrapper fallback — a handful of atoms and no loops / calls of note.
    call_atoms = [a for a in atoms if "call " in a or re.search(r"\w+\(", a)]
    if (
        len(atoms) <= 5
        and len(call_atoms) <= 2
        and not re.search(r"\b(?:while|for|switch)\b", text)
    ):
        return RoleLabel(
            role="wrapper",
            confidence=0.55,
            rationale="≤5 atoms, ≤2 calls, no loop/switch",
        )
    return RoleLabel(role="other", confidence=0.25, rationale="no obvious pattern")


_SYSTEM_PROMPT = (
    "You are a reverse engineer classifying one function's role. Pick "
    "a single best label from: parser, serializer, validator, "
    "crypto_core, network_io, file_io, dispatch_table, wrapper, "
    "entry_stub, ctor_dtor, ioctl_handler, state_machine_step, "
    "getter, setter, other. Favour the most specific label that still "
    "fits. Base the decision on *how* the function uses its inputs "
    "and what it calls, not on surface-level string matches. One-line "
    "rationale citing the specific evidence."
)


def _build_prompt(args: ClassifyFunctionRoleArgs) -> str:
    parts = []
    if args.c_prototype:
        parts.append(f"Prototype: {args.c_prototype}")
    parts.append(f"Pseudocode:\n```\n{args.pseudocode}\n```")
    parts.append("Pick the single best role. Return confidence and rationale.")
    return "\n\n".join(parts)


class ClassifyFunctionRoleTool(
    MemoryTool[ClassifyFunctionRoleArgs, ClassifyFunctionRoleResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="classify_function_role",
                description="Assign one function to a small role vocabulary "
                            "(parser / serializer / validator / crypto_core "
                            "/ network_io / file_io / dispatch_table / …). "
                            "Steers rewrite style and naming.",
                tags=("llm", "functions", "layer2"),
            ),
            ClassifyFunctionRoleArgs,
            ClassifyFunctionRoleResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: ClassifyFunctionRoleArgs,
    ) -> ClassifyFunctionRoleResult:
        heur = _heuristic(args.pseudocode, args.c_prototype)
        if not args.use_llm or heur.confidence >= 0.7:
            return ClassifyFunctionRoleResult(label=heur, source="heuristic")

        prompt = _build_prompt(args)
        label = run_structured_llm(
            prompt=prompt,
            output_type=RoleLabel,
            system_prompt=_SYSTEM_PROMPT,
            fallback=lambda: heur,
        )
        source = "heuristic" if label is heur else "llm"
        return ClassifyFunctionRoleResult(label=label, source=source)


def build_tool() -> MemoryTool[
    ClassifyFunctionRoleArgs, ClassifyFunctionRoleResult
]:
    return ClassifyFunctionRoleTool()
