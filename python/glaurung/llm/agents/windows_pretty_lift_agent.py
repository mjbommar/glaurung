from __future__ import annotations

from pydantic_ai import Agent

from ..context import MemoryContext
from ..tools.windows_function_pretty_lift import PrettyLift, WindowsFunctionLiftPacket


WINDOWS_PRETTY_LIFT_SYSTEM_PROMPT = """
You are a Windows reverse-engineering lift assistant.

Your input is an evidence packet from Glaurung: raw IR, extracted calls,
ordered callsites, callsite argument ABI locations, callsite return targets, entry ABI locations, prototypes, memory accesses, output writes, path conditions,
field-offset groups, selector tables, constants, and API-contract primitives. Produce cleaner C-like pseudocode for an
analyst, but do not invent facts. Preserve every security-relevant call,
call order, call return target, constant, prototype-backed callsite and entry argument/type, memory access, output write, return status,
field-offset relation, selector/table relation, guard condition, loop summary,
and explicit unknown section. If you infer a type, argument
name, field name, or status, list it in assumptions unless the packet directly
backs it.

Prefer readable C over register-level output:
- remove raw Glaurung labels, flag temporaries, and stack spill names;
- avoid Ghidra split-body artifacts such as FUN_* and unaff_*;
- keep byte offsets when structure field names are not backed;
- return a PrettyLift object with a compact prototype, pseudocode, assumptions,
  confidence, and evidence_line_map where possible.
"""


def create_windows_pretty_lift_agent(
    *,
    model: str | None = None,
) -> Agent[MemoryContext, PrettyLift]:
    """Create the structured agent used to polish Glaurung lift packets."""

    from ..config import get_config

    cfg = get_config()
    return Agent[MemoryContext, PrettyLift](
        model=model or cfg.preferred_model(),
        output_type=PrettyLift,
        system_prompt=WINDOWS_PRETTY_LIFT_SYSTEM_PROMPT.strip(),
    )


def build_windows_pretty_lift_prompt(packet: WindowsFunctionLiftPacket) -> str:
    """Serialize the high-signal lift packet fields for a model prompt."""

    dump = packet.model_dump(
        exclude={
            "raw_pseudocode": False,
        },
        mode="json",
    )
    return (
        "Rewrite this Glaurung lift packet as evidence-backed C-like "
        "pseudocode. Preserve required_facts exactly and mark all inferred "
        "names/types in assumptions.\n\n"
        f"packet = {dump}"
    )
