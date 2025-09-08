"""Memory-first summarizer agent with BinarySummary output."""

from __future__ import annotations

from typing import Optional, List
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from ..context import MemoryContext
import os
from ..config import get_config


class BinarySummary(BaseModel):
    summary: str
    purpose: str
    risk_level: str = Field(default="unknown")
    key_behaviors: List[str] = Field(default_factory=list)
    recommendation: str = Field(default="Review further")


SYSTEM_PROMPT = (
    "You are a concise binary analysis assistant.\n"
    "Provide a high-level summary, purpose, risk assessment,\n"
    "key behaviors, and a recommendation. Ground answers in facts in the KB."
)


def create_summarizer_agent(
    model: Optional[str] = None,
) -> Agent[MemoryContext, BinarySummary]:
    cfg = get_config()
    avail = cfg.available_models()
    chosen = (
        model
        or cfg.summarizer_model
        or (cfg.default_model if any(avail.values()) else "test")
    )
    # If no API key for external providers, fall back to test model
    if not model and os.environ.get("OPENAI_API_KEY") is None:
        chosen = "test"
    agent = Agent(
        model=chosen,
        system_prompt=SYSTEM_PROMPT,
        deps_type=MemoryContext,
        output_type=BinarySummary,
    )

    @agent.system_prompt
    async def _inject(ctx: RunContext[MemoryContext]) -> str:
        kb = ctx.deps.kb
        node_count = sum(1 for _ in kb.nodes())
        edge_count = sum(1 for _ in kb.edges())
        return (
            f"KB nodes: {node_count}, edges: {edge_count}. File: {ctx.deps.file_path}"
        )

    return agent


async def summarize_binary(
    artifact, file_path: str, model: Optional[str] = None
) -> BinarySummary:
    from ..kb.adapters import import_triage

    # Build a minimal MemoryContext and seed KB
    ctx = MemoryContext(file_path=file_path, artifact=artifact)
    import_triage(ctx.kb, artifact, file_path)
    agent = create_summarizer_agent(model=model)
    res = await agent.run("Summarize this binary.", deps=ctx)
    return res.output


def summarize_binary_sync(
    artifact, file_path: str, model: Optional[str] = None
) -> BinarySummary:
    import asyncio

    return asyncio.run(summarize_binary(artifact, file_path, model))
