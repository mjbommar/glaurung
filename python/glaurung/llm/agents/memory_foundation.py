from __future__ import annotations

from pydantic_ai import Agent, RunContext

from ..context import MemoryContext


def build_system_prompt() -> str:
    return (
        "You are a binary analysis assistant that reasons over a structured knowledge base (KB).\n"
        "Tools may add nodes and edges to the KB. Prefer using KB search to ground answers.\n"
        "Provide concise, technical, evidence-based conclusions."
    )


def inject_kb_context(ctx: RunContext[MemoryContext]) -> str:
    kb = ctx.deps.kb
    node_count = sum(1 for _ in kb.nodes())
    edge_count = sum(1 for _ in kb.edges())
    path = ctx.deps.file_path
    return f"Context: file={path}, kb_nodes={node_count}, kb_edges={edge_count}"


def create_foundation_agent(model: str | None = None) -> Agent[MemoryContext, str]:
    from ..config import get_config

    cfg = get_config()
    avail = cfg.available_models()
    default_model = model or (cfg.default_model if any(avail.values()) else "test")
    agent = Agent(
        model=default_model,
        system_prompt=build_system_prompt(),
        deps_type=MemoryContext,
        output_type=str,
    )

    @agent.system_prompt
    async def _add(ctx: RunContext[MemoryContext]) -> str:
        return inject_kb_context(ctx)

    return agent
