import os
from pathlib import Path

import glaurung as g
from glaurung.llm.context import MemoryContext
from glaurung.llm.kb.adapters import import_triage
from glaurung.llm.agents.memory_agent import create_memory_agent


def test_memory_agent_tools_smoke():
    # Pick a small sample binary
    sample = Path("samples/binaries/platforms/linux/amd64/native/clang/O0/hello-clang-O0")
    assert sample.exists(), "sample binary missing"

    art = g.triage.analyze_path(str(sample), 10_000_000, 100_000_000, 1)
    ctx = MemoryContext(file_path=str(sample), artifact=art, session_id="t1")
    import_triage(ctx.kb, art, str(sample))

    agent = create_memory_agent(model="test")  # use pydantic-ai test model

    # Compute hash
    r1 = agent.run_sync("hash the file", deps=ctx)
    assert isinstance(r1.output, str)

    # Annotate (basic function discovery)
    r2 = agent.run_sync("annotate the binary functions", deps=ctx)
    assert isinstance(r2.output, str)

    # Search for hello-related strings in KB
    r3 = agent.run_sync("search KB for hello", deps=ctx)
    assert isinstance(r3.output, str)

