from __future__ import annotations

from dataclasses import dataclass, field

import glaurung as g

from .kb.store import KnowledgeBase


@dataclass
class Budgets:
    """Execution and output budgets for tools and evidence collection."""

    max_functions: int = 5
    max_blocks: int = 2048
    max_instructions: int = 50_000
    timeout_ms: int = 200
    max_read_bytes: int = 10_485_760
    max_file_size: int = 104_857_600
    max_disasm_window: int = 4096
    max_results: int = 200


@dataclass
class MemoryContext:
    """Context passed to tools/agents.

    Holds the triage artifact, a mutable knowledge base, and budgets.
    """

    file_path: str
    artifact: g.triage.TriagedArtifact
    kb: KnowledgeBase = field(default_factory=KnowledgeBase)
    budgets: Budgets = field(default_factory=Budgets)
    session_id: str = "default"
    allow_expensive: bool = False
