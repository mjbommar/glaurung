from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

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

    Persistence: when ``db_path`` is supplied, the KnowledgeBase is
    backed by a SQLite file at that path so renames/comments/types/
    KB nodes/edges survive process exit. ``open_persistent`` is the
    factory that wires this up. Otherwise ``kb`` defaults to the
    in-memory implementation, which is what every existing test relies
    on — backward-compatible.
    """

    file_path: str
    artifact: g.triage.TriagedArtifact
    kb: KnowledgeBase = field(default_factory=KnowledgeBase)
    budgets: Budgets = field(default_factory=Budgets)
    session_id: str = "default"
    allow_expensive: bool = False
    db_path: Optional[str] = None

    @classmethod
    def open_persistent(
        cls,
        file_path: str,
        artifact: g.triage.TriagedArtifact,
        db_path: str | Path,
        *,
        session: str = "main",
        budgets: Optional[Budgets] = None,
    ) -> "MemoryContext":
        """Construct a MemoryContext whose KB is a PersistentKnowledgeBase
        opened on ``db_path``. The caller is responsible for closing it
        (via ``ctx.kb.close()`` or ``with ctx.kb: ...``).
        """
        # Imported lazily so the in-memory path doesn't require sqlite3
        # to be importable at module load time.
        from .kb.persistent import PersistentKnowledgeBase

        kb = PersistentKnowledgeBase.open(
            db_path, binary_path=file_path, session=session,
        )
        return cls(
            file_path=file_path,
            artifact=artifact,
            kb=kb,
            budgets=budgets or Budgets(),
            session_id=session,
            db_path=str(db_path),
        )
