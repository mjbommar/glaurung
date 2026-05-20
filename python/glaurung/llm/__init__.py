"""LLM integration for Glaurung.

Compatibility exports for legacy tests plus new memory-first APIs.
"""

from __future__ import annotations

import os

# Pydantic's plugin loader imports optional telemetry plugins such as logfire
# during model-class construction. That path is expensive and can hang test
# collection on slow filesystems, while Glaurung does not rely on Pydantic
# plugins for deterministic LLM tools.
os.environ.setdefault("PYDANTIC_DISABLE_PLUGINS", "1")


def __getattr__(name: str):
    if name in {"LLMConfig", "get_config"}:
        from . import config

        return getattr(config, name)
    if name == "MemoryContext":
        from .context import MemoryContext

        return MemoryContext
    if name == "create_memory_agent":
        from .agents.memory_agent import create_memory_agent

        return create_memory_agent
    raise AttributeError(name)


__all__ = [
    "LLMConfig",
    "get_config",
    "MemoryContext",
    "create_memory_agent",
]
