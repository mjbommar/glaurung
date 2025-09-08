"""LLM integration for Glaurung.

Compatibility exports for legacy tests plus new memory-first APIs.
"""

from .config import LLMConfig, get_config
from .context import MemoryContext
from .agents.memory_agent import create_memory_agent

__all__ = [
    "LLMConfig",
    "get_config",
    "MemoryContext",
    "create_memory_agent",
]
