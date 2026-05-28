"""LLM integration for Glaurung.

Compatibility exports for legacy tests plus new memory-first APIs.
"""

from __future__ import annotations

import os
import warnings

# Pydantic's plugin loader imports optional telemetry plugins such as logfire
# during model-class construction. That path is expensive and can hang test
# collection on slow filesystems, while Glaurung does not rely on Pydantic
# plugins for deterministic LLM tools.
os.environ.setdefault("PYDANTIC_DISABLE_PLUGINS", "1")


# Required pydantic-ai floor. From 1.0 onward Agent.run() takes
# sampling parameters via model_settings=ModelSettings(...), not as
# top-level kwargs. Glaurung's single_pass / iterative_refinement
# agents target this API; older pydantic-ai will fail at runtime with
# the confusing "AbstractAgent.run() got an unexpected keyword argument
# 'temperature'" error.
_PYDANTIC_AI_MIN = (1, 0, 0)


def _check_pydantic_ai_version() -> None:
    try:
        import pydantic_ai as _pa
    except ImportError:  # pragma: no cover - optional dep at import time
        return
    raw = getattr(_pa, "__version__", "0.0.0")
    parts: tuple[int, ...]
    try:
        parts = tuple(int(p) for p in raw.split(".")[:3])
    except ValueError:
        return
    if parts < _PYDANTIC_AI_MIN:
        warnings.warn(
            f"Glaurung requires pydantic-ai >= "
            f"{'.'.join(str(p) for p in _PYDANTIC_AI_MIN)} (found {raw}). "
            "Sampling-parameter handoff (temperature, max_tokens, etc.) "
            "is via model_settings=ModelSettings(...) from 1.0 onward; "
            "older versions will fail with kwarg errors at run time.",
            RuntimeWarning,
            stacklevel=2,
        )


_check_pydantic_ai_version()


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
