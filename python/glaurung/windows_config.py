"""Shared Windows PE analysis configuration.

The Windows pipeline touches several entry points: CFG, decompile, view,
project bootstrap, and project xref indexing. Keep their resource defaults
in one place so large system binaries such as ntoskrnl.exe do not silently
fall back to the small generic CLI budgets.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG_PATH = Path(".glaurung/windows-analysis.yaml")
ENV_CONFIG_PATH = "GLAURUNG_WINDOWS_ANALYSIS_CONFIG"


@dataclass(frozen=True)
class WindowsAnalysisConfig:
    max_read_bytes: int = 104_857_600
    max_file_size: int = 104_857_600
    max_functions: int = 0
    max_blocks: int = 1_000_000
    max_instructions: int = 30_000_000
    timeout_ms: int = 600_000
    pdb_cache_dir: str | None = None
    symbol_cache_dir: str | None = None
    symbol_server: str | None = None
    corpus_manifest: str | None = None

    @classmethod
    def load(cls, path: str | Path | None = None) -> "WindowsAnalysisConfig":
        config_path = _resolve_config_path(path)
        if config_path is None or not config_path.exists():
            return cls()
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"{config_path}: expected top-level mapping")
        allowed = {field.name for field in fields(cls)}
        data: dict[str, Any] = {}
        for key, value in raw.items():
            normalized = str(key).replace("-", "_")
            if normalized not in allowed:
                raise ValueError(f"{config_path}: unknown Windows analysis key {key!r}")
            data[normalized] = value
        return cls(**data)

    def with_overrides(self, **values: Any) -> "WindowsAnalysisConfig":
        clean = {key: value for key, value in values.items() if value is not None}
        if not clean:
            return self
        return replace(self, **clean)


def _resolve_config_path(path: str | Path | None) -> Path | None:
    if path:
        return Path(path).expanduser()
    env_path = os.environ.get(ENV_CONFIG_PATH)
    if env_path:
        return Path(env_path).expanduser()
    if DEFAULT_CONFIG_PATH.exists():
        return DEFAULT_CONFIG_PATH
    return None


def load_windows_analysis_config(path: str | Path | None = None) -> WindowsAnalysisConfig:
    return WindowsAnalysisConfig.load(path)
