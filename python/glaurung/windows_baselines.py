"""Canonical locations of the Windows/Ghidra parity baselines.

The four JSON dashboards produced by ``scripts/windows_ghidra_parity.py`` are
runtime defaults for the ``glaurung windows`` CLI, for eleven LLM agent and
tool modules, and for the parity refresh workflow. They live under
``data/baselines/windows-ghidra-parity/`` alongside the other checked-in data
sets (``data/types/``, ``data/sigs/``); the human-readable ``.md`` tables that
accompany them stay under ``docs/history/windows-port-2026-05/``.

Every consumer spells the path once, here. The constants are repository-relative
strings because that is how they are consumed -- as argparse defaults and as
pydantic field defaults resolved against the current working directory, the same
convention ``data/types/`` and ``data/sigs/`` already use. Use :func:`repo_path`
when a caller needs an absolute path independent of the working directory.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "REPO_ROOT",
    "WINDOWS_GHIDRA_PARITY_DIR",
    "VENDOR_WINDOWS_BASELINE",
    "VENDOR_WINDOWS_30_BASELINE",
    "VENDOR_WINDOWS_30_COMPARISON",
    "VENDOR_WINDOWS_30_DIAGNOSTICS",
    "repo_path",
]

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
"""Repository root, resolved from this module's location.

``python/glaurung/windows_baselines.py`` -> ``python/glaurung`` -> ``python`` ->
the repository root, matching ``glaurung.windows_analysis``'s resolution of
``data/types/stdlib-winapi-protos.json``.
"""

WINDOWS_GHIDRA_PARITY_DIR: str = "data/baselines/windows-ghidra-parity"
"""Directory holding every Glaurung-vs-Ghidra Windows parity baseline."""

VENDOR_WINDOWS_BASELINE: str = (
    f"{WINDOWS_GHIDRA_PARITY_DIR}/glaurung_vs_ghidra_vendor_windows.json"
)
"""Full vendor-Windows corpus comparison (every sample, all metrics)."""

VENDOR_WINDOWS_30_BASELINE: str = (
    f"{WINDOWS_GHIDRA_PARITY_DIR}/glaurung_vs_ghidra_vendor_windows_30.json"
)
"""Thirty-sample comparison taken before the tiny-stub gate landed."""

VENDOR_WINDOWS_30_COMPARISON: str = (
    f"{WINDOWS_GHIDRA_PARITY_DIR}/"
    "glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json"
)
"""Current thirty-sample comparison dashboard; the default every tool reads."""

VENDOR_WINDOWS_30_DIAGNOSTICS: str = (
    f"{WINDOWS_GHIDRA_PARITY_DIR}/glaurung_vs_ghidra_vendor_windows_30_diagnostics.json"
)
"""Per-function diagnostics (missing/extra starts) for the thirty-sample run."""


def repo_path(relative: str | Path) -> Path:
    """Resolve a repository-relative path against the repository root.

    Args:
        relative: A path relative to the repository root, such as one of the
            constants in this module.

    Returns:
        The absolute path, independent of the current working directory.
    """
    return REPO_ROOT / relative
