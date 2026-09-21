"""Render the per-binary result artifacts a local DecBench replay writes.

Extracted from `decbench_redecompile_tree.py` so the shapes are testable
without starting a run, and so the timeout path has a shape at all.

WHY THE TIMEOUT PATH EXISTS. The harness used to answer a per-binary timeout
with `stats["timeout"] += 1; continue`, writing nothing. The binary then had no
artifact in the tree, and `decbench_audit_full` -- which compares the evaluated
binary set against the manifest -- reported `evaluated binary set mismatch`.
A budget we chose ourselves therefore surfaced as a corrupt tree. Upstream's
driver instead persists `failed_functions = ["all"]` with `timeout = true`, so
the run records what happened; this module mirrors that.

WHY A TIMEOUT WRITES NO `.c`. `decbench_audit_full._artifact_functions` raises
on a decompiled artifact with no `// Function:` markers, so an empty file is
rejected. Emitting stub bodies to satisfy it would be far worse: `return 0;`
parses to a one-node CFG and is GED-perfect, which is precisely the published
null baseline (`docs/design/metrics-research/interpreting-results.md`, "a stub
scores 27.24%"). A timed-out binary claims nothing.
"""

from __future__ import annotations

import pathlib
import re
from collections.abc import Mapping, Sequence

#: A TOML bare-ish identifier we are willing to interpolate unquoted into a
#: table header, and a value we are willing to place inside a basic string.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.$@?:<>~+\-\[\]]+$")

#: `(address, line_count, gotos)` for one emitted function.
FunctionRow = tuple[str, int, int]


class ResultError(ValueError):
    """Raised when a result artifact would be malformed or misleading."""


def _check_name(name: str, what: str) -> str:
    """Reject a name that would corrupt the emitted TOML.

    Args:
        name: Candidate identifier.
        what: Field description used in the error message.

    Returns:
        The name unchanged.

    Raises:
        ResultError: If the name is empty or holds a character that would
            escape its TOML context.
    """
    if not name or not _SAFE_NAME.match(name):
        raise ResultError(f"unsafe {what} for a TOML artifact: {name!r}")
    return name


def _header(binary: str, decompiler: str, version: str, total_time: float) -> list[str]:
    """Return the fields every result artifact carries, in published order."""
    return [
        f'binary = "{_check_name(binary, "binary")}"',
        f'decompiler = "{_check_name(decompiler, "decompiler")}"',
        f'version = "{_check_name(version, "version")}"',
        f"total_time = {total_time:.3f}",
    ]


def render_result_toml(
    *,
    binary: str,
    decompiler: str,
    version: str,
    total_time: float,
    functions: Mapping[str, FunctionRow],
    failed_functions: Sequence[str],
) -> str:
    """Render the artifact for a binary that produced output.

    Args:
        binary: Binary stem as the manifest names it.
        decompiler: Column name, e.g. `glaurung-abc1234`.
        version: Revision the column was produced by.
        total_time: Wall-clock seconds for this binary.
        functions: Emitted function name -> `(address, line_count, gotos)`.
        failed_functions: Requested names that produced no body.

    Returns:
        The TOML document.

    Raises:
        ResultError: If `functions` is empty -- that is the timeout/failure
            shape, and `render_timeout_toml` owns it -- or if any name would
            corrupt the document.
    """
    if not functions:
        raise ResultError(
            "a success artifact needs at least one function; "
            "use render_timeout_toml for a binary that produced none"
        )
    lines = _header(binary, decompiler, version, total_time)
    lines += [
        "timeout = false",
        f"function_count = {len(functions)}",
        "failed_functions = ["
        + ", ".join(
            f'"{_check_name(name, "failed function")}"' for name in failed_functions
        )
        + "]",
        "",
    ]
    for name, (address, line_count, gotos) in functions.items():
        lines += [
            f'["functions.{_check_name(name, "function name")}"]',
            f'address = "{_check_name(address, "address")}"',
            f"line_count = {line_count}",
            f"gotos = {gotos}",
            "bools = 0",
            "",
        ]
    return "\n".join(lines)


def render_timeout_toml(
    *,
    binary: str,
    decompiler: str,
    version: str,
    total_time: float,
    budget_seconds: int,
) -> str:
    """Render the artifact for a binary that exhausted its wall-clock budget.

    Args:
        binary: Binary stem as the manifest names it.
        decompiler: Column name, e.g. `glaurung-abc1234`.
        version: Revision the column was produced by.
        total_time: Wall-clock seconds actually spent.
        budget_seconds: The per-binary budget that was exceeded, recorded so a
            reader can tell a standard-budget failure from an override.

    Returns:
        The TOML document, declaring `failed_functions = ["all"]` and no
        function tables.
    """
    lines = _header(binary, decompiler, version, total_time)
    lines += [
        "timeout = true",
        "function_count = 0",
        'failed_functions = ["all"]',
        f"budget_seconds = {budget_seconds}",
        "",
    ]
    return "\n".join(lines)


def write_timeout_result(
    *,
    directory: pathlib.Path,
    binary: str,
    decompiler: str,
    version: str,
    total_time: float,
    budget_seconds: int,
) -> pathlib.Path:
    """Write the timeout artifact into a tree's `decompiled/` directory.

    Args:
        directory: The `decompiled/` directory to write into; created if absent.
        binary: Binary stem as the manifest names it.
        decompiler: Column name, e.g. `glaurung-abc1234`.
        version: Revision the column was produced by.
        total_time: Wall-clock seconds actually spent.
        budget_seconds: The per-binary budget that was exceeded.

    Returns:
        Path of the written `.toml`. No `.c` is written: see the module
        docstring.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{decompiler}_{binary}.toml"
    path.write_text(
        render_timeout_toml(
            binary=binary,
            decompiler=decompiler,
            version=version,
            total_time=total_time,
            budget_seconds=budget_seconds,
        )
    )
    return path
