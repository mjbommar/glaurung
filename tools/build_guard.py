#!/usr/bin/env python3
"""Two things every local decompiler run needs before it means anything.

**1. The native extension must be newer than the Rust it was built from.**
Every fixture verdict is produced by shelling out to the `glaurung` CLI, which
loads `python/glaurung/_native*.so`. Nothing in that path notices that the `.so`
predates `src/ir/structure.rs`, so a run against a stale build is
indistinguishable from a run against a fresh one — it just measures the previous
commit. That has already cost a full gate cycle in this repository (see the
"stale-build lesson" in `test(gate): three ways the gate disagreed with itself`).
It is a one-`stat` check, so there is no reason for any runner to skip it.

**2. Project executables must be findable without an activated virtualenv.**
`tools/diff_decompile.py` and `tests/decompiler_fixtures/structural.py` both
invoke the bare name `glaurung`. From a shell where `.venv/bin` is not on PATH
the whole gate dies with `FileNotFoundError: [Errno 2] ... 'glaurung'`, which
reads like a harness bug rather than a missing PATH entry. Resolution order is
`GLAURUNG_BIN`, then the repo's own `.venv/bin/glaurung`, then PATH.

Harness workers also need the synced Python dependencies (notably
``pyelftools``).  An executable runner may itself start under system Python, so
workers resolve `GLAURUNG_PYTHON`, then `.venv/bin/python`, then PATH rather
than inheriting `sys.executable` blindly.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Where the PyO3 extension lands. `.parent` is asserted to exist by the tests so
#: a package-layout move cannot silently disable the staleness check.
NATIVE_GLOB = ROOT / "python" / "glaurung" / "_native*.so"

#: Everything whose change invalidates the extension.
BUILD_INPUTS = [ROOT / "src", ROOT / "Cargo.toml", ROOT / "build.rs"]

BUILD_CMD = "VIRTUAL_ENV=.venv uvx maturin develop --release"


def native_so() -> Path | None:
    """The built extension, or None if it has never been built."""
    matches = sorted(NATIVE_GLOB.parent.glob(NATIVE_GLOB.name))
    return matches[0] if matches else None


def _newest_mtime(paths) -> tuple[float, Path | None]:
    newest, where = 0.0, None
    for p in paths:
        if p.is_file():
            candidates = [p]
        elif p.is_dir():
            candidates = [q for q in p.rglob("*.rs")]
        else:
            continue
        for q in candidates:
            m = q.stat().st_mtime
            if m > newest:
                newest, where = m, q
    return newest, where


def stale_reason(so: Path | None, inputs=None) -> str | None:
    """Why the extension cannot be trusted, or None if it can.

    Deliberately returns a *reason* rather than a bool: the caller prints it, and
    "src/ir/structure.rs is newer" is what turns a confusing verdict into an
    obvious one.
    """
    if inputs is None:
        inputs = BUILD_INPUTS
    if so is None or not so.exists():
        return "the native extension has never been built"
    newest, where = _newest_mtime(inputs)
    if newest > so.stat().st_mtime:
        rel = where.relative_to(ROOT) if where and ROOT in where.parents else where
        return f"{rel} is newer than the built extension"
    return None


def check_fresh(allow_stale: bool = False) -> str | None:
    """Returns a warning string, or raises unless the caller opted out."""
    reason = stale_reason(native_so())
    if reason is None:
        return None
    msg = (
        f"STALE BUILD: {reason}.\n"
        f"  Every verdict below would describe the PREVIOUS build, not your change.\n"
        f"  Rebuild:  {BUILD_CMD}\n"
        f"  Override: --allow-stale (or GLAURUNG_ALLOW_STALE=1)"
    )
    if allow_stale or os.environ.get("GLAURUNG_ALLOW_STALE"):
        return msg
    raise SystemExit(msg)


def glaurung_bin() -> str:
    """The `glaurung` CLI to shell out to.

    `GLAURUNG_BIN` wins so a bisect or a comparison against another checkout can
    point at a specific build; the repo venv comes next so no activation is
    needed; PATH last.
    """
    declared = os.environ.get("GLAURUNG_BIN")
    if declared:
        if not Path(declared).exists():
            raise FileNotFoundError(f"GLAURUNG_BIN={declared} does not exist")
        return declared
    local = ROOT / ".venv" / "bin" / "glaurung"
    if local.exists():
        return str(local)
    found = shutil.which("glaurung")
    if found:
        return found
    raise FileNotFoundError(
        "no `glaurung` CLI: not in GLAURUNG_BIN, not at .venv/bin/glaurung, not on PATH.\n"
        f"  Build it with:  {BUILD_CMD}"
    )


def python_bin() -> str:
    """The synced Python interpreter for fixture-harness workers.

    ``tools/dectest.py`` is an executable with an ``env python3`` shebang, so a
    clean shell may start it under system Python.  Its worker process imports
    development dependencies declared in the repository's synced environment;
    using ``sys.executable`` would therefore make the same command pass only
    when the caller happened to activate the venv.
    """
    declared = os.environ.get("GLAURUNG_PYTHON")
    if declared:
        if not Path(declared).exists():
            raise FileNotFoundError(f"GLAURUNG_PYTHON={declared} does not exist")
        return declared
    local = ROOT / ".venv" / "bin" / "python"
    if local.exists():
        return str(local)
    found = shutil.which("python3") or shutil.which("python")
    if found:
        return found
    raise FileNotFoundError(
        "no Python interpreter: not in GLAURUNG_PYTHON, not at "
        ".venv/bin/python, and not on PATH.\n  Sync it with: uv sync --dev"
    )


def reexec_with_repo_python() -> None:
    """Restart an executable tool under :func:`python_bin` when necessary.

    This is intentionally opt-in rather than import-time behavior: modules such
    as ``dectest`` are imported by unit tests and must never replace the pytest
    process.  Executable entry points call it under ``if __name__ == '__main__'``.
    """
    # Do not resolve symlinks here.  A venv's ``python`` commonly symlinks to
    # the same base binary as system Python; the executable inode is the same
    # while ``sys.prefix`` and therefore installed dependencies are not.
    target = Path(python_bin()).absolute()
    current = Path(sys.executable).absolute()
    if current == target:
        return
    os.execv(str(target), [str(target), *sys.argv])


def export_bin_to_path(env: dict | None = None) -> dict:
    """An environment where the bare name `glaurung` resolves.

    The harness invokes `glaurung` by name from several places; rather than
    thread a path through all of them, put its directory on PATH once.
    """
    env = dict(os.environ if env is None else env)
    bindir = str(Path(glaurung_bin()).parent)
    if bindir not in env.get("PATH", "").split(os.pathsep):
        env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
    return env


def main() -> int:
    so = native_so()
    reason = stale_reason(so)
    print(f"native extension: {so if so else '(absent)'}")
    print(f"glaurung CLI:     {glaurung_bin()}")
    print(f"worker Python:    {python_bin()}")
    if reason:
        print(f"STALE: {reason}\n  rebuild: {BUILD_CMD}")
        return 1
    print("fresh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
