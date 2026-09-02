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

**3. The execution worker must see a fixed address space and a fixed environment.**
A recovered function that reads an uninitialised local dereferences whatever the
stack happened to hold. With ASLR on that is a coin flip (`aslr_mode`); and even
with ASLR off, the environment block sits at the top of the initial stack, so its
*size* shifts every frame beneath it and the same build gives one answer in an
interactive shell and another under the pre-push gate's `env -i` (`worker_env`).
Both rules live here rather than in `tools/diff_decompile.py` because
`tools/arch_roundtrip.py` records them in its baseline fingerprint, and this
module is the one both can import without pulling in the native extension.
"""

from __future__ import annotations

import hashlib
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


def native_fingerprint(so: Path | None = None) -> str | None:
    """SHA-256 of the exact extension whose behavior a gate will measure."""
    so = native_so() if so is None else so
    if so is None or not so.is_file():
        return None
    digest = hashlib.sha256()
    with so.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def aslr_mode() -> str:
    """Whether the execution worker runs with address randomization disabled.

    This changes what a verdict MEANS. A recovery that reads an uninitialised
    local dereferences whatever the stack happened to contain, and with ASLR on
    that is a coin flip: `09_memory_effects:armv7:O2:read_counter` recovers as
    `*(int *)(*(int *)(var1 + 4) + var1)` over an uninitialised `var1` and
    segfaulted on 4 of 8 identical runs, passing on the other 4 — one flapping
    function is enough to make a ratchet unusable. With randomization off it
    fails 6 of 6, which is the correct verdict.

    Fail-soft here and fail-LOUD in the consumer: a host without `setarch`
    (util-linux) still runs, but `tools/arch_roundtrip.py` records `RANDOMIZED`
    in its baseline's `__toolchain__` and `--check` then refuses to compare
    against a baseline recorded the other way, rather than silently reporting
    phantom regressions and improvements.
    """
    return "no-randomize (setarch)" if shutil.which("setarch") else "RANDOMIZED"


def worker_launch_prefix() -> list[str]:
    """Argv prefix that disables address randomization — see `aslr_mode`."""
    setarch = shutil.which("setarch")
    return [setarch, "--addr-no-randomize"] if setarch else []


#: Variables the execution worker genuinely needs. Everything else is dropped by
#: `worker_env`.
_WORKER_ENV_KEEP = (
    "GLAURUNG_BIN",
    "GLAURUNG_PYTHON",
    "GLAURUNG_FIXTURE_TMPDIR",
)


def worker_env() -> dict:
    """A FIXED environment for the execution worker.

    Disabling randomization is not enough to make a verdict reproducible. The
    environment block sits at the top of the initial stack, so its *size* shifts
    every frame beneath it — and a recovered function that reads an uninitialised
    local therefore returns different garbage depending on how many variables the
    invoking shell happened to export. `09_memory_effects:armv7:O2:read_counter`
    passed under an interactive shell and failed under the pre-push gate's
    `env -i`, from one identical build.

    So the worker gets a canonical environment: the handful of variables it
    actually reads, plus a fixed `PATH`/locale/timezone. A verdict is then a
    property of the decompilation, not of the shell that launched the gate.
    Padding to a fixed total width keeps it stable even as those few values
    change length.
    """
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    for key in _WORKER_ENV_KEEP:
        if key in os.environ:
            env[key] = os.environ[key]
    # A fixed-width block: the values above (notably a repo-specific tmpdir) vary
    # in length between checkouts, and that alone would move the stack.
    width = sum(len(k) + len(v) + 2 for k, v in env.items())
    env["GLAURUNG_STACK_PAD"] = "0" * max(
        0, 4096 - width - len("GLAURUNG_STACK_PAD") - 2
    )
    return env


def main() -> int:
    so = native_so()
    reason = stale_reason(so)
    print(f"native extension: {so if so else '(absent)'}")
    print(f"native SHA-256:  {native_fingerprint(so) or '(absent)'}")
    print(f"glaurung CLI:     {glaurung_bin()}")
    print(f"worker Python:    {python_bin()}")
    if reason:
        print(f"STALE: {reason}\n  rebuild: {BUILD_CMD}")
        return 1
    print("fresh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
