#!/usr/bin/env python3
"""The fingerprinted compile toolchain used by every stage of the fixture gate.

WHY
---
`tests/decompiler_fixtures/baseline.json` records a per-function verdict for each
toolchain lane. Two different compilers reach that verdict:

  1. the fixture compiler (gcc/clang x O0/O2) — its codegen idioms decide what the
     decompiler is even asked to recover;
  2. the compiler that rebuilds our own decompiled C in
     `tools/diff_decompile.py` — gcc >= 14 turns several C diagnostics that gcc 11
     merely warns about into hard errors, so "decompiled C failed to compile" is a
     function of the host gcc.

Recorded against whatever compilers a developer's host happens to ship, that
baseline is not a regression gate: it is a snapshot of one machine, and it cannot
reproduce on a CI runner with different compiler releases. Every compiler
invocation therefore runs inside the image built from
`tests/decompiler_fixtures/toolchain/Dockerfile`, whose observed compiler versions
are recorded in the baseline and asserted by the gate.

Only COMPILATION is containerised. The produced objects execute natively: the
image is deliberately old (Ubuntu 22.04, glibc 2.35), so its output loads on any
newer host or runner.

The image is NOT bit-reproducible — its base is digest-pinned but the compilers it
installs come from the live Ubuntu archive. What the gate relies on is the recorded
fingerprint: an archive update changes the version strings and fails the comparison
loudly, instead of silently changing what the baseline means.

Escape hatch: `GLAURUNG_FIXTURE_TOOLCHAIN=host` runs the host compilers directly.
It is never silent — the recorded fingerprint says `mode: host` plus the host
versions, so a baseline written that way cannot be compared against a pinned run
without the gate failing and telling you why.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE_DIR = ROOT / "tests" / "decompiler_fixtures" / "toolchain"
IMAGE = "glaurung-fixture-toolchain:1"

#: Compilers whose versions are recorded in the fingerprint. `ld`/`ldd` are
#: included because the linker and libc floor decide whether the produced object
#: loads on the executing host.
_VERSION_PROBES = (
    ("gcc", ["gcc", "--version"]),
    ("gpp", ["g++", "--version"]),
    ("clang", ["clang", "--version"]),
    ("clangpp", ["clang++", "--version"]),
    ("ld", ["ld", "--version"]),
    ("libc", ["ldd", "--version"]),
)


class ToolchainError(RuntimeError):
    """The pinned toolchain is unusable. Fail-closed: never degrade to the host
    compilers implicitly, because that silently changes what the baseline means."""


def mode() -> str:
    """`docker` (pinned, the default) or `host` (explicit opt-out)."""
    m = os.environ.get("GLAURUNG_FIXTURE_TOOLCHAIN", "docker").strip().lower()
    if m not in ("docker", "host"):
        raise ToolchainError(
            f"GLAURUNG_FIXTURE_TOOLCHAIN={m!r} is not a mode; use 'docker' or 'host'"
        )
    return m


@functools.lru_cache(maxsize=1)
def _docker() -> str:
    exe = shutil.which("docker")
    if exe is None:
        raise ToolchainError(
            "docker is required for the pinned fixture toolchain (the fixture "
            "baseline is only meaningful against pinned compilers). Install "
            "docker, or run with GLAURUNG_FIXTURE_TOOLCHAIN=host and accept that "
            "the recorded fingerprint will not match a pinned baseline."
        )
    return exe


@functools.lru_cache(maxsize=1)
def _rootless() -> bool:
    """Rootless docker maps the container's root to the invoking host user, so
    `--user $(id -u)` would land on an unprivileged subuid that cannot write to
    the mounted work directories. Rootful docker is the opposite: without
    `--user`, output files come back owned by root. Probe rather than guess."""
    r = subprocess.run(
        [_docker(), "info", "-f", "{{.SecurityOptions}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return "name=rootless" in r.stdout


@functools.lru_cache(maxsize=1)
def ensure_image() -> str:
    """Build the pinned image if it is not present. Idempotent and cheap once
    built (an inspect); the build itself is ~35s of apt on a cold cache."""
    dkr = _docker()
    have = subprocess.run(
        [dkr, "image", "inspect", IMAGE], capture_output=True, text=True, check=False
    )
    if have.returncode != 0:
        build = subprocess.run(
            [dkr, "build", "-t", IMAGE, str(DOCKERFILE_DIR)],
            capture_output=True,
            text=True,
            check=False,
        )
        if build.returncode != 0:
            raise ToolchainError(
                f"failed to build {IMAGE} from {DOCKERFILE_DIR}:\n"
                + build.stderr.strip()[-2000:]
            )
    return IMAGE


def _mount_dirs(argv: list[str], cwd: Path) -> list[Path]:
    """Host directories the invocation touches, mounted at their host paths so no
    argument rewriting is needed (and so DWARF `DW_AT_comp_dir`/file paths are
    identical to a host build)."""
    dirs: set[Path] = {cwd.resolve()}
    for tok in argv[1:]:
        if tok.startswith("-") and "/" not in tok:
            continue
        # A flag may carry a path (-o/path, -I/path, --sysroot=/path).
        cand = tok
        for sep in ("=",):
            if tok.startswith("-") and sep in tok:
                cand = tok.split(sep, 1)[1]
        if "/" not in cand:
            continue
        p = Path(cand)
        if not p.is_absolute():
            p = cwd / p
        p = p.resolve()
        dirs.add(p if p.is_dir() else p.parent)
    # Drop directories already covered by an ancestor mount.
    out: list[Path] = []
    for d in sorted(dirs, key=lambda p: len(p.parts)):
        if not any(str(d).startswith(str(o) + "/") for o in out):
            out.append(d)
    return out


def run(
    argv: list[str], cwd: Path | None = None, timeout: int | None = None
) -> subprocess.CompletedProcess:
    """Run one compiler invocation under the pinned toolchain.

    `argv` is an ordinary compiler command line (absolute paths preferred). The
    return value is the CompletedProcess of the compiler itself, so callers treat
    it exactly like a direct `subprocess.run`.
    """
    work = (cwd or Path.cwd()).resolve()
    if mode() == "host":
        return subprocess.run(
            argv,
            cwd=str(work),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    image = ensure_image()
    cmd = [_docker(), "run", "--rm", "--network", "none"]
    if not _rootless():
        cmd += ["--user", f"{os.getuid()}:{os.getgid()}"]
    for d in _mount_dirs(argv, work):
        cmd += ["-v", f"{d}:{d}"]
    cmd += ["-w", str(work), image, *argv]
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )


@functools.lru_cache(maxsize=1)
def fingerprint() -> dict[str, str]:
    """Identity of the toolchain that produced (or is checking) a baseline.

    Recorded in `baseline.json` under `__toolchain__` and compared by the gate: a
    different compiler release means the recorded verdicts are not comparable, so
    the gate must fail loudly with a refresh instruction rather than report
    phantom regressions and improvements.
    """
    script = "; ".join(" ".join(cmd) + " 2>&1 | head -1" for _, cmd in _VERSION_PROBES)
    if mode() == "host":
        r = subprocess.run(
            ["sh", "-c", script], capture_output=True, text=True, check=False
        )
    else:
        image = ensure_image()
        r = subprocess.run(
            [_docker(), "run", "--rm", "--network", "none", image, "sh", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    if r.returncode != 0 or len(lines) != len(_VERSION_PROBES):
        raise ToolchainError(
            f"could not fingerprint the {mode()} toolchain (exit {r.returncode}):\n"
            f"{r.stdout.strip()[-800:]}\n{r.stderr.strip()[-800:]}"
        )
    fp = {"mode": mode()}
    fp.update({key: line for (key, _), line in zip(_VERSION_PROBES, lines)})
    return fp


def fingerprint_problems(
    recorded: dict | None, current: dict | None = None
) -> list[str]:
    """Reasons a baseline's toolchain is not comparable to this run's.

    Pure and dict-driven so the fast lane can unit-test the rule without docker.
    """
    if current is None:
        current = fingerprint()
    if not recorded:
        return [
            (
                "baseline records no `__toolchain__` fingerprint — regenerate it "
                "with `python tools/fixture_harness.py --write-baseline`"
            )
        ]
    problems = []
    for key in ("mode", *(k for k, _ in _VERSION_PROBES)):
        want, got = recorded.get(key), current.get(key)
        if want != got:
            problems.append(f"{key}: baseline {want!r} != current {got!r}")
    return problems


def main() -> int:
    import json
    import sys

    if "--json" in sys.argv:
        print(json.dumps(fingerprint(), indent=2, sort_keys=True))
        return 0
    for k, v in sorted(fingerprint().items()):
        print(f"{k:9s} {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
