"""Keep this project's temporary files off the shared `/tmp` tmpfs.

`/tmp` on this host is a 62 GB tmpfs with a **per-user quota**, shared with
every other project running here. It exhausts long before `df` reports full, and
when it does it never says "disk full" — it has surfaced as a plausible
assertion failure inside a DecBench test, as eight fabricated `pass->fail`
"SEMANTIC REGRESSIONS" in the fixture matrix, as a pytest `INTERNALERROR` from
`OSError: [Errno 122]` raised inside `terminal.py` `flush()` that reported *exit
code 0 with no test results at all*, and twice as the shell dying outright with
every command returning nonzero and no output.

Every one of those cost far more to diagnose than to prevent, and none of them
looked like a disk problem.

Importing this module points `TMPDIR` at a directory on the root filesystem
(~466 GB) unless the caller has already chosen one. That covers `tempfile`, and
therefore the fixture harness, `pytest`, `subprocess` children, and — the one
that actually did the damage — `maturin develop`, which writes a fresh wheel to
`TMPDIR` on every rebuild.

This is dev tooling only. It is deliberately *not* imported by the `glaurung`
package: a library has no business rewriting its caller's environment.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

#: Where this project's scratch goes when the caller has not said otherwise.
#: On `/` rather than the tmpfs, and outside the repository so it never shows up
#: in `git status` or gets swept by a clean.
DEFAULT_SCRATCH = Path.home() / ".cache" / "glaurung" / "tmp"


def ensure_tmpdir(scratch: Path | None = None) -> Path | None:
    """Point `TMPDIR` somewhere with room, unless it is already set.

    An explicitly-set `TMPDIR` is always honoured — a caller who has chosen a
    location knows something this module does not.

    **Degrades instead of raising.** Keeping `/tmp` clean is an optimisation;
    running is a requirement, and this module must never be the reason a process
    dies. The execution worker is the case that proves it:
    `build_guard.worker_env()` deliberately sets `HOME=/`, because the
    environment block sits at the top of the initial stack and its *size* shifts
    every frame beneath it — a recovered function reading an uninitialised local
    returns different garbage depending on how many variables the invoking shell
    exported, and `09_memory_effects:armv7:O2:read_counter` really did pass under
    an interactive shell and fail under `env -i` from one identical build.

    Under that fixed environment `Path.home()` is `/`, so the default scratch
    becomes `/.cache/glaurung/tmp` and creating it raises `PermissionError`. An
    earlier version of this function propagated that, which killed the worker and
    turned 27 fixture tests into `worker crashed (exit 1)`. If the directory
    cannot be created we leave `tempfile` on the system default and carry on.

    Args:
        scratch: Override the default location.

    Returns:
        The directory temporary files will be created in, or `None` when the
        preferred location was unusable and the system default still applies.
    """
    existing = os.environ.get("TMPDIR")
    target = Path(existing) if existing else (scratch or DEFAULT_SCRATCH)
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Unwritable — a fixed worker environment, a read-only home, a
        # container. Say nothing and leave the caller on the system default.
        os.environ.pop("TMPDIR", None) if not existing else None
        return None
    if not existing:
        os.environ["TMPDIR"] = str(target)
    # `tempfile` caches its directory on first use, so setting the environment
    # variable alone is not enough inside an already-running interpreter.
    tempfile.tempdir = str(target)
    return target


ensure_tmpdir()
