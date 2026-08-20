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


def ensure_tmpdir(scratch: Path | None = None) -> Path:
    """Point `TMPDIR` somewhere with room, unless it is already set.

    An explicitly-set `TMPDIR` is always honoured — a caller who has chosen a
    location knows something this module does not.

    Args:
        scratch: Override the default location.

    Returns:
        The directory temporary files will now be created in.
    """
    existing = os.environ.get("TMPDIR")
    if existing:
        target = Path(existing)
    else:
        target = scratch or DEFAULT_SCRATCH
        os.environ["TMPDIR"] = str(target)
    target.mkdir(parents=True, exist_ok=True)
    # `tempfile` caches its directory on first use, so setting the environment
    # variable alone is not enough inside an already-running interpreter.
    tempfile.tempdir = str(target)
    return target


ensure_tmpdir()
