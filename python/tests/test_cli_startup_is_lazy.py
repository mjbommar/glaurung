"""A CLI subcommand must not pay for subsystems it does not use.

`glaurung.cli.main` used to import all 35 command classes at module scope so it
could call `setup_parser` on each. One of them, `ask`, pulls in
`glaurung.llm.agents.factory` -> `pydantic_ai` -> `pydantic_ai.mcp` /
`pydantic_graph`. Measured on the development host:

    import glaurung          (the PyO3 extension)   0.11 s
    glaurung --help          (no work at all)       3.10 s
    glaurung decompile ...   (one function)         7.16 s

`python -X importtime -c "import glaurung.cli"` attributed 1417 ms of a 1467 ms
import to `glaurung.cli.commands.ask`. So every `glaurung decompile` spent
roughly 1.4 s constructing an LLM agent stack it never touches.

That is not merely slow interactively. `tools/diff_decompile.py` invokes the
decompile CLI once per function, and a full fixture matrix issues thousands of
those invocations, so the wasted imports dominated the gate's wall clock.

These tests run the CLI in a subprocess and inspect `sys.modules`, because that
is the only way to observe what an invocation actually loaded.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

#: Subsystems no plain analysis subcommand has any reason to load.
HEAVY = ("pydantic_ai", "pydantic_graph")


def _modules_after(argv: list[str]) -> set[str]:
    """Top-level modules loaded after running the CLI with `argv`.

    `--help` raises SystemExit, which is exactly the cheapest path that still
    forces the parser to be built, so it is caught rather than avoided.
    """
    # The subcommand's own `--help` output goes to stdout, so the probe result
    # is written to a file rather than interleaved with it.
    script = (
        "import sys, json, os, io, contextlib\n"
        "from glaurung.cli.main import main\n"
        f"try:\n"
        f"    with contextlib.redirect_stdout(io.StringIO()):\n"
        f"        main({argv!r})\n"
        "except SystemExit:\n    pass\n"
        "open(os.environ['PROBE_OUT'], 'w').write("
        "json.dumps(sorted({m.split('.')[0] for m in sys.modules})))\n"
    )
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "modules.json"
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env={**os.environ, "PROBE_OUT": str(out)},
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return set(json.loads(out.read_text()))


def test_decompile_does_not_import_the_llm_stack():
    """The hot path for the fixture gate must not construct an agent stack."""
    loaded = _modules_after(["decompile", "--help"])
    leaked = sorted(set(HEAVY) & loaded)
    assert not leaked, (
        f"`glaurung decompile` imported {leaked}, which it never uses. Every "
        f"invocation pays for it, and the fixture matrix issues thousands."
    )


def test_triage_does_not_import_the_llm_stack():
    """Same contract for the other most-used analysis subcommand."""
    loaded = _modules_after(["triage", "--help"])
    leaked = sorted(set(HEAVY) & loaded)
    assert not leaked, f"`glaurung triage` imported {leaked}, which it never uses"


def test_ask_still_gets_its_dependencies():
    """The negative control: laziness must not break the command that needs it.

    A test that only asserts absence would pass if the subcommand were deleted,
    so the LLM-backed command is asserted to still load its stack.
    """
    loaded = _modules_after(["ask", "--help"])
    assert "pydantic_ai" in loaded, (
        "`glaurung ask` must still load pydantic_ai; laziness may defer an "
        "import, never drop it"
    )


def test_top_level_help_still_lists_every_command():
    """Deferring imports must not shrink the advertised command set."""
    result = subprocess.run(
        [sys.executable, "-m", "glaurung.cli.main", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    text = result.stdout + result.stderr
    for name in ("triage", "decompile", "ask", "kickoff", "windows", "java"):
        assert name in text, f"`--help` no longer advertises {name!r}:\n{text}"
