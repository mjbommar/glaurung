#!/usr/bin/env python3
"""Decompile named functions with angr — the third comparator.

    tools/angr_decompile.py <binary> [function ...]

Needs angr importable (it ships in the DecBench venv at
`/nas4/data/workspace-infosec/decbench/.venv`). Run it with that interpreter.

Why angr and not only Ghidra: on the 14-program DecBench corpus angr is the best
of the three on graph edit distance (9.93 vs Ghidra 11.50), and dramatically so
at clang -O0. Ghidra is the better *analyst* tool and reads DWARF; angr recovers
source-like control flow from the instruction stream alone. They are worth
reading for different reasons, so both are kept.

Deliberately prints the raw generated C rather than a structured model, so its
output is comparable line-for-line with `glaurung decompile` and
`tools/ghidra_decompile.py`.
"""

from __future__ import annotations

import logging
import sys

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)
logging.getLogger("pyvex").setLevel(logging.CRITICAL)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    binary, names = argv[1], set(argv[2:])

    import angr

    proj = angr.Project(binary, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    for func in sorted(proj.kb.functions.values(), key=lambda f: f.addr):
        if func.is_plt or func.is_simprocedure or func.is_alignment:
            continue
        if names and func.name not in names:
            continue
        try:
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        except Exception as exc:  # noqa: BLE001 — a failure is a result worth seeing
            print(f"===== {func.name} =====\n/* angr failed: {exc} */")
            continue
        code = getattr(dec, "codegen", None)
        print(f"===== {func.name} =====")
        print(code.text if code is not None else "/* angr produced no codegen */")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
