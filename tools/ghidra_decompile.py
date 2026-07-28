#!/usr/bin/env python3
"""Decompile named functions with Ghidra — the production reference to compare against.

angr was the only comparator this project had ever measured against, and it is the
weakest credible one; choosing the comparator that makes the numbers survivable is a
way of not asking the question. Ghidra is what an analyst would actually reach for.

    tools/ghidra_decompile.py <ghidra_install_dir> <binary> [function ...]

Needs `pyghidra` (ships in the Ghidra distribution under
Ghidra/Features/PyGhidra/pypkg/dist) installed into a venv, and JDK 21+. Ghidra's
Java-script path does not compile under JDK 25's OSGi loader, which is why this
drives the decompiler through PyGhidra instead of `analyzeHeadless -postScript`.
"""

import os
import sys

os.environ.setdefault("GHIDRA_INSTALL_DIR", sys.argv[1])
import pyghidra

pyghidra.start()
binary, names = sys.argv[2], sys.argv[3:]
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

with pyghidra.open_program(binary, analyze=True) as api:
    prog = api.getCurrentProgram()
    d = DecompInterface()
    d.openProgram(prog)
    mon = ConsoleTaskMonitor()
    for f in prog.getFunctionManager().getFunctions(True):
        if names and f.getName() not in names:
            continue
        r = d.decompileFunction(f, 60, mon)
        if r.decompileCompleted():
            print(f"===== {f.getName()} =====")
            print(r.getDecompiledFunction().getC())
