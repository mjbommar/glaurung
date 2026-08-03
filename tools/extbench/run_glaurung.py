#!/usr/bin/env python3
"""Glaurung runner: `glaurung cfg` for discovery, `glaurung decompile --vas` for C.

    run_glaurung.py <glaurung_bin> <binary> <out.json> [--vas 0x..,0x..] [--timeout S]

`--style decbench` is used, not the default `plain`: plain emits a register-level
LLIR listing that is not C at all, so scoring it against Ghidra's and angr's C
would be measuring two different products. decbench style is the one Glaurung
itself submits to a decompiler benchmark, i.e. its best effort at C.

The whole VA batch goes through a single `decompile --vas` call because that is
the documented batch entry point and it analyses once; a per-function loop would
re-analyse the binary N times and report a throughput number that no user of the
tool would ever see.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time

glaurung_bin, binary, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
vas: list[int] = []
timeout = 1800
argv = sys.argv[4:]
for i, a in enumerate(argv):
    if a == "--vas" and i + 1 < len(argv):
        vas = [int(x, 0) for x in argv[i + 1].split(",") if x]
    if a == "--timeout" and i + 1 < len(argv):
        timeout = int(argv[i + 1])

result = {
    "tool": "glaurung",
    "binary": binary,
    "functions": [],
    "error": None,
    "analyze_s": None,
    "decompile_s": None,
}

t0 = time.time()
# --- discovery -------------------------------------------------------------
try:
    proc = subprocess.run(
        [glaurung_bin, "cfg", binary, "--format", "json"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    payload = json.loads(proc.stdout)
    result["discovered"] = [
        {
            "va": f["entry_point"],
            "name": f.get("name"),
            "thunk": False,
            "external": False,
            "blocks": f.get("basic_blocks"),
            "size": f.get("size"),
        }
        for f in payload.get("functions", [])
    ]
except subprocess.TimeoutExpired:
    result["discovered"] = []
    result["error"] = "cfg timeout"
except Exception as exc:
    result["discovered"] = []
    result["error"] = f"cfg: {type(exc).__name__}: {exc}"
result["analyze_s"] = time.time() - t0

# --- decompilation ---------------------------------------------------------
targets = vas or [d["va"] for d in result.get("discovered", [])]
t1 = time.time()
if targets:
    cmd = [
        glaurung_bin,
        "decompile",
        binary,
        "--vas",
        ",".join(hex(v) for v in targets),
        "--style",
        "decbench",
        "--format",
        "json",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        got = {}
        try:
            for item in json.loads(proc.stdout):
                got[int(item["entry_va"])] = item
        except Exception as exc:
            result["error"] = (
                f"decompile parse: {type(exc).__name__}: {exc}; "
                f"rc={proc.returncode}; stderr={proc.stderr[-400:]}"
            )
        for va in targets:
            item = got.get(va)
            if item is None:
                result["functions"].append(
                    {"va": va, "name": None, "code": None, "status": "not_found"}
                )
            else:
                code = item.get("pseudocode")
                result["functions"].append(
                    {
                        "va": va,
                        "name": item.get("name"),
                        "code": code,
                        "status": "ok" if code else "empty",
                    }
                )
    except subprocess.TimeoutExpired:
        result["error"] = f"decompile timeout after {timeout}s"
        for va in targets:
            result["functions"].append(
                {"va": va, "name": None, "code": None, "status": "timeout"}
            )
result["decompile_s"] = time.time() - t1
result["total_s"] = time.time() - t0
with open(out_path, "w") as fh:
    json.dump(result, fh)
print(f"glaurung: {len(result['functions'])} functions in {result['total_s']:.1f}s")
