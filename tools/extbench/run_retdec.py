#!/usr/bin/env python3
"""RetDec runner: whole-binary decompile, then split the .c back into functions.

    run_retdec.py <retdec-decompiler> <binary> <out.json> [--timeout S]

RetDec has no per-function entry point on a stripped binary, so it is run
whole-image (which is how anyone actually uses it) and the emitted C is split on
the `// Address range: 0x... - 0x...` banner it writes above each function. That
banner carries raw file VAs, so no rebasing is needed.

Whole-image is also RetDec's worst case for wall clock, and that is reported as
what it is rather than divided away: the tool cannot be asked for one function.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

retdec_bin, binary, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
timeout = 1800
argv = sys.argv[4:]
for i, a in enumerate(argv):
    if a == "--timeout" and i + 1 < len(argv):
        timeout = int(argv[i + 1])

RANGE_RE = re.compile(r"^// Address range: (0x[0-9a-fA-F]+) - (0x[0-9a-fA-F]+)\s*$")
# RetDec's own name for a recovered function, e.g. `function_1234` / `sub_1234`.
DEF_RE = re.compile(r"^[A-Za-z_][\w \*]*?([A-Za-z_]\w*)\s*\(.*\)\s*\{\s*$")

result = {
    "tool": "retdec",
    "binary": binary,
    "version": "v5.0",
    "functions": [],
    "error": None,
    "analyze_s": None,
    "decompile_s": None,
}

t0 = time.time()
with tempfile.TemporaryDirectory() as td:
    out_c = Path(td) / "out.c"
    cmd = [retdec_bin, binary, "-o", str(out_c), "--cleanup"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if not out_c.exists():
            result["error"] = f"no output; rc={proc.returncode}; {proc.stderr[-500:]}"
        else:
            text = out_c.read_text(errors="replace")
            lines = text.splitlines()
            # Walk the file collecting each `// Address range:` block.
            cur_va = None
            cur_name = None
            buf: list[str] = []
            for line in lines:
                m = RANGE_RE.match(line)
                if m:
                    if cur_va is not None:
                        result["functions"].append(
                            {
                                "va": cur_va,
                                "name": cur_name,
                                "code": "\n".join(buf),
                                "status": "ok",
                            }
                        )
                    cur_va = int(m.group(1), 16)
                    cur_name = None
                    buf = []
                    continue
                if cur_va is not None:
                    if cur_name is None:
                        d = DEF_RE.match(line)
                        if d:
                            cur_name = d.group(1)
                    buf.append(line)
            if cur_va is not None:
                result["functions"].append(
                    {
                        "va": cur_va,
                        "name": cur_name,
                        "code": "\n".join(buf),
                        "status": "ok",
                    }
                )
            result["discovered"] = [
                {"va": f["va"], "name": f["name"], "thunk": False, "external": False}
                for f in result["functions"]
            ]
    except subprocess.TimeoutExpired:
        result["error"] = f"timeout after {timeout}s"

result["total_s"] = time.time() - t0
result["decompile_s"] = result["total_s"]
result.setdefault("discovered", [])
with open(out_path, "w") as fh:
    json.dump(result, fh)
print(
    f"retdec: {len(result['functions'])} functions in {result['total_s']:.1f}s"
    + (f" ERROR={result['error']}" if result["error"] else "")
)
