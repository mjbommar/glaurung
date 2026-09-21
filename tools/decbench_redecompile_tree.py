#!/usr/bin/env python3
"""Re-decompile the materialized DecBench sample-set tree with the CURRENT build.

Writes `decompiled/glaurung-<sha>_<stem>.c` + `.toml` beside the artifacts
already in the tree, so `decbench evaluate-tree` can score the new column and
the comparison is same-tree, same-source-CFGs, same-metric-code -- only the
decompiler revision differs.

WHY THIS EXISTS. `tools/decbench_matrix.py` spawns a Joern JVM per cell, which
is why it is opt-in and costs ~37 minutes for 56 cells. The materialized tree
already contains the expensive Joern product -- 221 extracted
`source_cfgs/*.json` -- so GED can be scored over the whole 250-function
sample-set with no Joern at all. See `docs/development/decompiler-testing.md`,
"A real DecBench score, without Joern".

DISCIPLINE. DecBench decompiles STRIPPED bytes at addresses derived from DWARF.
The materialized tree ships only `compiled/` (unstripped), so this resolves each
target function's address from that binary's symbol table, strips a COPY into
`$TMPDIR`, and decompiles the copy at those VAs. It never modifies the tree's
binaries.

BUDGETS. DecBench standardised 600s per function and 3600s per binary
(upstream `5818d67`). Those are the defaults here, because a run at a tighter
budget fails functions the published board would have scored and is therefore
not comparable to any other column. `tools/decbench_limits.py` owns the
resolution and the override names; set `BUDGET_RECEIPT=<path>` to write the
resolved budgets beside the run. For cheap local iteration:

    DECBENCH_GLAURUNG_TIMEOUT_MS=20000 DECBENCH_DECOMPILE_TIMEOUT=600 \
        python3 tools/decbench_redecompile_tree.py "$(git rev-parse --short=7 HEAD)"

...which prints `-- OVERRIDDEN {...}` and must not be published as a score.

    python3 tools/decbench_redecompile_tree.py "$(git rev-parse --short=7 HEAD)"
    python3 tools/decbench_redecompile_tree.py "$(git rev-parse --short=7 HEAD)" coreutils

The optional second argument restricts to one project, which is the smoke test:
12 binaries in about two seconds.

Then score, SCOPED to the new column -- an unscoped run re-scores every stored
artifact in the tree (2,007 of them took over 50 minutes; 215 took about 20):

    cd ~/projects/personal/decbench-glaurung-integration
    uv run decbench evaluate-tree <tree> -m ged -m byte_match -d glaurung-<sha> -j 12

`evaluate-tree` rewrites the tree's `scoreboard.toml` with only the columns it
scored, so copy the old one aside first if the previous numbers matter.
"""

import json
import pathlib
import subprocess
import sys
import time
import collections
import os
import re

from decbench_inputs import find_binary, normalise_address, strip_copy
from decbench_limits import binary_timeout_seconds, budget_receipt, function_timeout_ms
from decbench_tree_writer import render_result_toml, write_timeout_result

TREE = pathlib.Path(
    os.environ.get(
        "DECBENCH_SAMPLE_TREE",
        pathlib.Path.home() / "projects/personal/decbench-sample-set-glaurung-tree",
    )
)
G = os.environ.get(
    "GLAURUNG_BIN",
    str(pathlib.Path(__file__).resolve().parents[1] / ".venv/bin/glaurung"),
)
SHA = sys.argv[1]
ONLY = sys.argv[2] if len(sys.argv) > 2 else None
NAME = os.environ.get("DECBENCH_COLUMN", f"glaurung-{SHA}")
# Set GLAURUNG_REDECOMP_FORCE=1 to re-decompile binaries that already have output.
FORCE = os.environ.get("GLAURUNG_REDECOMP_FORCE") == "1"
TMP = pathlib.Path(os.environ["TMPDIR"]) / "redecomp"
TMP.mkdir(parents=True, exist_ok=True)

# Budgets default to DecBench's published standard; see tools/decbench_limits.py.
# A run at a tighter budget is not comparable to the published board, so the
# receipt is printed and written beside the run rather than left implicit.
BUDGETS = budget_receipt()
FUNCTION_TIMEOUT_MS = function_timeout_ms()
BINARY_TIMEOUT_S = binary_timeout_seconds()
print(
    f"budgets: {FUNCTION_TIMEOUT_MS}ms/function, {BINARY_TIMEOUT_S}s/binary"
    + (
        ""
        if BUDGETS["matches_published_standard"]
        else f" -- OVERRIDDEN {BUDGETS['overrides']}"
    ),
    flush=True,
)
_budget_receipt_path = os.environ.get("BUDGET_RECEIPT")
if _budget_receipt_path:
    pathlib.Path(_budget_receipt_path).write_text(json.dumps(BUDGETS, indent=2))

man = json.loads((TREE / "sample_set_manifest.json").read_text())["functions"]
want = collections.defaultdict(list)
for e in man:
    want[(e["opt"], e["project"], e["binary"])].append(e["function"])


def _pe_symbol_addr(binary: pathlib.Path, names):
    """name -> address for a PE binary, via glaurung's own object reader.

    `readelf` returns nothing for PE, so the 12 Windows binaries in the corpus
    (dexter, minipig, mydoom, x0r-usb at three opt levels each) were recorded
    `no-symbols` and never decompiled at all -- ~500 functions absent from the
    score, which reads as failure rather than as never-attempted.

    The name matching itself lives in `tools/decbench_symbols.py`, which is
    importable without starting a run and is tested against a real i386 PE. It
    knows three decorations rather than two: the missing one, stdcall
    `_name@N`, is DecBench failure class F1a and 33 unresolved rows in the
    pinned run.
    """
    import decbench_symbols as S

    resolutions = S.resolve_many(str(binary), names)
    # Non-LOCAL dispositions are deliberately NOT collapsed into "missing":
    # an import has no local body by construction, an ambiguity is a dataset
    # defect, and a data hit is a resolver bug. The caller records them.
    RESOLUTIONS[str(binary)] = {n: r.as_record() for n, r in resolutions.items()}
    return {n: r.address for n, r in resolutions.items() if r.ok}


#: binary path -> {requested name: resolution record}. Written into the
#: checkpoint so a run can be audited without re-reading the binaries.
RESOLUTIONS: dict[str, dict] = {}


def symbol_addr(binary: pathlib.Path, names):
    """name -> address, from the compiled binary's symbol table."""
    out = subprocess.run(
        ["readelf", "-sW", str(binary)], capture_output=True, text=True
    ).stdout
    found = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 8 and f[3] == "FUNC":
            nm = f[7].split("@")[0]
            if nm in names and nm not in found:
                try:
                    a = int(f[1], 16)
                except ValueError:
                    continue
                if a:
                    found[nm] = a
    # readelf is ELF-only; fall back to glaurung's reader for PE/Mach-O.
    if not found:
        return _pe_symbol_addr(binary, names)
    return found


stats = collections.Counter()
t0 = time.time()
keys = sorted(want)
if ONLY:
    keys = [k for k in keys if k[1] == ONLY]
for opt, proj, binstem in keys:
    d = TREE / opt / proj
    # Resume: a pass over the full corpus takes hours and ours has been killed
    # by its own `timeout` at 723/803. Re-running from scratch would redo three
    # hours of work to reach the same tail, so skip binaries already written.
    if not FORCE and (d / "decompiled" / f"{NAME}_{binstem}.c").exists():
        stats["skipped"] += 1
        continue
    src = find_binary(d / "compiled", binstem)
    if src is None or not src.exists():
        stats["no-binary"] += 1
        continue
    fns = want[(opt, proj, binstem)]
    addrs = symbol_addr(src, set(fns))
    if not addrs:
        stats["no-symbols"] += 1
        continue
    stripped = TMP / f"{opt}_{proj}_{binstem}"
    receipt = strip_copy(src, stripped)
    ledger = os.environ.get("STRIP_LEDGER")
    if ledger:
        with open(ledger, "a") as handle:
            handle.write(
                json.dumps({"opt": opt, "project": proj, "binary": binstem, **receipt})
                + "\n"
            )
    cmd = [
        G,
        "decompile",
        str(stripped),
        "--vas",
        ",".join(hex(a) for a in addrs.values()),
        "--style",
        "decbench",
        "--format",
        "json",
        "--timeout-ms",
        str(FUNCTION_TIMEOUT_MS),
    ]
    t1 = time.time()
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=BINARY_TIMEOUT_S
        )
    except subprocess.TimeoutExpired:
        # Declare the failure. Dropping the binary silently made a budget we
        # chose ourselves surface as `evaluated binary set mismatch` in the
        # audit, which reads as a corrupt tree rather than as a timeout.
        stats["timeout"] += 1
        write_timeout_result(
            directory=d / "decompiled",
            binary=binstem,
            decompiler=NAME,
            version=SHA,
            total_time=time.time() - t1,
            budget_seconds=BINARY_TIMEOUT_S,
        )
        continue
    if r.returncode != 0:
        stats["nonzero"] += 1
        continue
    try:
        recs = json.loads(r.stdout)
    except Exception:
        stats["bad-json"] += 1
        continue
    by_addr = {normalise_address(src, int(rec["entry_va"])): rec for rec in recs}
    parts, meta, failed = [], {}, []
    for nm, a in addrs.items():
        rec = by_addr.get(normalise_address(src, a))
        if rec is None:
            failed.append(nm)
            continue
        body = rec["pseudocode"]
        # DecBench keys functions by NAME; rename our sub_<va> to the DWARF name.
        body = re.sub(r"\b" + re.escape(rec["name"]) + r"\b", nm, body)
        parts.append(f"// Function: {nm} @ {hex(a)}\n{body}\n")
        meta[nm] = (hex(a), body.count("\n") + 1, body.count("goto "))
        stats["functions"] += 1
    if not parts:
        stats["no-output"] += 1
        continue
    # A tree fetched straight from the published dataset has no `decompiled/`
    # yet -- only a tree materialized from a completed pipeline run does. Create
    # it rather than requiring the caller to have run something else first.
    (d / "decompiled").mkdir(parents=True, exist_ok=True)
    out_c = d / "decompiled" / f"{NAME}_{binstem}.c"
    out_c.write_text("\n".join(parts))
    (d / "decompiled" / f"{NAME}_{binstem}.toml").write_text(
        render_result_toml(
            binary=binstem,
            decompiler=NAME,
            version=SHA,
            total_time=time.time() - t1,
            functions=meta,
            failed_functions=failed,
        )
    )
    stats["binaries"] += 1
    if stats["binaries"] % 25 == 0:
        print(
            f"  {stats['binaries']}/{len(keys)} binaries, "
            f"{stats['functions']} functions, {time.time() - t0:.0f}s",
            flush=True,
        )
print(
    f"decompiled {stats['binaries']} binaries / {stats['functions']} functions "
    f"in {time.time() - t0:.0f}s as {NAME}"
)
for k, v in stats.most_common():
    if k not in ("binaries", "functions"):
        print(f"  {k}: {v}")
