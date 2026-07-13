#!/usr/bin/env python3
"""Measure glaurung's IOCTL analysis parity against the reference ioctlance fork.

Runs both tools on the same driver and diffs:
  - IOCTL codes discovered (ioctlance uses symbolic discovery; glaurung static)
  - vulnerability findings (kinds / handler functions)

Ground truth = the ioctlance fork (angr). This makes "progress toward parity"
a number we can track as the glaurung engine gains interprocedural execution,
broader API modeling, and symbolic code discovery.

Usage:
  ioctlance_parity.py <driver.sys> [--ioctlance-root DIR] [--glaurung-root DIR] [--timeout S]
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def run_ioctlance(root: Path, drv: Path, timeout: int) -> dict:
    """Run the fork; return {codes:set, vulns:[titles]}. Prefers a sidecar .json."""
    sidecar = drv.with_suffix(drv.suffix + ".json")
    out = {"codes": set(), "vulns": [], "raw": None}
    try:
        proc = subprocess.run(
            [str(root / ".venv/bin/python"), "-m", "ioctlance.cli",
             "--timeout", str(timeout), str(drv)],
            cwd=root, capture_output=True, text=True, timeout=timeout + 120)
        out["raw"] = proc.stdout + proc.stderr
        for m in re.finditer(r"Discovered \d+ IOCTL codes?: \[([^\]]*)\]", out["raw"]):
            out["codes"] |= {c.strip().strip("'\"") for c in m.group(1).split(",") if c.strip()}
        for m in re.finditer(r"^\s*-\s*(.+)$", out["raw"], re.M):
            t = m.group(1).strip()
            if t and "vulnerab" not in t.lower():
                out["vulns"].append(t)
    except subprocess.TimeoutExpired:
        out["raw"] = "<timeout>"
    if sidecar.exists():
        try:
            d = json.load(open(sidecar))
            v = d.get("vuln")
            if isinstance(v, list):
                for f in v:
                    if isinstance(f, dict) and f.get("title"):
                        out["vulns"].append(f["title"])
        except Exception:
            pass
    return out


def run_glaurung(root: Path, drv: Path, timeout: int) -> dict:
    """Run glaurung ioctlance example; return {codes:set, by_kind:dict, hi:int}."""
    out = {"codes": set(), "by_kind": {}, "hi": 0, "raw": None}
    exe = root / "target/release/examples/ioctlance"
    surf = root / "target/release/examples/ioctl_surface_scan"
    try:
        if surf.exists():
            s = subprocess.run([str(surf), str(drv)], capture_output=True, text=True, timeout=120)
            for line in s.stdout.splitlines():
                if line.startswith("CODES "):
                    out["codes"] |= {c for c in line[6:].split()}
        p = subprocess.run([str(exe), str(drv)], capture_output=True, text=True, timeout=timeout + 60)
        out["raw"] = p.stderr
        m = re.search(r"high-confidence=(\d+)", p.stderr)
        if m:
            out["hi"] = int(m.group(1))
        m = re.search(r"\[by-kind\] (\{.*\})", p.stderr)
        if m:
            out["by_kind"] = eval(m.group(1))  # trusted local output
    except subprocess.TimeoutExpired:
        out["raw"] = "<timeout>"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("driver")
    ap.add_argument("--ioctlance-root", default="/nas4/data/workspace-infosec/ioctlance")
    ap.add_argument("--glaurung-root", default="/nas4/data/workspace-infosec/glaurung")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()
    drv = Path(args.driver)

    ifork = run_ioctlance(Path(args.ioctlance_root), drv, args.timeout)
    glau = run_glaurung(Path(args.glaurung_root), drv, args.timeout)

    fcodes, gcodes = ifork["codes"], glau["codes"]
    code_recall = len(fcodes & gcodes) / len(fcodes) if fcodes else float("nan")
    print(f"== ioctlance-parity: {drv.name} ==")
    print(f"  IOCTL codes   fork={len(fcodes)} glaurung={len(gcodes)} "
          f"shared={len(fcodes & gcodes)} code-recall={code_recall:.0%}")
    print(f"    fork-only:     {sorted(fcodes - gcodes)}")
    print(f"    glaurung-only: {sorted(gcodes - fcodes)}")
    print(f"  fork vulns ({len(ifork['vulns'])}): {ifork['vulns']}")
    print(f"  glaurung high-confidence sinks: {glau['hi']}  by-kind={glau['by_kind']}")
    # crude vuln-class parity: does glaurung surface a matching kind for each fork vuln?
    KMAP = {"stack": "stack-overflow", "write": "arbitrary-write", "read": "arbitrary-read",
            "null": "null-deref", "double free": "double-free", "use after": "use-after-free",
            "overflow": "integer-overflow", "physical": "physical-memory"}
    gkinds = set(glau["by_kind"])
    matched = 0
    for v in ifork["vulns"]:
        want = next((gk for key, gk in KMAP.items() if key in v.lower()), None)
        hit = want in gkinds if want else False
        matched += hit
        print(f"    fork vuln '{v[:50]}' -> glaurung {'HAS' if hit else 'MISSING'} {want}")
    if ifork["vulns"]:
        print(f"  VULN-CLASS RECALL: {matched}/{len(ifork['vulns'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
