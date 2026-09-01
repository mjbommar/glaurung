#!/usr/bin/env python3
"""Measure every decompiler failure the fixture corpus can demonstrate.

Writes `tests/open_defects/known_failures.json`, which
`python/tests/test_known_decompiler_failures.py` turns into one strict xfail
per failure. Regenerate deliberately -- the file is evidence, and the tests
that read it go red when a failure is FIXED, which is the point.

Two axes, both against ground truth rather than against a previous run:

* **types** -- the recovered prototype versus the DWARF the compiler emitted.
  DWARF states the source signature exactly, so any disagreement is a real
  recovery gap rather than a stylistic one.
Each row records the function's VA as well as its name: Rust emits many
functions called `{closure#0}`, so a name alone is not a unique key and a
name-keyed lookup silently resolves to the wrong closure.

* **structure** -- a `goto` in the recovered C for a function whose SOURCE
  contains no `goto` anywhere. The execution differential cannot see this: the
  code behaves identically, it simply is not the control flow the programmer
  wrote.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D

BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
OUT = ROOT / "tests" / "open_defects" / "known_failures.json"

#: C type text -> width in bytes. `long` is 8 on every target this corpus
#: builds for; the i386 lane is covered by `arch_baseline.json`, not here.
WIDTHS = {
    "char": 1,
    "short": 2,
    "int": 4,
    "long": 8,
    "long long": 8,
    "float": 4,
    "double": 8,
    "long double": 16,
    "void": 0,
    "_Bool": 1,
    "bool": 1,
}


def classify(text: str) -> dict:
    t = " ".join(text.replace("*", " * ").split())
    is_ptr = "*" in t
    base = t.replace("*", "").replace("const", "").strip()
    signed = not base.startswith("unsigned")
    b = base.replace("unsigned ", "").replace("signed ", "").strip()
    return {
        "w": 8 if is_ptr else WIDTHS.get(b),
        "s": signed,
        "ptr": is_ptr,
        "f": base in ("float", "double", "long double"),
        "raw": base,
    }


def dwarf_classify(p: dict) -> dict:
    if p.get("k") == "ptr":
        return {"w": 8, "s": True, "ptr": True, "f": False, "raw": "ptr"}
    return {
        "w": p.get("w"),
        "s": p.get("s", True),
        "ptr": False,
        "f": p.get("k") == "float",
        "raw": p.get("k", ""),
    }


def recovered_signature(binary: str, va: int) -> str | None:
    c = D.decompiled_c(binary, va)
    if not c:
        return None
    for line in c.splitlines():
        if line.startswith("//") or not line.strip():
            continue
        if "(" in line:
            return line.split("{")[0].strip()
    return None


def split_params(sig: str) -> list[str] | None:
    m = re.search(r"\((.*)\)\s*$", sig)
    if not m:
        return None
    inner = m.group(1).strip()
    if inner in ("", "void"):
        return []
    out, depth, cur = [], 0, ""
    for ch in inner:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [x.strip() for x in out]


def strip_name(decl: str) -> str:
    parts = decl.split()
    return " ".join(parts[:-1]) if len(parts) > 1 else decl


def sources_without_goto() -> set[str]:
    out = set()
    for f in SRC.iterdir():
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        if not re.search(r"\bgoto\b", text):
            out.add(f.name.rsplit(".", 1)[0])
    return out


def main() -> int:
    if not BUILD.is_dir():
        print(f"{BUILD} absent; build the fixture matrix first", file=sys.stderr)
        return 2
    goto_free = sources_without_goto()
    objects = sorted(p.name for p in BUILD.glob("*.so"))
    types, structure = [], []
    returns, pointers, markers, nobody = [], [], [], []
    t0 = time.time()

    for name in objects:
        path = str(BUILD / name)
        try:
            sigs = D.signatures(path)
        except Exception:
            continue
        stem = name.split("-")[0]
        for s in sigs:
            try:
                rendered = D.decompiled_c(path, s["va"])
            except Exception:
                continue
            if not rendered:
                nobody.append({"obj": name, "fn": s["name"], "va": s["va"]})
                continue

            if stem in goto_free:
                n = len(re.findall(r"\bgoto\s+\w+\s*;", rendered))
                if n:
                    structure.append(
                        {"obj": name, "fn": s["name"], "va": s["va"], "gotos": n}
                    )

            if "unrecovered" in rendered:
                markers.append({"obj": name, "fn": s["name"], "va": s["va"],
                                "n": rendered.count("unrecovered")})

            got = recovered_signature(path, s["va"])
            params = split_params(got) if got else None

            # Return type. Checked separately from parameters because a wrong
            # return type is the failure that makes a function look `void` --
            # the shape `-flto` and the AArch64 FMA gap both produce.
            if got:
                rw = dwarf_classify(s.get("ret") or {})
                rg = classify(got.split("(")[0].rsplit(" ", 1)[0]) if " " in got.split("(")[0] else None
                if rg and rw["w"] is not None and rg["w"] is not None:
                    if rw["ptr"] and not rg["ptr"]:
                        returns.append({"obj": name, "fn": s["name"], "va": s["va"],
                                        "kind": "ptr_lost", "want": "pointer",
                                        "got": rg["raw"]})
                    elif not rw["ptr"] and rw["w"] != rg["w"]:
                        returns.append({"obj": name, "fn": s["name"], "va": s["va"],
                                        "kind": "width", "want": rw["w"],
                                        "got": rg["raw"]})

            if params is None or len(params) != len(s["params"]):
                continue
            for i, (want, decl) in enumerate(zip(s["params"], params)):
                w, g = dwarf_classify(want), classify(strip_name(decl))
                if g["w"] is None:
                    continue
                # A DWARF pointer recovered as a scalar loses the fact that the
                # value is an address, which is what makes recovered C
                # dereference an integer.
                if w["ptr"] and not g["ptr"]:
                    pointers.append({"obj": name, "fn": s["name"], "va": s["va"],
                                     "arg": i, "got": g["raw"]})
                    continue
                if w["ptr"] or not w["w"] or not g["w"]:
                    continue
                if w["w"] != g["w"]:
                    types.append(
                        {
                            "obj": name,
                            "fn": s["name"],
                            "va": s["va"],
                            "arg": i,
                            "kind": "width",
                            "want": w["w"],
                            "got": g["raw"],
                        }
                    )
                elif w["s"] != g["s"]:
                    types.append(
                        {
                            "obj": name,
                            "fn": s["name"],
                            "va": s["va"],
                            "arg": i,
                            "kind": "signedness",
                            "want": "signed" if w["s"] else "unsigned",
                            "got": g["raw"],
                        }
                    )

    payload = {
        "note": "Measured decompiler failures. Regenerate with tools/gen_known_failures.py.",
        "elapsed_seconds": round(time.time() - t0, 1),
        "objects_scanned": len(objects),
        "counts": {
            "types": len(types),
            "structure": len(structure),
            "returns": len(returns),
            "pointers": len(pointers),
            "unrecovered": len(markers),
            "no_body": len(nobody),
            "goto_statements": sum(r["gotos"] for r in structure),
        },
        "types": sorted(types, key=lambda r: (r["obj"], r["va"], r["arg"])),
        "structure": sorted(structure, key=lambda r: (r["obj"], r["va"])),
        "returns": sorted(returns, key=lambda r: (r["obj"], r["va"])),
        "pointers": sorted(pointers, key=lambda r: (r["obj"], r["va"], r["arg"])),
        "unrecovered": sorted(markers, key=lambda r: (r["obj"], r["va"])),
        "no_body": sorted(nobody, key=lambda r: (r["obj"], r["va"])),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=1) + "\n")
    print(
        f"{OUT.relative_to(ROOT)}: "
        + ", ".join(f"{v} {k}" for k, v in payload["counts"].items())
        + f" in {payload['elapsed_seconds']}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
