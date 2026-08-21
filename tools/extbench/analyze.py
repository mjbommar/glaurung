#!/usr/bin/env python3
"""Score the collected decompiler output.

    analyze.py <outdir> [--json report.json]

There is no source for these samples, so nothing here claims to measure
"correctness". What it measures, and what each measure is worth:

* **success rate** — did the tool return C for a function the binary's own
  DWARF/eh_frame says exists. Hard, objective, and the one that matters first.
* **discovery recall** — of the ground-truth entry VAs, how many did the tool
  find on its own. Sound direction only: the reference is incomplete, so a
  function found by a tool and absent from the reference is NOT a false
  positive and is never counted as one.
* **prototype recovery** — emitted parameter count vs DWARF parameter count.
  Only meaningful on the stripped twins; on the unstripped ones it mostly
  measures whether the tool reads DWARF, which is reported separately.
* **machine leakage** — raw registers, condition flags, and unrecovered-control
  markers surviving into the C. A decompiler's whole job is to remove these, so
  their density is a direct readout of how far the output is from source.
* **structuring** — goto density. Structured control flow is the other half of
  that job; `goto` is what a decompiler emits when it gives up on a loop.
* **analyst signal** — resolved callee names and string literals per function,
  the two things a reverse engineer actually reads first.

None of these can be gamed into meaning "this decompiler is correct". They are
a description of the artifact, and they are reported next to the raw C.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

TOOLS = ("glaurung", "ghidra", "angr", "retdec")

# --- machine leakage: things that should not survive into decompiled C -------
#
# Two defects lived here and both under-reported leakage for every tool:
#
#   * `ARM_REGS` was defined and then never referenced — `register` matched the
#     x86 list only, so `fp`, `lr`, `sp` and `x0`..`x30` in AArch64 output were
#     invisible. Glaurung's ARM leakage read as roughly zero for that reason
#     alone.
#   * `\b[zcosap]f\b` cannot match `zf_3`: `_` is a word character, so there is
#     no boundary after `f`. Decompilers number their flag temporaries, so the
#     `flag` row read 0.00 across the board while the output plainly contained
#     `zf_1`…`zf_6`.
#
# Fixing both raises the reported leakage of every tool, not just Glaurung's.
X86_REGS = r"r[abcd]x|r[sd]i|r[sb]p|rip|r8|r9|r1[0-5]|e[abcd]x|e[sd]i|e[sb]p|[abcd][lh]"
# `x29`/`x30` are fp/lr by another name; `w\d+` is the 32-bit view of `x\d+`.
ARM_REGS = r"x\d{1,2}|w\d{1,2}|r\d{1,2}|sp|lr|fp|pc"
# A decompiler names a flag temporary `zf`, `%zf` or `zf_3`. `af` is the x86
# adjust flag; `nzcv` and `cpsr` are the AArch64/ARM condition registers.
FLAGS = r"%?\b(?:[zcosap]f|nzcv|cpsr|eflags)(?:_\d+)?\b"
LEAK_PATTERNS = {
    "register": re.compile(rf"%?\b(?:{X86_REGS}|{ARM_REGS})\b"),
    "flag": re.compile(FLAGS, re.IGNORECASE),
    "unrecovered": re.compile(
        r"unrecovered|unknown\(|__unknown|halt_baddata|UNRECOVERED|"
        r"<UNDEFINED>|/\* WARNING|switchD|joined_r0x|__asm|LOWORD|HIWORD",
    ),
    "undefined_type": re.compile(r"\bundefined[0-9]*\b|\bcode\b\s*\*|\bunkbyte"),
}
GOTO_RE = re.compile(r"\bgoto\b")
LABEL_RE = re.compile(r"^\s*[A-Za-z_]\w*:\s*;?\s*$", re.MULTILINE)
STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
# `<type> <name>;` on its own line. The leading alternation is the *type*
# position, and C keywords are excluded from it explicitly: without that,
# `goto L_36afd;` and `return ret;` both match, because each is two identifiers
# and a semicolon.
#
# That was not a small over-count. On the extbench Tier B corpus the reported
# 46.34 declarations per function is 14.73 gotos and 0.72 returns on top of
# 31.11 real declarations — **32% of the figure was this pattern's own blind
# spot**, and it scales with goto density, so it inflated the tool with the most
# gotos hardest. Every published declaration number before 2026-08-21 carries it.
_NOT_A_TYPE = r"(?!goto\b|return\b|break\b|continue\b|case\b|default\b|else\b|do\b)"
DECL_RE = re.compile(
    r"^\s{1,8}" + _NOT_A_TYPE + r"(?:const\s+|unsigned\s+|signed\s+|struct\s+|static\s+)*"
    r"[A-Za-z_]\w*(?:\s*\*)*\s+\**[A-Za-z_]\w*(?:\s*\[[^\]]*\])?\s*;\s*$",
    re.MULTILINE,
)
# Names a decompiler invents when it has nothing: sub_/FUN_/function_ + hex.
PLACEHOLDER_RE = re.compile(
    r"^(sub_|FUN_|function_|fcn\.|loc_|unknown_)", re.IGNORECASE
)

C_KEYWORDS = {
    "if",
    "while",
    "for",
    "switch",
    "return",
    "sizeof",
    "do",
    "else",
    "case",
    "default",
    "break",
    "continue",
    "goto",
    "typedef",
}


def find_prototype(code: str, name: str | None) -> str | None:
    """Return the parameter list of the definition of `name` (or the last
    definition in the blob, which is how every tool here lays it out)."""
    if not code:
        return None
    cands = []
    for m in re.finditer(
        r"^([A-Za-z_][\w\s\*\(\)]*?)\(([^;{]*)\)\s*\{", code, re.MULTILINE
    ):
        head, params = m.group(1), m.group(2)
        if any(k in head.split() for k in C_KEYWORDS):
            continue
        cands.append((head.strip(), params.strip()))
    if not cands:
        return None
    if name:
        for head, params in cands:
            if re.search(rf"\b{re.escape(name)}\s*$", head):
                return params
    return cands[-1][1]


def param_count(params: str | None) -> int | None:
    if params is None:
        return None
    p = params.strip()
    if p in ("", "void"):
        return 0
    depth = 0
    n = 1
    for ch in p:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            n += 1
    if p.endswith("..."):
        n -= 1  # varargs marker is not a parameter
    return n


EXTERN_RE = re.compile(r"^\s*(extern\b|typedef\b)")
COMMENT_RE = re.compile(r"^\s*(//|/\*|\*/|\*\s)")
LINE_COMMENT_RE = re.compile(r"//.*$", re.MULTILINE)
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def strip_comments(text: str) -> str:
    return LINE_COMMENT_RE.sub("", BLOCK_COMMENT_RE.sub("", text))


def body_of(code: str) -> tuple[str, str]:
    """Return (body_for_loc, body_for_leaks) with per-tool boilerplate removed.

    Glaurung's decbench style declares every callee with an `extern` prototype
    *inside* the body so the artifact is self-contained enough to recompile.
    That is a real, deliberate property of its output, but it is not code an
    analyst reads: counting it would report Glaurung as twice as verbose as
    Ghidra for a reason that has nothing to do with decompilation quality. So
    `extern` lines are dropped from both.

    Comments are dropped from the LOC body only. They must stay in the leak
    body because Ghidra's `/* WARNING: ... */` banners are exactly the
    "I could not recover this" signal being measured, and deleting them would
    hand Ghidra a free zero on the one metric it is honest about.
    """
    i = code.find("{")
    body = code[i:] if i >= 0 else code
    kept = [ln for ln in body.splitlines() if not EXTERN_RE.match(ln)]
    loc_body = "\n".join(ln for ln in kept if not COMMENT_RE.match(ln))
    return loc_body, "\n".join(kept)


def score_function(code: str | None, gt: dict | None) -> dict:
    if not code:
        return {"produced": 0}
    loc_body, leak_body = body_of(code)
    lines = [ln for ln in loc_body.splitlines() if ln.strip()]
    nloc = max(1, len(lines))
    # Trailing comments must go before counting registers. angr annotates every
    # local with the register it came from (`unsigned int *err;  // rbx`), which
    # is provenance an analyst wants, not a register surviving into the code —
    # counting it scored angr's most useful feature as a defect.
    code_only = STRING_RE.sub('""', strip_comments(loc_body))
    leak_src = STRING_RE.sub('""', leak_body)

    leaks = {
        k: len(p.findall(leak_src if k == "unrecovered" else code_only))
        for k, p in LEAK_PATTERNS.items()
    }
    calls = [
        c
        for c in CALL_RE.findall(code_only)
        if c not in C_KEYWORDS and not PLACEHOLDER_RE.match(c)
    ]
    placeholder_calls = [
        c for c in CALL_RE.findall(code_only) if PLACEHOLDER_RE.match(c)
    ]
    row = {
        "produced": 1,
        "loc": len(lines),
        "gotos": len(GOTO_RE.findall(code_only)),
        "labels": len(LABEL_RE.findall(loc_body)),
        "goto_per_100loc": 100.0 * len(GOTO_RE.findall(code_only)) / nloc,
        "decls": len(DECL_RE.findall(loc_body)),
        "strings": len(STRING_RE.findall(loc_body)),
        "named_calls": len(set(calls)),
        "placeholder_calls": len(set(placeholder_calls)),
        "leak_total": sum(leaks.values()),
        "leak_per_100loc": 100.0 * sum(leaks.values()) / nloc,
        **{f"leak_{k}": v for k, v in leaks.items()},
    }
    if gt:
        params = find_prototype(code, None)
        n = param_count(params)
        row["proto_parsed"] = int(n is not None)
        if n is not None:
            row["proto_argc"] = n
            row["gt_argc"] = len(gt["params"])
            row["argc_exact"] = int(n == len(gt["params"]))
        row["name_exact"] = None
    return row


def sample(pool: list[int], limit: int) -> list[int]:
    """Even stride over the ground-truth set — must match drive.py exactly.

    Kept identical to the selection the tools were actually given; if the two
    drifted, every tool would be scored against functions nobody asked it for.
    """
    if len(pool) <= limit:
        return list(pool)
    step = len(pool) / limit
    return [pool[int(i * step)] for i in range(limit)]


def load(outdir: Path, tool: str, tag: str) -> dict | None:
    p = outdir / f"{tool}_{tag}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def analyze(outdir: Path) -> dict:
    tags = sorted(p.name[3:-5] for p in outdir.glob("gt_*.json"))
    per_tag: dict[str, dict] = {}
    for tag in tags:
        gt = json.loads((outdir / f"gt_{tag}.json").read_text())
        gt_by_va = {f["va"]: f for f in gt["dwarf"]}
        fde_vas = {f["va"] for f in gt["fde"]}

        # The set every tool was actually asked for. Reconstructed the same way
        # drive.py built it, because RetDec cannot be asked for specific
        # functions and returns the whole image: scoring it on its own output
        # would let it pick its own denominator, and 99 tiny PLT stubs would
        # score a perfect success rate and a flattering mean line count.
        summary_path = outdir / f"summary_{tag}.json"
        gtsource = "dwarf"
        if summary_path.exists():
            gtsource = json.loads(summary_path.read_text()).get("gt", "dwarf")
        pool = sorted(gt_by_va) if gtsource == "dwarf" else sorted(fde_vas)
        target_vas = set(sample(pool, 40))
        entry = {
            "gt": {
                "dwarf": len(gt["dwarf"]),
                "fde": len(gt["fde"]),
                "arch": gt["arch"],
                "size": gt["size"],
                "pie": gt["pie"],
            },
            "tools": {},
        }
        for tool in TOOLS:
            data = load(outdir, tool, tag)
            if data is None:
                entry["tools"][tool] = {"missing": True}
                continue
            rows = []
            statuses = defaultdict(int)
            by_va = {f["va"]: f for f in data.get("functions", [])}
            # One denominator for everyone: the ground-truth target set.
            targets = sorted(target_vas)
            for va in targets:
                f = by_va.get(va)
                if f is None:
                    statuses["not_returned"] += 1
                    rows.append(score_function(None, gt_by_va.get(va)))
                    continue
                statuses[f.get("status", "?")] += 1
                rows.append(score_function(f.get("code"), gt_by_va.get(va)))

            disc = {d["va"] for d in data.get("discovered", [])}
            ref_dwarf = set(gt_by_va)
            ref_fde = fde_vas
            t = {
                "n_targets": len(targets),
                "produced": sum(r["produced"] for r in rows),
                "statuses": dict(statuses),
                "analyze_s": data.get("analyze_s"),
                "decompile_s": data.get("decompile_s"),
                "total_s": data.get("total_s"),
                "error": data.get("error"),
                "n_discovered": len(disc),
                "n_dwarf": len(ref_dwarf),
                "n_dwarf_found": len(disc & ref_dwarf),
                "n_fde": len(ref_fde),
                "n_fde_found": len(disc & ref_fde),
                "recall_dwarf": (len(disc & ref_dwarf) / len(ref_dwarf))
                if ref_dwarf
                else None,
                "recall_fde": (len(disc & ref_fde) / len(ref_fde)) if ref_fde else None,
            }
            ok = [r for r in rows if r["produced"]]
            t["n_produced_metrics"] = len(ok)
            if ok:
                for key in (
                    "loc",
                    "gotos",
                    "goto_per_100loc",
                    "decls",
                    "strings",
                    "named_calls",
                    "placeholder_calls",
                    "leak_total",
                    "leak_per_100loc",
                    "leak_register",
                    "leak_flag",
                    "leak_unrecovered",
                    "leak_undefined_type",
                ):
                    t[f"mean_{key}"] = statistics.mean(r.get(key, 0) for r in ok)
                # Prototype scoring needs DWARF parameter lists. On the Tier B
                # binaries there are none, and reporting 0.000 there would read
                # as "every tool failed" rather than "the question was not
                # asked", so the row is omitted instead.
                scored = [r for r in ok if "proto_parsed" in r]
                t["n_proto_scored"] = len(scored)
                if scored:
                    t["n_proto_parsed"] = sum(r["proto_parsed"] for r in scored)
                    t["proto_parse_rate"] = sum(
                        r["proto_parsed"] for r in scored
                    ) / len(scored)
                    exact = [r for r in scored if "argc_exact" in r]
                    t["n_argc_scored"] = len(exact)
                    if exact:
                        t["n_argc_exact"] = sum(r["argc_exact"] for r in exact)
                        t["argc_exact_rate"] = sum(
                            r["argc_exact"] for r in exact
                        ) / len(exact)
            entry["tools"][tool] = t
        per_tag[tag] = entry
    return per_tag


def agg(per_tag: dict, tags: list[str]) -> dict:
    out: dict[str, dict] = {}
    for tool in TOOLS:
        binary_vals: dict[str, list] = defaultdict(list)
        function_sums: dict[str, float] = defaultdict(float)
        function_counts: dict[str, int] = defaultdict(int)
        count_sums: dict[str, int] = defaultdict(int)
        tgt = prod = 0
        for tag in tags:
            t = per_tag[tag]["tools"].get(tool, {})
            if t.get("missing"):
                continue
            tgt += t.get("n_targets", 0)
            prod += t.get("produced", 0)
            n_produced = t.get("n_produced_metrics", t.get("produced", 0))
            for k, v in t.items():
                if not isinstance(v, (int, float)):
                    continue
                if k.startswith("mean_") and n_produced:
                    function_sums[k] += v * n_produced
                    function_counts[k] += n_produced
                elif k in ("total_s", "analyze_s", "decompile_s"):
                    binary_vals[k].append(v)
            for key in (
                "n_dwarf",
                "n_dwarf_found",
                "n_fde",
                "n_fde_found",
                "n_proto_scored",
                "n_proto_parsed",
                "n_argc_scored",
                "n_argc_exact",
            ):
                count_sums[key] += t.get(key, 0)
        row = {
            "n_targets": tgt,
            "produced": prod,
            "success_rate": (prod / tgt) if tgt else None,
        }
        for key, values in binary_vals.items():
            row[key] = statistics.mean(values) if values else None
        for key, total in function_sums.items():
            row[key] = total / function_counts[key]
        row.update(count_sums)
        row["recall_dwarf"] = (
            count_sums["n_dwarf_found"] / count_sums["n_dwarf"]
            if count_sums["n_dwarf"]
            else None
        )
        row["recall_fde"] = (
            count_sums["n_fde_found"] / count_sums["n_fde"]
            if count_sums["n_fde"]
            else None
        )
        row["proto_parse_rate"] = (
            count_sums["n_proto_parsed"] / count_sums["n_proto_scored"]
            if count_sums["n_proto_scored"]
            else None
        )
        row["argc_exact_rate"] = (
            count_sums["n_argc_exact"] / count_sums["n_argc_scored"]
            if count_sums["n_argc_scored"]
            else None
        )
        out[tool] = row
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--json", default=None)
    ap.add_argument("--filter", default="")
    args = ap.parse_args()
    outdir = Path(args.outdir)
    per_tag = analyze(outdir)
    tags = [t for t in sorted(per_tag) if args.filter in t]
    report = {"per_tag": per_tag, "overall": agg(per_tag, tags), "tags": tags}
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
    print(json.dumps(report["overall"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
