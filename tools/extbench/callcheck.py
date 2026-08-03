#!/usr/bin/env python3
"""Check each tool's emitted call set against the calls that are actually there.

    callcheck.py <outdir> <corpusdir> [--filter substr]

Every other metric in this harness describes the artifact. This one is a
correctness probe, and it works without source: objdump the exact byte range
DWARF gives for a function, collect the call/bl targets that resolve to a named
import, and compare that set with the library functions each decompiler's C
claims to call.

* **recall** — real imported callees that appear in the C. Missing one means the
  decompiler dropped a call the CPU makes.
* **spurious** — named library calls in the C that are NOT called anywhere in
  the function's bytes. This is the one that matters: it is a decompiler
  inventing behaviour, and it is invisible to every structural metric, which is
  how `parsenum` on AArch64 came out calling `ether_hostton()`.

Only imports (PLT-resolved names) are scored, because internal calls have no
agreed name across tools on a stripped binary. That makes both numbers
conservative rather than generous.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from bisect import bisect_left
from collections import defaultdict
from pathlib import Path

TOOLS = ("glaurung", "ghidra", "angr", "retdec")
# `call 2340 <strtoul@plt>` / `bl 1234 <__errno_location@plt>` / `jmp 2120 <x@plt>`
#
# Branch mnemonics are included alongside call ones because a tail call to an
# import is still a call: musl's `_start_c` reaches __libc_start_main by `jmp`,
# and counting only `call` marked all four decompilers as having invented it.
# Local branches are harmless here — a target only counts if it resolves to a
# name in the import table.
#
# The symbol must close immediately after the optional `@plt`. objdump labels
# unnamed code in a stripped binary as `<nearest_symbol+0x1b9>`, and accepting
# those would credit a call to whichever import happened to sort before it.
CALL_RE = re.compile(
    r"\b(?:call|callq|bl|blx|jmp|jmpq|b|bx|br)\b[^<\n]*<([A-Za-z_][\w.]*)(?:@plt)?>"
)
IDENT_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
# Two patterns, not one alternation: with re.S the `//.*$` branch consumes the
# entire remaining file rather than one line, which silently emptied the body of
# every tool whose output opens with a `//` banner.
LINE_COMMENT_RE = re.compile(r"//[^\n]*")
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


# Architectures where the reference disassembly can be trusted on a STRIPPED
# image. 32-bit ARM is excluded: stripping removes the $a/$t mapping symbols, so
# no disassembler here can tell Thumb from ARM, and llvm-objdump decodes musl's
# Thumb code as garbage. That is a limit of the reference, not a result about
# the decompilers, so those cells are dropped rather than scored.
SCORABLE_ARCH = {"x64", "AArch64"}


# `    1140: e8 eb ff ff ff   callq 0x1130 <strtoul@plt>` — leading hex address.
INSN_ADDR_RE = re.compile(r"^\s*([0-9a-f]+):", re.MULTILINE)
RELOCATION_RE = re.compile(
    r"^\s*([0-9a-f]+)\s+\S+\s+([A-Za-z_][\w.]*)(?:@\S+)?\s*$",
    re.MULTILINE,
)
INDIRECT_TARGET_RE = re.compile(r"\b(?:call|callq|jmp|jmpq)\b.*#\s*([0-9a-f]+)(?:\s|$)")

# One full disassembly per binary, keyed by path. `--start-address` does NOT
# make llvm-objdump cheap: it still decodes the whole image and only filters
# what it prints, so a per-function call is O(filesize). At 172 FDE extents per
# distro binary that made the Tier B probe take longer than its timeout and
# produce nothing at all.
_DISASM: dict[tuple[Path, str], list[tuple[int, str]]] = {}
_RELOCATIONS: dict[tuple[Path, str], dict[int, str]] = {}


def objdump_executable(arch: str) -> str:
    """Return the GNU cross-objdump matching a scorable architecture."""
    return {
        "x64": "objdump",
        "AArch64": "aarch64-linux-gnu-objdump",
    }.get(arch, "llvm-objdump")


def objdump_command(binary: Path, arch: str) -> list[str]:
    """Build a deterministic local-only disassembly command.

    GNU objdump preserves dynamic PLT names in stripped images; LLVM 21 renders
    those same targets as ``.plt.sec+offset``, which made every real import look
    absent. Use the matching GNU cross-objdump for each scorable architecture.
    """
    executable = objdump_executable(arch)
    command = [executable]
    if executable == "llvm-objdump":
        command.append("--no-debuginfod")
    return [*command, "-d", str(binary)]


def parse_dynamic_relocations(output: str) -> dict[int, str]:
    """Parse GOT/PLT relocation addresses into unversioned import names."""
    return {int(address, 16): name for address, name in RELOCATION_RE.findall(output)}


def indirect_import_target(text: str, relocations: dict[int, str]) -> str | None:
    """Resolve an x86 indirect call/jump through a named dynamic relocation."""
    match = INDIRECT_TARGET_RE.search(text)
    if match is None:
        return None
    return relocations.get(int(match.group(1), 16))


def _dynamic_relocations(binary: Path, arch: str) -> dict[int, str]:
    key = (binary, arch)
    if key in _RELOCATIONS:
        return _RELOCATIONS[key]
    executable = objdump_executable(arch)
    if executable == "llvm-objdump":
        command = [executable, "--no-debuginfod", "-R", str(binary)]
    else:
        command = [executable, "-R", str(binary)]
    env = os.environ.copy()
    env["DEBUGINFOD_URLS"] = ""
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        relocations = parse_dynamic_relocations(process.stdout)
    except subprocess.TimeoutExpired:
        relocations = {}
    _RELOCATIONS[key] = relocations
    return relocations


def _disasm(binary: Path, arch: str) -> list[tuple[int, str]]:
    """(address, text) for every instruction line, ascending."""
    key = (binary, arch)
    if key in _DISASM:
        return _DISASM[key]
    env = os.environ.copy()
    # Both GNU binutils and LLVM can inherit this ambient service. Disassembly
    # is a local measurement; an unreachable debug server previously wedged the
    # Tier B probe for 17 minutes on a 40 KiB stripped binary.
    env["DEBUGINFOD_URLS"] = ""
    try:
        p = subprocess.run(
            objdump_command(binary, arch),
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
        )
        out = p.stdout
    except subprocess.TimeoutExpired:
        out = ""
    lines: list[tuple[int, str]] = []
    for ln in out.splitlines():
        m = INSN_ADDR_RE.match(ln)
        if m:
            lines.append((int(m.group(1), 16), ln))
    lines.sort(key=lambda t: t[0])
    _DISASM[key] = lines
    return lines


def real_calls(
    binary: Path, va: int, size: int, imports: set[str], arch: str
) -> set[str]:
    lines = _disasm(binary, arch)
    relocations = _dynamic_relocations(binary, arch)
    lo = bisect_left(lines, (va, ""))
    found = set()
    for addr, text in lines[lo:]:
        if addr >= va + size:
            break
        m = CALL_RE.search(text)
        if m and m.group(1).strip() in imports:
            found.add(m.group(1).strip())
        indirect = indirect_import_target(text, relocations)
        if indirect in imports:
            found.add(indirect)
    return found


def claimed_calls(code: str, imports: set[str]) -> set[str]:
    body = LINE_COMMENT_RE.sub("", BLOCK_COMMENT_RE.sub("", code))
    # Drop `extern ...;` declaration lines: declaring a prototype is not the
    # same as calling it, and Glaurung declares a block of them up front.
    body = "\n".join(
        ln for ln in body.splitlines() if not ln.strip().startswith("extern")
    )
    return {n for n in IDENT_RE.findall(body) if n in imports}


def index_function_code(functions: list[dict]) -> dict[int, str]:
    """Return at most one non-empty emitted body per function address."""
    indexed: dict[int, str] = {}
    for function in functions:
        code = function.get("code")
        if code:
            indexed.setdefault(function["va"], code)
    return indexed


def sample_entries(entries: list[dict], limit: int) -> list[dict]:
    """Apply the exact address-deduped even stride used by ``drive.py``."""
    by_va: dict[int, dict] = {}
    for entry in entries:
        by_va.setdefault(entry["va"], entry)
    pool = [by_va[va] for va in sorted(by_va)]
    if len(pool) <= limit:
        return pool
    step = len(pool) / limit
    return [pool[int(i * step)] for i in range(limit)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("corpusdir")
    ap.add_argument("--filter", default="")
    args = ap.parse_args()
    outdir, corpus = Path(args.outdir), Path(args.corpusdir)
    needles = [s for s in args.filter.split(",") if s]

    stats = {t: defaultdict(int) for t in TOOLS}
    examples = {t: [] for t in TOOLS}
    skipped: set[str] = set()

    for gtp in sorted(outdir.glob("gt_*.json")):
        tag = gtp.name[3:-5]
        if not all(n in tag for n in needles):
            continue
        gt = json.loads(gtp.read_text())
        if gt.get("arch") not in SCORABLE_ARCH:
            skipped.add(f"{tag} ({gt.get('arch')})")
            continue
        binary = corpus / tag
        if not binary.exists():
            binary = Path(gt["binary"])
        if not binary.exists():
            continue
        imports = set(gt["imports"])
        arch = gt["arch"]
        truth = {}
        # Use the same source and even-stride sample that drive.py handed to the
        # decompilers. RetDec returns a whole image; scoring all of its rows once
        # inflated its denominator to 5,351 against 263 shared targets.
        summary_path = outdir / f"summary_{tag}.json"
        summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}
        source = summary.get("gt", "dwarf" if gt["dwarf"] else "fde")
        entries = gt.get(source, [])
        if source == "fde":
            entries = [{**f, "name": f"sub_{f['va']:x}"} for f in entries]
        entries = sample_entries(entries, summary.get("n_targets", len(entries)))
        for f in entries:
            if not f.get("size"):
                continue
            truth[f["va"]] = (
                f["name"],
                real_calls(binary, f["va"], f["size"], imports, arch),
            )

        for tool in TOOLS:
            p = outdir / f"{tool}_{tag}.json"
            if not p.exists():
                continue
            data = json.loads(p.read_text())
            emitted = index_function_code(data.get("functions", []))
            for va, code in emitted.items():
                if va not in truth:
                    continue
                name, real = truth[va]
                claimed = claimed_calls(code, imports)
                stats[tool]["functions"] += 1
                stats[tool]["real"] += len(real)
                stats[tool]["hit"] += len(real & claimed)
                spurious = claimed - real
                stats[tool]["spurious"] += len(spurious)
                if spurious:
                    stats[tool]["fn_with_spurious"] += 1
                    if len(examples[tool]) < 4:
                        examples[tool].append(
                            f"{tag}:{name} invents {sorted(spurious)[:3]}"
                        )

    print(
        "| tool | imported-callee recall | functions with an invented call | "
        "invented calls per function |"
    )
    print("|---|---|---|---|")
    for tool in TOOLS:
        s = stats[tool]
        n = s["functions"] or 1
        rec = f"{100 * s['hit'] / s['real']:.0f}%" if s["real"] else "—"
        print(
            f"| {tool} | {rec} | {100 * s['fn_with_spurious'] / n:.0f}% "
            f"({s['fn_with_spurious']}/{s['functions']}) | {s['spurious'] / n:.2f} |"
        )
    # A table of dashes and 0.00 reads exactly like a clean result. Say when
    # nothing was actually scored, so an empty probe cannot be mistaken for a
    # passing one.
    if not any(stats[t]["functions"] for t in TOOLS):
        print(
            "\n**NOTHING WAS SCORED** — no decompiled function matched a ground-truth "
            "extent. This is a harness failure, not a clean result."
        )
    if skipped:
        print(
            f"\n*Not scorable ({len(skipped)} binaries), reference disassembly unreliable: "
            f"{', '.join(sorted(skipped))}*"
        )
    print()
    for tool in TOOLS:
        for e in examples[tool]:
            print(f"* {tool}: {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
