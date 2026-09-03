#!/usr/bin/env python3
"""Measure naming recall of the Cortex-M FLIRT libraries on real firmware.

Two validation corpora, both on the NAS (read-only, never copied):

* ``rt-libopencm3`` -- 20 STM32F4 (Cortex-M4, v7E-M+FP hard) firmwares built
  with this exact toolchain (``arm-none-eabi-gcc 13.2.1 20231009``), with
  ``addr2name.json`` ground truth (decimal VA -> name, some VAs carrying the
  Thumb bit) and a matching stripped/unstripped pair per firmware.
* ``decbench-holdout`` -- ARM EABI5 static firmware projects. Ground truth is
  read straight off each ELF's own symbol table with the toolchain's own
  ``nm``, because (measured here, and recorded as a corpus defect below) the
  holdout rebuild's "stripped" output is byte-identical to "compiled" for
  every ARM project checked, so there is no separately-stripped file to
  derive truth from.

For each firmware this script:

1. Reads the firmware's real multilib off its own ``.ARM.attributes`` section
   (``Tag_CPU_arch``, ``Tag_FP_arch``, ``Tag_ABI_HardFP_use``) rather than
   guessing from a filename, and maps that to one of the six libraries built
   by ``tools/build_armtc_signatures.py``.
2. Merges that multilib's component libraries (newlib, libgcc, libstdc++,
   libsupc++, libnosys -- **not** the ``-nano`` variants, since these
   projects link the standard reentrant newlib) into one in-memory
   ``FlirtLibraryFile``-shaped JSON. Concatenating ``entries`` is sufficient:
   the Rust matcher already treats a masked-pattern collision across
   *any* two entries as ambiguous, in-file or not, so no separate
   cross-library ambiguity pass is needed. See
   ``docs/reference/function-signature-libraries.md`` for the matcher's
   escalation levels.
3. Calls ``glaurung.analysis.flirt_match_functions_with_evidence_path``,
   comparing entry VA (Thumb bit cleared on both sides) against the truth
   map, and reports the table the task lane asked for: functions in truth,
   named, correct, wrong, ambiguous.

Usage::

    uv run python tools/validate_cortex_m_signatures.py \\
        --sigs-dir ~/.cache/glaurung/system-libs/armtc-13.2.1/sigs \\
        --corpus rt-libopencm3 \\
        --corpus holdout
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import glaurung as g

RT_LIBOPENCM3_ROOT = Path("/nas4/data/binary-analysis/rt-libopencm3")
HOLDOUT_ROOT = Path(
    "/nas4/data/binary-analysis/decbench-holdout-source-rebuild-2026-08-06"
)
TOOLCHAIN_NM = Path(
    "/nas4/data/binary-analysis/armtc/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-eabi"
    "/bin/arm-none-eabi-nm"
)

#: Non-nano component libraries merged for validation matching. Nano variants
#: are built (see build_armtc_signatures.py) but excluded here because every
#: measured firmware links the standard reentrant newlib (DW_AT_producer has
#: no `--specs=nano.specs`, and the corpus prints doubles via `_dtoa_r`,
#: which newlib-nano does not build by default).
MERGE_COMPONENTS: tuple[str, ...] = (
    "newlib",
    "libgcc",
    "libstdc++",
    "libsupc++",
    "libnosys",
)


def _readelf_attrs(binary: Path) -> dict[str, str]:
    out = subprocess.run(
        ["readelf", "-A", str(binary)], capture_output=True, text=True, check=False
    ).stdout
    attrs: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if ":" not in line or not line.startswith("Tag_"):
            continue
        key, _, value = line.partition(":")
        attrs[key.strip()] = value.strip().strip('"')
    return attrs


def infer_multilib(binary: Path) -> str:
    """Map a firmware's own `.ARM.attributes` to one of the six built multilibs.

    Reading the build attributes off the binary itself is exact; guessing
    from a filename or board name is not (`docs/reference/...` items 3
    explicitly asks for build-flag-level inference).

    Raises:
        ValueError: the binary's arch/fp combination is not one of the six
            multilibs this lane built.
    """
    attrs = _readelf_attrs(binary)
    arch = attrs.get("Tag_CPU_arch", "")
    fp = attrs.get("Tag_FP_arch", "")
    hardfp = attrs.get("Tag_ABI_HardFP_use", "")

    if arch == "v6-M":
        return "thumb/v6-m/nofp"
    if arch == "v7E-M":
        if not fp:
            return "thumb/v7e-m/nofp"
        if hardfp:
            # VFPv4-D16 (single precision only) -> +fp; a double-precision
            # FPU variant would report "VFPv4" (no -D16 SP restriction) or a
            # DP-capable arch tag -- none of the measured firmware does.
            if "D16" in fp and "sp" not in fp.lower():
                return "thumb/v7e-m+fp/hard"
            return "thumb/v7e-m+dp/hard"
        raise ValueError(
            f"{binary}: v7E-M with FP_arch={fp!r} but no HardFP_use (softfp not built)"
        )
    if arch == "v7":
        # "7-M" without the E (no DSP/MAC extensions) is the plain v7-M profile.
        if attrs.get("Tag_CPU_name", "") in ("7-M", "Cortex-M3"):
            return "thumb/v7-m/nofp"
    if (
        arch.startswith("v8-M")
        or "M-Main" in arch
        or attrs.get("Tag_CPU_name", "").startswith("8")
    ):
        return "thumb/v8-m.main/nofp"

    raise ValueError(f"{binary}: unrecognised multilib (arch={arch!r} fp={fp!r})")


def merged_library_path(sigs_dir: Path, multilib: str, cache_dir: Path) -> Path:
    """Build (or reuse) one merged FLIRT library JSON for `multilib`.

    Concatenates the non-nano component entries into a single
    `FlirtLibraryFile`-shaped JSON. `index`, `library` and `stats` are all
    `#[serde(default)]` on the Rust side (`src/flirt/mod.rs`), so omitting
    them is a valid schema-2 file.
    """
    slug = multilib.replace("/", "-")
    out = cache_dir / f"merged.{slug}.flirt.json"
    index = json.loads((sigs_dir / "index.json").read_text())
    rows = [r for r in index["libraries"] if r["multilib"] == multilib]
    if not rows:
        raise ValueError(f"no built libraries recorded for multilib {multilib}")

    entries: list[dict] = []
    sources: list[str] = []
    for name in MERGE_COMPONENTS:
        row = next((r for r in rows if r["library_name"] == name), None)
        if row is None or not row.get("output"):
            continue
        lib_path = sigs_dir / row["output"]
        lib = json.loads(lib_path.read_text())
        entries.extend(lib["entries"])
        sources.append(f"{name}={len(lib['entries'])}")

    merged = {
        "schema_version": "2",
        "arch": "armv7",
        "prologue_len": 32,
        "entries": entries,
    }
    cache_dir.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(merged))
    print(
        f"  merged {multilib}: {len(entries)} entries ({', '.join(sources)}) -> {out}",
        file=sys.stderr,
    )
    return out


def truth_from_addr2name(addr2name_path: Path, key: str) -> dict[int, set[str]]:
    data = json.loads(addr2name_path.read_text())
    if key not in data:
        raise KeyError(f"{key!r} not in {addr2name_path}")
    truth: dict[int, set[str]] = {}
    for addr, name in data[key].items():
        if int(addr) == 0:
            continue
        truth.setdefault(int(addr) & ~1, set()).add(name)
    return truth


def truth_from_nm(binary: Path) -> dict[int, set[str]]:
    """Ground truth read directly off the ELF's own symbol table."""
    nm = str(TOOLCHAIN_NM) if TOOLCHAIN_NM.is_file() else "nm"
    out = subprocess.run(
        [nm, "-S", "--defined-only", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    truth: dict[int, set[str]] = {}
    for line in out.splitlines():
        parts = line.split()
        # "<addr> <size> <type> <name>" or "<addr> <type> <name>" with no size.
        if len(parts) == 4:
            addr_s, _size, sym_type, name = parts
        elif len(parts) == 3:
            addr_s, sym_type, name = parts
        else:
            continue
        if sym_type not in ("t", "T"):
            continue
        try:
            addr = int(addr_s, 16) & ~1
        except ValueError:
            continue
        if addr == 0:
            continue
        # A linked ARM EABI binary routinely carries TWO co-located symbols
        # for one libgcc helper -- the RTABI name (`__aeabi_ddiv`) and the
        # generic GCC libcall name (`__divdf3`) both point at the same bytes
        # (measured: `nm -S` on nuttx and betaflight lists both at every one
        # of these addresses). Either is a correct identification of the
        # code that is actually there, so truth is a *set* of acceptable
        # names per address, not a single arbitrarily-chosen one.
        truth.setdefault(addr, set()).add(name)
    return truth


def score(binary: Path, library_path: Path, truth: dict[int, set[str]]) -> dict:
    matches = g.analysis.flirt_match_functions_with_evidence_path(
        str(binary), str(library_path)
    )
    by_addr = {int(m["entry_va"]) & ~1: m for m in matches}

    named = correct = wrong = ambiguous = 0
    wrong_examples: list[str] = []
    for addr, truth_names in truth.items():
        m = by_addr.get(addr)
        if m is None:
            continue
        if m["ambiguous"]:
            ambiguous += 1
            continue
        named += 1
        got = m["names"][0] if m["names"] else None
        if got in truth_names:
            correct += 1
        else:
            wrong += 1
            truth_name = "|".join(sorted(truth_names))
            if len(wrong_examples) < 10:
                wrong_examples.append(f"{hex(addr)}: got {got!r}, truth {truth_name!r}")
    return {
        "functions_in_truth": len(truth),
        "named": named,
        "correct": correct,
        "wrong": wrong,
        "ambiguous": ambiguous,
        "wrong_examples": wrong_examples,
    }


def print_row(label: str, opt: str, r: dict) -> None:
    print(
        f"{label:32s} {opt:12s} truth={r['functions_in_truth']:5d} "
        f"named={r['named']:4d} correct={r['correct']:4d} "
        f"wrong={r['wrong']:3d} ambiguous={r['ambiguous']:3d}"
    )
    for ex in r["wrong_examples"]:
        print(f"    WRONG: {ex}")


def run_rt_libopencm3(sigs_dir: Path, cache_dir: Path) -> list[dict]:
    addr2name = RT_LIBOPENCM3_ROOT / "addr2name.json"
    rows: list[dict] = []
    for opt in ("O0", "O2", "O2-noinline"):
        opt_dir = RT_LIBOPENCM3_ROOT / "stripped" / opt
        if not opt_dir.is_dir():
            continue
        for elf in sorted(opt_dir.glob("*.elf")):
            stem = elf.stem
            key = f"{opt}/{stem}"
            try:
                multilib = infer_multilib(elf)
            except ValueError as exc:
                print(f"SKIP {key}: {exc}", file=sys.stderr)
                continue
            lib_path = merged_library_path(sigs_dir, multilib, cache_dir)
            try:
                truth = truth_from_addr2name(addr2name, key)
            except KeyError as exc:
                print(f"SKIP {key}: {exc}", file=sys.stderr)
                continue
            r = score(elf, lib_path, truth)
            r.update(
                {
                    "corpus": "rt-libopencm3",
                    "firmware": stem,
                    "opt": opt,
                    "multilib": multilib,
                }
            )
            rows.append(r)
            print_row(f"rt-libopencm3/{stem}", opt, r)
    return rows


#: (project, binary-relative-path-under-compiled) picked because they cover
#: three distinct multilibs (see infer_multilib): freertos = v7-m/nofp,
#: nuttx = v7e-m/nofp, betaflight = v7e-m+fp/hard.
HOLDOUT_TARGETS: tuple[tuple[str, str], ...] = (
    ("freertos", "RTOSDemo.out"),
    ("nuttx", "nuttx"),
    ("betaflight", "betaflight_STM32F405.elf"),
)


def run_holdout(sigs_dir: Path, cache_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for opt in ("O0",):
        for project, relname in HOLDOUT_TARGETS:
            binary = HOLDOUT_ROOT / opt / project / "compiled" / relname
            if not binary.is_file():
                print(f"SKIP {project}: {binary} missing", file=sys.stderr)
                continue
            try:
                multilib = infer_multilib(binary)
            except ValueError as exc:
                print(f"SKIP {project}: {exc}", file=sys.stderr)
                continue
            lib_path = merged_library_path(sigs_dir, multilib, cache_dir)
            truth = truth_from_nm(binary)
            r = score(binary, lib_path, truth)
            r.update(
                {
                    "corpus": "decbench-holdout",
                    "firmware": project,
                    "opt": opt,
                    "multilib": multilib,
                }
            )
            rows.append(r)
            print_row(f"holdout/{project}", opt, r)
    return rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sigs-dir", type=Path, required=True)
    p.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("~/.cache/glaurung/system-libs/armtc-13.2.1/merged").expanduser(),
    )
    p.add_argument(
        "--corpus",
        action="append",
        choices=["rt-libopencm3", "holdout"],
        default=None,
    )
    p.add_argument("--json-out", type=Path, default=None)
    args = p.parse_args(argv)

    corpora = args.corpus or ["rt-libopencm3", "holdout"]
    rows: list[dict] = []
    if "rt-libopencm3" in corpora:
        rows.extend(run_rt_libopencm3(args.sigs_dir.expanduser(), args.cache_dir))
    if "holdout" in corpora:
        rows.extend(run_holdout(args.sigs_dir.expanduser(), args.cache_dir))

    totals = {
        "functions_in_truth": sum(r["functions_in_truth"] for r in rows),
        "named": sum(r["named"] for r in rows),
        "correct": sum(r["correct"] for r in rows),
        "wrong": sum(r["wrong"] for r in rows),
        "ambiguous": sum(r["ambiguous"] for r in rows),
    }
    print("\nTOTALS:", totals)
    if args.json_out:
        args.json_out.write_text(
            json.dumps({"rows": rows, "totals": totals}, indent=2, sort_keys=True)
            + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
