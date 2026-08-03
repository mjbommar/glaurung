# extbench — Glaurung against other decompilers, on real binaries

`tools/decbench_matrix.py` scores Glaurung against a corpus we compile ourselves,
where source is available and GED / type-match / byte-match are meaningful. This
harness does the other half: it runs Glaurung, **Ghidra**, **angr** and
**RetDec** over real, shipped, mostly-stripped Linux binaries where there is no
source, and measures the things that can still be measured honestly.

The two are complements. Curriculum metrics say how close the output is to the
source we started from; extbench says what happens on a binary nobody built for
us — whether the functions are even found, whether the emitted calls are the
calls the CPU makes, and how the output compares to what an analyst would
otherwise open Ghidra for.

## Quick start

```bash
tools/extbench/build_corpus.sh /tmp/extbench          # copy + strip samples, write lists
tools/extbench/runall.sh /tmp/extbench/outA /tmp/extbench/tierA.txt
tools/extbench/runall.sh /tmp/extbench/outB /tmp/extbench/tierB.txt

python3 tools/extbench/report.py /tmp/extbench/outA --filter strip_ --per-tag
python3 tools/extbench/callcheck.py /tmp/extbench/outA /tmp/extbench/corpus --filter strip_
python3 tools/extbench/compilable.py /tmp/extbench/outA --filter strip_
```

`python3 tools/extbench/config.py` prints which comparators are available and
what to set if one is missing.

| variable | what it points at | default |
|---|---|---|
| `EXTBENCH_PYTHON` | a venv that can `import angr` and `import pyghidra` | the DecBench checkout venv |
| `EXTBENCH_GLAURUNG` | the `glaurung` CLI under test | `.venv/bin/glaurung` in this checkout |
| `EXTBENCH_GHIDRA` | unpacked Ghidra release directory | `~/.cache/ghidra-releases/ghidra_12.1.2_PUBLIC` |
| `EXTBENCH_RETDEC` | `retdec-decompiler` binary | `~/.local/opt/retdec/bin/retdec-decompiler` |
| `EXTBENCH_SAMPLES` | sample tree root | `/nas4/data/binary-analysis/glaurung/binaries-small` |

A missing comparator is reported, never silently skipped.

## The two corpora

**Tier A — DWARF ground truth.** `getconf`, `getent`, `iconv` from Alpine 3.18,
x86-64 / AArch64 / ARMv7. These nine are the only binaries in the sample tree
that shipped unstripped with DWARF, so they are the only place a *prototype* can
be scored against truth. Each is also stripped locally into a twin; the
original's DWARF still describes it exactly, because stripping moves no code.
**The sym/strip pair is the whole point** — with DWARF present three of the four
tools score 100% on everything and the benchmark says nothing.

**Tier B — real-world at scale.** Stripped `cat`, `grep`, `find`, `tar`,
`bash`, scored against `.eh_frame` FDE starts: a *sound but incomplete*
reference. Every FDE start is a real function entry, but functions built without
unwind tables have none — so it supports a recall claim and never a
false-positive one.

Where a binary has more than the requested number of ground-truth functions, the
sample is taken at an **even stride across the image**, not the first N. `bash`
has 2,345 FDEs and its lowest 40 addresses are a contiguous run of 29-to-46-byte
stubs; sampling those once reported angr as finding 4 of 40 functions in a binary
where it had located 2,259 of 2,345.

## What each script answers

| script | question |
|---|---|
| `gt.py` | ground truth: DWARF subprograms (name, VA, size, param types), `.eh_frame` FDEs, imports |
| `drive.py` | run all four tools over one binary against the same function set |
| `runall.sh` | the same over a corpus list |
| `analyze.py` / `report.py` | success, discovery recall, prototypes, goto density, machine leakage, callee and string recovery |
| `callcheck.py` | **the correctness probe** — emitted calls vs `llvm-objdump` over the exact DWARF byte range |
| `compilable.py` | `gcc -fsyntax-only` rate with a permissive per-dialect prelude |
| `sidebyside.py` | all four tools' C for one ground-truth function, next to its DWARF signature |
| `discover_only.py` | cross-tool discovery consensus where there is no ground truth at all |

Only `callcheck.py` is a correctness measure. Everything else describes the
artifact — how much of it there is, how much machine detail survives into it,
how much of what an analyst reads first comes back. Read them together, and read
them next to `sidebyside.py` output; a metric alone has been wrong here before.

## Seven traps, each of which produced a wrong headline

Kept here because they will recur if this is ever reimplemented.

1. **angr reports 32-bit ARM functions at `addr | 1`** (the Thumb convention)
   while DWARF `DW_AT_low_pc` is even. Exact-VA matching scored 19 correctly
   found functions as misses and read as "angr collapses on ARMv7".
   `run_angr.py` clears bit 0 on ARM only.
2. **"First N functions by address" is a biased sample** — see the `bash` case
   above. Use the stride in `drive.py`/`analyze.py`, and keep the two in sync or
   tools get scored on functions nobody asked them for.
3. **`pyghidra.open_program()` defaults `project_location` to the binary's own
   directory** and reopens it if it already exists, so a second run over the same
   binary skips auto-analysis and looks 3–8× faster (`tar`: 4.6 s cached vs
   33.7 s fresh). It also writes `<name>_ghidra/` into the sample tree.
   `run_ghidra.py` passes an explicit temporary project location and removes it.
4. **A mean of per-binary means is not a per-function rate.** A two-function
   binary once outweighed a 22-function binary and manufactured an AArch64
   prototype regression. Function metrics are micro-averaged over their scored
   functions; only timing remains a per-binary mean, and the report prints both
   denominators.
5. **Ambient `DEBUGINFOD_URLS` can turn local disassembly into a network job.**
   LLVM spent minutes polling `debuginfod.ubuntu.com` for a 40 KiB stripped
   binary. The call probe clears that variable and never asks for external debug
   data.
6. **LLVM 21 prints stripped PLT targets as `.plt.sec+offset`.** Treating that as
   an unresolved call made every reference tool appear to invent the same libc
   calls. The probe uses GNU `objdump` / the matching GNU cross-objdump, and
   resolves indirect x86 GOT calls from dynamic relocations.
7. **Whole-image output must still use the shared sample.** RetDec cannot be
   asked for individual functions; scoring every returned row gave it a 5,351
   function denominator against 263 shared targets. `callcheck.py` now applies
   the same address-deduped even stride as `drive.py` and `analyze.py`.

## Scoring on stripped ARMv7

`callcheck.py` refuses to score 32-bit ARM. Stripping removes the `$a`/`$t`
mapping symbols, so no disassembler available here can tell Thumb from ARM, and
the *reference* disassembly is wrong. Those cells are dropped and named in the
output rather than scored — a limit of the reference, not a result about the
decompilers.
