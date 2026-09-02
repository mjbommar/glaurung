# Phase 8 — Ground truth at scale: the DWARF twin oracle

> **Kind:** plan · **Status:** proposed

## The problem this solves

The execution differential is the strongest evidence we have, and it has a
survivorship bias built in: it can only score functions simple enough to
recompile and drive. The fixture corpus is therefore small (219 sources) and
hand-designed. DecBench is held out. Between them there is nothing that
scores recovery on **arbitrary real binaries** — which is what the tool is
for.

The oracle that closes the gap is one we already trust and already parse:
**DWARF**. Build (or obtain) a binary with debug info, strip a copy,
decompile the *stripped* copy, and score the recovered facts against the
unstripped twin's DWARF:

* function boundaries and count (discovery precision/recall),
* prototype arity and parameter types (`type_match`-class metrics, but on
  our own terms),
* local variable counts and types where recoverable,
* names, for the subset DWARF names.

Every binary with debug info becomes labeled ground truth. No hand-written
expectations, no recompilation requirement, no execution requirement — so it
scales to C++ template soup, to Go, to whatever a distro ships.

## 8.1 Check what exists first

A `dev-oracle` cargo feature already exists (it is one of the gate lanes
nothing but `feature-build-gate.sh` builds). **Before writing anything,
inventory what is behind it** — this phase may be partly built and
unreachable, which given this codebase's history is the expected case, and
extending an existing skeleton beats a parallel one.

## 8.2 `tools/dwarf_oracle.py`

* Input: a binary with DWARF (or a `--debug-twin` pair). Pipeline: strip a
  temp copy (respecting `TMPDIR`), run the real decompile entry point over
  the stripped copy, parse the twin's DWARF (the `src/debug/` machinery —
  reuse, don't reimplement), match functions by address, emit a per-function
  and aggregate score JSON.
* Matching rule and scoring vocabulary are shared with the def-use census
  style: exact counts, no fuzzy credit, a `--explain <function>` mode that
  prints the diff for one function (the analyst-debuggable form is what made
  `dectest` usable; copy it).
* Crucially, the scorer must treat DWARF as *imperfect* truth: optimized-out
  parameters, `<artificial>` entries, and merged functions are recorded as
  `unscoreable`, not failures — the count of unscoreable entries is itself
  reported, so the denominator is honest.

## 8.3 Populations, smallest first

1. **Our own fixtures** (we build them with `-g` already): validates the
   oracle against ground truth we know independently — where the oracle and
   the differential disagree about a fixture, one of them is wrong and it is
   findable. This is the calibration step; do not skip it.
2. **`samples/binaries/`** entries that carry debug info.
3. **Distro binaries via debuginfod** (opt-in, network): the 12.8 MB
   DWARF-heavy fixture already in the bench ladder, then a pinned list of
   ~20 `/usr/bin` binaries with their buildids recorded, so the population
   is stable even though the host is not.

## 8.4 Ratchet

`tests/dwarf_oracle_baseline.json` over populations 1–2 (hermetic), refreshed
under the same discipline as the other six side files, `slow`-marked, run in
the local gate. Population 3 is reporting-only (network + host-dependent),
never a gate.

## What this phase is not

Not a benchmark for publication (that is DecBench's job, and it stays held
out), and not a replacement for the differential — execution proves semantics,
DWARF proves *facts about recovery*. They fail differently, which is why
having both is the point.

## Acceptance

* Oracle runs over all fixture lanes and its scores are consistent with the
  known baselines (calibration finding count: 0 unexplained).
* Baseline recorded over populations 1–2; gate lane added.
* One page in `docs/development/` describing the metric definitions, so a
  number like "arity exact-match 91%" has a written meaning before anyone
  quotes it.

## Effort

Two to three days after Phases 2 and 7, plus whatever 8.1 discovers behind
`dev-oracle`.
