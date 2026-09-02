# Decompiler roadmap planning package — 2026-08-31

This is the entry point for the evidence-driven roadmap research completed
after the pinned 94,575-function DecBench run. It maps each roadmap workstream
and milestone to its authoritative evidence, detailed implementation plan, and
next bounded increment.

This package is internal. It does not authorize publication, submission,
email, issues, pull requests, commits, or pushes.

## Progress update — 2026-09-01

Recent history materially advanced R1, R3, R4, R6, and R7. F1a now has a
collision-safe resolver and real PE32 fixture (`0d6b30d1`), and the F1b core
distinguishes imports from absent symbols. The readability census now contains
3,580 rows across both corpora and GCC/Clang O0/O2 (`1329382d`); a dispatch
relaxation was reverted after adding 162 gotos while removing only 37 breaks.
Closure and effect expectations remain lane-independent.

An instruction-count baseline over three large references now exists and was
proved to reject an injected 10% regression (`a938d897`). It is not yet a
release baseline: missing, partial, and incomparable evidence still fails open,
and provenance, RSS, output, and body completeness are absent. PE field
reporting, PDB-path exposure, and RSDS scanning were repaired (`610d3afd`);
the clang-cl lane then established a `/nodefaultlib` requirement and this local
toolchain's inability to emit the planned TLS fixture (`8fb47f62`).

## Pinned evidence

The full-run evidence boundary is:

* 803 binaries and 94,575 requested functions;
* 94,358 returned bodies and 217 missing bodies;
* 213.1 seconds for the complete decompile stage;
* Glaurung revision `7bc7353923cc659d3e970dbde8455b2b9b503a6d`;
* DecBench revision `f76dae075d4d82004fb21132b3f15e43b680e179`;
* dataset revision `e5eb576d66ee36793b800a4dd45e291e0add4472`; and
* retained root
  `/home/mjbommar/.cache/glaurung/decbench-submission/20260831T180316Z`.

These identities establish what was measured. Plans use owned, source-grounded
fixtures for implementation and keep DecBench held out.

## Workstream map

| workstream | demonstrated problem | detailed authority | first implementation increment |
|---|---|---|---|
| R0 measurement/inventory | generated inventory cannot reproduce itself; JSON and Markdown snapshots disagree | [inventory-authority plan](test-inventory-authority-plan-2026-08-31.md) | recover committed canonical records, schema v2, atomic generation, `--check` |
| R1 missing-body accounting | 217 rows span identity, dataset, and ARM lift causes rather than one generic decompiler failure | [failure taxonomy](../design/decbench-full-failure-taxonomy-2026-08-31.md), [remediation plan](decbench-failure-remediation-plan-2026-08-31.md) | F1a landed and F1b core landed; next F2a, then F1c/F1d validation |
| R2 large functions | compile and structural perfection collapse as recovered output grows | [large-function plan](large-function-plan-2026-08-31.md) | smallest source-grounded size/shape ladder with phase telemetry |
| R3 optimized structure | readability covers GCC/Clang O0/O2, but closure/effects remain lane-independent | [optimized structural-quality plan](optimized-structural-quality-plan-2026-08-31.md) | lane-key closure/effects, then add optimized shape predicates |
| R4 PE/PDB/Mach-O | many PE samples but no coherent source/PDB matrix; one Mach-O sample only | [format-parity plan](pe-pdb-macho-parity-plan-2026-08-31.md) | four-cell clang-cl PE32/PE32+ identity lane |
| R5 hostile/production shapes | existing realistic corpus mainly proves x86-64 ELF discovery, not body semantics | [real-world asset plan](real-world-malware-asset-plan-2026-08-31.md) | add body accounting and a semantic subset to the existing corpus |
| R6 performance/determinism | a three-reference baseline exists, but incomplete/incomparable evidence can pass | [performance/determinism plan](performance-determinism-ratchet-plan-2026-08-31.md) | RED tests for fail-open states, then provenance/RSS/completeness |
| R7 breadth/thin modules | valuable lower-priority gaps remain after proven body/format/quality risks | [fuzzing](test-estate/03-fuzzing.md), [thin modules](test-estate/05-thin-modules.md), [matrix extension](test-estate/07-matrix-extension.md) | finish current thin-module lanes without displacing R0/R1/R2 gates |
| R8 test automation/coverage | the default suite is 65% decompiler-IR unit tests over synthetic bytes; 19 `disasm` tests, 4 `decompile` tests (all profiler), and 20 toolchain gates that pass silently when the compiler is absent | [this section](#r8--test-automation-and-coverage), [CI gap](test-estate/10-ci-environment-gap.md) | make silent toolchain skips visible, then bind `cargo test` to the fixture corpus |

The product-facing ordering and non-goals remain in the
[real-binary roadmap](real-binary-decompiler-roadmap-2026-08-31.md).

## Complete failure taxonomy

The 217 missing bodies reconcile exactly:

| class | rows | owner | required disposition |
|---|---:|---|---|
| F1a i386 stdcall decoration | 33 | Glaurung adapter | collision-safe decorated-symbol resolution |
| F1b import-only identity | 63 | adapter and scoring contract | explicit external/import record; no local-body claim |
| F1c manifest-only identity | 88 | dataset validation | remove, correct, or provide valid source/binary identity |
| F1d source-CFG-only gzip wrapper | 2 | dataset/build provenance | prove elimination/rename or correct identity |
| F2a Cortex-M MRS/MSR lift gap | 31 | ARM32 lifter | conservative special-register semantics or typed refusal |
| **total** | **217** |  |  |

E1 is separate: thirteen Dexter compile-evidence rows lack original bytes in
the evaluator. They are not among the 217 and do not indicate missing Glaurung
bodies.

The 35-checkpoint ledger and binary/source-CFG evidence are retained in the
taxonomy. Completion means zero unexplained rows, not merely a favorable
aggregate percentage.

## Milestone evidence map

### M1 — trustworthy estate

Required proof:

* canonical inventory inputs committed;
* all generated views atomically current under `--check`;
* explicit runner/reachability records;
* zero unexplained unreachable entries; and
* CI/local gates named separately.

Current state: planned, not achieved. The current snapshots are stale and the
generator inputs are missing.

### M2 — complete accounting

Required proof:

* every requested address yields a body or typed disposition;
* all F1a–F2a rows have independent fixtures;
* import/alias/runtime identities are not scored as local bodies; and
* a fresh pinned run has no unexplained missing body.

Current state: taxonomy complete; F1a and the F1b product core are implemented.
F1c, F1d, F2a, scoring-contract work, and a fresh pinned full run remain open.

### M3 — bounded large functions

Required proof:

* size-by-shape ladder and production-shaped tier;
* phase/tail/RSS/output/MIR/SSA telemetry;
* body-loss, timeout, refusal, and quality ratchets; and
* no small-function improvement hiding large-function explosion.

Current state: candidate size curve measured; fixture/telemetry implementation
open.

### M4 — optimized readability

Required proof:

* GCC/Clang O0/O2 structural populations with stable denominators;
* optimized shape and readability predicates;
* priority dropped-value/call/type defects fixed or precisely limited; and
* execution, def-use, architecture, signal, and performance gates green.

Current state: readability covers both corpora and GCC/Clang O0/O2. Lane-keyed
closure/effects, schema v2, and optimized shape predicates remain open.

### M5 — format parity

Required proof:

* hermetic PE32, PE32+, Mach-O x86-64, and Mach-O ARM64 O0/O2 cells;
* source/linker/PDB/DWARF identity and type oracles;
* PE runtime/loader and Mach-O bind/fixup/fat-slice coverage; and
* provisioned fetched-fixture lane cannot pass with zero inputs.

Current state: broad PE parsing assets and one tested Mach-O stub sample;
semantic parity open.

### M6 — real-world confidence

Required proof:

* source-built matched hostile/control families;
* body, structure, compile/execute, resource, and refusal oracles;
* mandatory tool availability in release lane; and
* third-party probes kept outside semantic aggregates.

Current state: strong discovery substrate exists; deeper oracles and format/
architecture balance open.

### M7 — release gate

Required proof:

* provenance-complete performance baseline;
* fail-closed completeness, cost, RSS, output, and determinism report;
* all prior milestone denominators and build/asset hashes bound together; and
* held-out evaluation reported internally without leakage into fixtures.

Current state: an initial instruction baseline and determinism tests exist;
fail-closed completeness, provenance, resource/output evidence, and the unified
release artifact remain open.

### M8 — the suite measures what it claims

Required proof:

* no test can pass by not running: every toolchain-dependent test reports a
  visible skip with a reason, never a silent `return`;
* the default `cargo test` exercises the fixture corpus end to end, not only
  lifted IR in isolation;
* per-area coverage is recorded and ratcheted, so a module cannot quietly stay
  at two tests while the tree around it grows; and
* local and CI runs are compared on the same denominator, with the difference
  explained rather than tolerated.

Current state: measured for the first time on 2026-09-01 and worse than the
headline count suggests. See R8 below.

## R8 — test automation and coverage

The counts are healthy and the distribution is not. Measured directly rather
than estimated:

| | plain `cargo test` | `--features python-ext` |
|---|---:|---:|
| passing | **2,829** | **2,951** |
| ignored | 4 | 4 |

**Where those tests are.** `ir` holds 1,867 of 2,859 named tests -- **65% of
the suite is decompiler IR internals**. The rest thins out fast: `analysis`
264, `core` 183, `triage` 106, `formats` 99, `strings` 33, `symbols` 22,
`entropy` 20, `disasm` **19**, and `decompile` **4** -- all four of which test
the profiler wrapper, not decompilation. There is no end-to-end decompile in
the default Rust suite at all.

**What they run on.** 75 distinct sample paths are named across all Rust tests:
**55 Linux, 9 Windows, 1 macOS**. By language: 22 native, 3 rust, 3 go, 2 java,
2 dotnet, 1 fortran -- and the non-C entries are format work
(`analysis/gopclntab.rs`, `analysis/java_class/`, `analysis/cil_metadata.rs`),
not decompilation. Four cross-compiled targets appear as real binaries:
`windows-x86_64`, `armhf`, `arm64`, `riscv64`. MIPS, PPC64 and s390x are named
in strings and comments but have no sample under test.

**No Rust test uses `tests/decompiler_fixtures/` as a corpus.** The 196-fixture
matrix that actually proves the decompiler correct is driven entirely from
Python (`tools/dectest.py` and the execution differential). `cargo test` --
the command a Rust contributor runs -- never reaches it. Individual `src/`
tests do `include_bytes!` single fixture *sources* and compile them ad hoc,
which is a different and much weaker thing.

**Twenty tests pass without testing anything.** The pattern is:

```rust
Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
```

A test that compiles a fixture and cannot find its compiler returns `ok`
having asserted nothing -- not skipped, not reported, indistinguishable from a
pass. On a machine without cross-compilers an unknown fraction of the 2,829 is
vacuous, and the total does not move. This is the same defect class as the
Python-side skips that phase 1.6 made visible with `-ra`, and it is worse:
there is no equivalent flag, because these are not skips.

### R8 status — landed 2026-09-01

1. **Silent toolchain gates** (`1b9f19c9`). 21 sites returned `ok` having
   asserted nothing. Measured both ways: 0 skips on a provisioned machine
   (`GLAURUNG_REQUIRE_TOOLCHAINS=1`), **33 vacuous passes** on a PATH-shimmed
   bare machine. CI demands the toolchains.
2. **`cargo test` reaches the corpus** (`55246eff`). The default Rust suite now
   decompiles nine committed canary objects end to end; proven load-bearing by
   injecting a stub into `ast::render`.
3. **Per-module census** (`753bf1dd`, corrected `18640412`, closed `3fb3184c`).
   Never-executed tests: 271 -> 195 -> **0**. Both intermediate figures were
   wrong: 271 misread a `cfg` gate (`python-ext` already pulled in `exec`), and
   195 was a correct measurement of a non-problem — nothing prevented
   `src/symbolic/` from running, and the first `--features symbolic` run passed
   3,025/0. A ratchet counting that hole would have recorded it indefinitely
   while the fix was one workflow stanza.
4. **Perf gate fails closed and is scheduled** (`4f4f88e3`). Three states
   returned 0, including a baseline reference the run never measured. Now exit
   3, "not evidence" — and only then scheduled, because scheduling a fail-open
   gate manufactures assurance.
5. **The TDD corpus** (`1694bb06`, `7be914cf`). 1,162 measured failures across
   six axes as strict xfails; see `test-estate/EXECUTION.md` for the table.

Remaining: R8.4 (local/CI denominator gap) and R8.5 (1 macOS sample, 0
MIPS/PPC64 under test). 92 tests stay behind `solver-*` features that link
external SMT libraries — a provisioning decision, recorded as
`solver_gated_estimate` rather than hidden.

### R8 increments

1. **Make the silent gates visible.** Replace the 20 `NotFound => return` sites
   with a helper that records the missing tool and fails the run if *every*
   gated test in a module skipped -- an all-skipped module is indistinguishable
   from a deleted one. Cheap, mechanical, and it converts an unknown into a
   number.
2. **Bind `cargo test` to the fixture corpus.** A Rust-side smoke lane over the
   committed canary objects (`tests/decompiler_fixtures/canary/`, already built
   and hermetic for exactly this reason) so a Rust change that breaks
   decompilation fails in the Rust suite rather than only in Python.
3. **Record per-area coverage and ratchet it.** A committed table of tests per
   module with the same discipline as the fitness ratchet: `disasm` at 19
   against `ir` at 1,867 is a fact worth pinning so the imbalance cannot widen
   silently.
4. **Close the local/CI denominator gap.** Local and CI must run the same
   count or explain the difference; today CI lacks cross toolchains and the
   built fixture directory (phase 10), and the difference is absorbed rather
   than reported.
5. **Extend the format/arch matrix where it is thinnest.** One macOS sample and
   zero MIPS/PPC64 samples under test is the coverage floor, not a plateau; the
   Mach-O thin lanes (`ba2fe5c2`) are the template.

## Dependency order

```text
R0 inventory authority
 ├──> every later fixture/gate has durable reachability and metadata
 └──> M1

R1 identity/body accounting ──> R4 format identity ──> M2/M5
R2 large telemetry ────────────> R3 size-aware quality ──> M3/M4
R5 hostile families ───────────> R4 format cells + R6 resource gates ──> M6
R6 fail-closed measurement <─── R2/R3/R4/R5 reference cells ─────────> M7

R7 breadth follows demonstrated gaps and may proceed independently only when
it does not delay R0/R1/R2 acceptance work.

R8 measurement integrity underpins every other workstream's evidence: a gate
that can pass without running cannot support a milestone claim. Its first
increment is independent of all others and should not wait.
```

## First six bounded increments

1. Make inventory generation renewable and add a stale-artifact check.
2. Add the Cortex-M special-register fixture and minimum lift/refusal contract.
3. Add the F1c validator and trace F1d provenance.
4. Add the smallest large-function size/shape ladder with phase telemetry.
5. Make the performance gate fail closed and add provenance, completeness,
   RSS, and output evidence to its baseline contract.
6. Lane-key structural closure/effects and add optimized shape predicates.
7. Make the 20 silent toolchain gates visible, and fail a module whose gated
   tests all skipped (R8.1) -- independent of every other increment.

PE/Mach-O and hostile-family minimal cells follow as soon as those substrate
contracts can record their runner, provenance, failure, and resource evidence.

## Change discipline

Every implementation increment:

* starts with a real failing fixture/test;
* names source, binary, build, oracle, runner, and applicability;
* makes missing/unsupported/inapplicable distinct from pass;
* runs focused tests before the full required gates in `CLAUDE.md`;
* refreshes every affected baseline and inventory view deliberately;
* reports local focused, full local, committed/pushed, and remote CI states
  separately; and
* updates the [research diary](../design/decompiler-roadmap-diary-2026-08-31.md)
  with evidence that changed the next decision.

This planning work itself remains documentation-only and internal.

## Package validation

The package is structurally complete when:

* R0–R7 and M1–M7 each map to an authority and completion evidence;
* the failure counts reconcile to 217 plus the separate thirteen E1 rows;
* local Markdown links resolve;
* no plan claims an unimplemented selector, baseline, runner, or matrix exists;
* stale older-plan claims are corrected where discovered; and
* concurrent implementation work remains untouched.
