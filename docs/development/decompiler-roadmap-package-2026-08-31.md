# Decompiler roadmap planning package — 2026-08-31

This is the entry point for the evidence-driven roadmap research completed
after the pinned 94,575-function DecBench run. It maps each roadmap workstream
and milestone to its authoritative evidence, detailed implementation plan, and
next bounded increment.

This package is internal. It does not authorize publication, submission,
email, issues, pull requests, commits, or pushes.

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
| R1 missing-body accounting | 217 rows span identity, dataset, and ARM lift causes rather than one generic decompiler failure | [failure taxonomy](../design/decbench-full-failure-taxonomy-2026-08-31.md), [remediation plan](decbench-failure-remediation-plan-2026-08-31.md) | i386 stdcall RED fixture, then Cortex-M MRS/MSR RED fixture |
| R2 large functions | compile and structural perfection collapse as recovered output grows | [large-function plan](large-function-plan-2026-08-31.md) | smallest source-grounded size/shape ladder with phase telemetry |
| R3 optimized structure | structural baseline is GCC O0 only; O2 readability is not a population-level gate | [optimized structural-quality plan](optimized-structural-quality-plan-2026-08-31.md) | parameterize existing runner, adding GCC O2 before Clang lanes |
| R4 PE/PDB/Mach-O | many PE samples but no coherent source/PDB matrix; one Mach-O sample only | [format-parity plan](pe-pdb-macho-parity-plan-2026-08-31.md) | four-cell clang-cl PE32/PE32+ identity lane |
| R5 hostile/production shapes | existing realistic corpus mainly proves x86-64 ELF discovery, not body semantics | [real-world asset plan](real-world-malware-asset-plan-2026-08-31.md) | add body accounting and a semantic subset to the existing corpus |
| R6 performance/determinism | performance tool is wired but has no baseline and can pass incomplete evidence | [performance/determinism plan](performance-determinism-ratchet-plan-2026-08-31.md) | RED tests for missing/partial/incomparable measurement states |
| R7 breadth/thin modules | valuable lower-priority gaps remain after proven body/format/quality risks | [fuzzing](test-estate/03-fuzzing.md), [thin modules](test-estate/05-thin-modules.md), [matrix extension](test-estate/07-matrix-extension.md) | finish current thin-module lanes without displacing R0/R1/R2 gates |

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

Current state: taxonomy complete; product/dataset remediation not implemented.

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

Current state: GCC O0 baseline strong within scope; other populations open.

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

Current state: measurement utility and determinism tests exist; unified release
artifact and valid baseline open.

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
```

## First six bounded increments

1. Make inventory generation renewable and add a stale-artifact check.
2. Add the i386 stdcall collision fixture and bounded resolver change.
3. Add the Cortex-M special-register fixture and minimum lift/refusal contract.
4. Add the smallest large-function size/shape ladder with phase telemetry.
5. Make the existing performance gate fail closed before recording a baseline.
6. Parameterize the structural runner for GCC O2, preserving the GCC O0
   population separately.

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

