# Decompiler roadmap

> **Kind:** plan · **Status:** proposed

This is the one live plan set for the decompiler and the estate around it. It
maps each workstream (R0–R8) and milestone (M1–M8) to its authoritative
evidence, its detailed implementation plan, and its next bounded increment.
The evidence baseline is the pinned 94,575-function DecBench run described
under [Pinned evidence](#pinned-evidence).

This package is internal. It does not authorize publication, submission,
email, issues, pull requests, commits, or pushes.

## How to read this

Four rules govern how work here is chosen and how a box is allowed to be
ticked. They were paid for by the roadmap this one replaces (archived as
[`history/design/decompiler-roadmap-2026-08-13.md`](../../history/design/decompiler-roadmap-2026-08-13.md)),
and every one of them was learned by getting it wrong first.

- **Two tracks, judged differently.** CORRECTNESS succeeds when fixture cells
  move `fail` → `pass` or a defect census goes down; feedback is days.
  ARCHITECTURE succeeds when a boundary holds — a narrower API, one reason to
  change, a capability something else can be built on — and is *expected* to
  move zero cells. Judge each by its own standard. An architecture item that
  has to promise cell movement to get scheduled will be over-sold, and a
  correctness item asked to justify itself architecturally gets blocked on a
  refactor it does not need.
- **`[x]` requires a production caller.** "Implemented" and "connected" are
  different claims and conflating them has cost real time here: `SymbolStore`
  was ticked while every caller lived in `session_tests.rs`, and a whole
  width-propagation cluster in `ast.rs` was reachable only from its own tests.
  A box does not tick until something in the shipping pipeline asks it a
  question. `[~]` is partial or diagnostic-only; `[ ]` is open; `[!]` is
  blocked; `[r]` is measured and rejected — do not revive it unchanged.
- **Phases and workstreams are views, not additional work.** The same item
  routinely appears in a workstream row, a milestone, and a plan document.
  Landing it and ticking one of the three leaves the plan claiming it is
  undone. Record progress in every view, and never quote a
  percentage-complete over the boxes: closing one real item moves one, two or
  three of them depending only on how many views mention it.
- **Capability census before a modelling theory.** Before attributing a
  cluster of failures to a deep modelling gap, check whether the capability
  exists at all. Three whole missing ISA categories (AArch64 scalar FP, i386
  x87, ARM32 modified immediates) were found in three days by grepping the
  lifters for an ISA's mnemonic families and diffing that against what the
  corpus emits, and each looked like scattered unrelated fixture failures
  beforehand.

## The plan set

The documents in this directory are the detailed authorities. The live status
of everything they depend on is
[`test-estate/EXECUTION.md`](../test-estate/EXECUTION.md) — the todo list of
record, carrying the commit for every landed item.

| plan | workstream |
|---|---|
| [2026-09-02 review implementation plan](../../history/decompiler-review-2026-09-02/PLAN.md) | Detailed implementation and verification packages WP0-WP10; subordinate to this index and the execution ledger |
| [test-inventory-authority.md](test-inventory-authority.md) | R0 — make the generated inventory reproducible and atomic |
| [decbench-failure-remediation.md](decbench-failure-remediation.md) | R1 — the 217-row missing-body taxonomy, class by class |
| [large-functions.md](large-functions.md) | R2 — size/shape ladder and phase telemetry |
| [optimized-structural-quality.md](optimized-structural-quality.md) | R3 — GCC/Clang O0/O2 structural populations and readability |
| [pe-pdb-macho-parity.md](pe-pdb-macho-parity.md) | R4 — hermetic PE32/PE32+/PDB and Mach-O lanes |
| [real-world-malware-assets.md](real-world-malware-assets.md) | R5 — hostile shapes with real oracles |
| [performance-determinism-ratchet.md](performance-determinism-ratchet.md) | R6 — fail-closed performance and determinism evidence |
| [real-binary-decompiler.md](real-binary-decompiler.md) | the product-facing ordering, non-goals, and the items carried from the 2026-08-13 roadmap |
| [distribution.md](distribution.md) | getting Glaurung installable — the never-fired release matrix, the 104-package base install, and what a wheel costs |
| [../test-estate/README.md](../test-estate/README.md) | R7 — the estate-hygiene layer these sit on top of |

## Progress

Recent history materially advanced R1, R3, R4, R6, and R7. F1a now has a
collision-safe resolver and real PE32 fixture (`0d6b30d1`), and the F1b core
distinguishes imports from absent symbols. The readability census now contains
3,580 rows across both corpora and GCC/Clang O0/O2 (`1329382d`); a dispatch
relaxation was reverted after adding 162 gotos while removing only 37 breaks.
Closure and effect expectations remain lane-independent.
R3's dropped inlined-`printf` argument is now fixed using fail-closed literal
format-string arity, with GCC/Clang O2 real-fixture and six-cell def-use-census
coverage. This is a bounded parity gain; generic variadic arity remains open.

Two of the five missing-body classes are now closed at the product end. F2a
turned out not to be a lifter gap at all: Capstone rejected every Cortex-M
system-register encoding, so the function was abandoned before any lift ran
(`0031c3ee` — decoder mode, `SysReg` operand, and the `MRS`/`MSR` lift, with a
body-recovery fixture). R4 gained hermetic lanes rather than plans: a PE
entry/TLS/import identity fixture (`99113bc8`), a clang-cl PE32/PE32+ identity
lane (`8c0a89f6`), a PDB type/layout lane (`c7200d2d`), and Mach-O x86-64 and
ARM64 thin lanes (`ba2fe5c2`). Each of the four found a real defect in the
code it was pointed at. Mach-O fat slices, the F1c dataset validator, and the
F1d provenance trace stay open.

An instruction-count baseline over three large references exists and was proved
to reject an injected 10% regression (`a938d897`), and the gate now **fails
closed** and is scheduled (`4f4f88e3`): three states that used to exit 0 —
including a baseline reference the run never measured — now exit 3, "not
evidence". It is still not a release baseline: provenance, RSS, output health,
and body completeness are absent. PE field reporting, PDB-path exposure, and
RSDS scanning were repaired (`610d3afd`); the clang-cl lane established a
`/nodefaultlib` requirement and this local toolchain's inability to emit the
planned TLS fixture (`8fb47f62`).

R7's Go lanes are wired and **opt-in** behind `GLAURUNG_FIXTURE_GO`
(`6660f1f7`); the manifest entries and four baseline refreshes they need are
still open. R8 landed in five parts — see [R8 status](#r8-status) — and the
never-executed-test pool reached zero (`3fb3184c`).

The 2026-09-02 review implementation lane has completed WP0's gate-integrity
package and WP7A's width-proved render idioms. Its bounded WP1 trial rejected
MIR as the production definedness consumer; the replacement final-AST verifier
is landed, while responsibility-by-responsibility MIR cleanup remains in WP10.
WP4's replacement structurer and WP5's typed-switch recovery now have verified
shadow/opt-in vertical slices over real conditionals, reducible and irreducible
loops, multi-exit loops, and switches as large as 256 cases. They are not the
production default and do not yet have corpus-wide promotion evidence. WP4's
bounded cleanup now handles verified short straight-line return tails as well
as one-block epilogues: the real gcc-O0 `hybrid_switch` shadow fell from four
gotos to one. Switch arms now also stop at a verified shared in-loop
post-dominator, leaving the continuation once after the switch; real flattened
and obfuscated state machines pass execution differentials after the change.
The current exploratory corpus has 6 rather than 14 goto regressions. The run
shared uncommitted parser sources, so the review plan keeps a clean pinned rerun
as a promotion prerequisite.

WP5 also now carries exact chained unsigned-guard semantics: `ja`/`jnbe`
fallthroughs are inclusive and `jae`/`jnb` fallthroughs are exclusive. The
Clang O2 fixture-204 adjacent-table case now reaches both the verified shadow
tree and the production structurer with cases `0..6` plus its out-of-table
default, no indirect placeholder, and 34/34 deterministic executions. The
production recognizer requires SSA-transitive dependence on an unsigned
comparison, preventing arbitrary two-way conditionals from being promoted as
dense switch guards. All 20 fixture-204 cells and the 55 focused production
structure tests pass. The complete 838-lane baseline-aware comparison reports
34 older unrecorded improvements and one `rust_slice_get` regression which an
isolated `55ab688b` A/B proves predates this increment; no regression is
attributable to this change. This closes the production gap
for that cell, not WP5's shared evidence-object or architecture-wide exit
criteria. Its former unaccounted-edge diagnostic is gone, but structure
accounting is now clean as well. Shared return tails carry explicit borrowed
provenance: predecessor-specific SSA renderings may be cloned for readable C,
while the underlying machine block has exactly one structural owner. A full
838-lane rerun preserves the same 34 older improvements and sole pre-existing
`rust_slice_get` baseline mismatch, with no regression attributable to the
ownership repair.

The ABI/call-value work formerly recorded here as uncommitted is landed: CFG-
aware parameter evidence, exceptional and aggregate call results, non-C source
to machine-ABI boundaries, and float-valued call rendering all have bounded
fixture evidence in the review plan. The bounded SysV AMD64 homogeneous-float
slice is also closed: all non-structural rows in fixture 197 pass across
GCC/Clang O0/O2 after exact SSE-pair return materialization, contract-proved
tail forwarding, and the required legacy packed-XMM semantics. This does not
complete WP6's general constraint solver or establish other architecture,
vector, or language-ABI support. The first optimized-complex follow-on now
models all four legacy packed binary32 arithmetic mnemonics as typed XMM lanes.
The next bounded call-boundary slice is landed too: `__mulsc3` and `__muldc3`
receive four exact source-ordered SysV SSE arguments, while the returned value
is represented according to its real carrier. `__mulsc3` packs two binary32
lanes into `xmm0`; only `__muldc3` uses the `xmm0:xmm1` pair. The GCC and Clang
O2 float and double complex-multiply cells all move to pass, four improvements
with no scoped adjacent regression. General exact call-boundary facts and
exceptional-input coverage remain WP6 work; this two-helper catalogued contract
does not establish other ABIs, arbitrary aggregate calls, or vector support.
WP8 has
authoritative DWARF/PDB/analyst
declaration slices and now owns their total priority order in the program
environment; authoritative tagged PDB pointers also retain their nominal type
instead of degrading to `void *`. The same real PDB fixture no longer turns
clang-cl's overwritten Win64 home-slot reservation into an undefined C local;
the rule is width- and effect-guarded and has clean-master A/B evidence. An
explicit CLI analyst mode can now place deterministic declaration/recovery
conflicts beside affected signatures while the default scored text stays
unchanged; the mode bypasses the text cache because drained provenance cannot
be reconstructed from a cached artifact. DWARF variadic markers now survive
into GCC and Clang rendered signatures across O0/O2; generic stripped-binary
variadic inference and complete SysV `va_start` lowering remain open. WP9 has
target-owned ARM32 register views plus standing
decoded/effect capability censuses and several silent-writer repairs. WP2,
WP3, WP6, and WP7B remain open architectural work. No current-tip release gate
is claimed green; isolated overlay results in the review record retain their
named scope and must not be read as cross-architecture or full-plan
completion.

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
| R0 measurement/inventory | generated inventory cannot reproduce itself; JSON and Markdown snapshots disagree | [inventory-authority plan](test-inventory-authority.md) | recover committed canonical records, schema v2, atomic generation, `--check` |
| R1 missing-body accounting | 217 rows span identity, dataset, and ARM lift causes rather than one generic decompiler failure | [failure taxonomy](../../history/design/campaigns/decbench-full-failure-taxonomy-2026-08-31.md), [remediation plan](decbench-failure-remediation.md) | F1a, F1b core and F2a landed; next F1c/F1d dataset validation |
| R2 large functions | compile and structural perfection collapse as recovered output grows | [large-function plan](large-functions.md) | smallest source-grounded size/shape ladder with phase telemetry |
| R3 optimized structure | readability covers GCC/Clang O0/O2, but closure/effects remain lane-independent | [optimized structural-quality plan](optimized-structural-quality.md) | lane-key closure/effects, then add optimized shape predicates |
| R4 PE/PDB/Mach-O | many PE samples but no coherent source/PDB matrix; one Mach-O sample only | [format-parity plan](pe-pdb-macho-parity.md) | four-cell clang-cl PE32/PE32+ identity lane |
| R5 hostile/production shapes | existing realistic corpus mainly proves x86-64 ELF discovery, not body semantics | [real-world asset plan](real-world-malware-assets.md) | add body accounting and a semantic subset to the existing corpus |
| R6 performance/determinism | a three-reference baseline exists, but incomplete/incomparable evidence can pass | [performance/determinism plan](performance-determinism-ratchet.md) | RED tests for fail-open states, then provenance/RSS/completeness |
| R7 breadth/thin modules | valuable lower-priority gaps remain after proven body/format/quality risks | [fuzzing](../test-estate/03-fuzzing.md), [thin modules](../test-estate/05-thin-modules.md), [matrix extension](../test-estate/07-matrix-extension.md) | finish current thin-module lanes without displacing R0/R1/R2 gates |
| R8 test automation/coverage | the default suite is 65% decompiler-IR unit tests over synthetic bytes; 19 `disasm` tests, 4 `decompile` tests (all profiler), and 20 toolchain gates that pass silently when the compiler is absent | [this section](#r8--test-automation-and-coverage), [CI gap](../test-estate/10-ci-environment-gap.md) | make silent toolchain skips visible, then bind `cargo test` to the fixture corpus |

The product-facing ordering and non-goals remain in the
[real-binary roadmap](real-binary-decompiler.md).

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

Current state: taxonomy complete; F1a, the F1b product core, and F2a are
implemented (`0d6b30d1`, `0031c3ee`). F1c, F1d, scoring-contract work, and a
fresh pinned full run remain open.

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

Current state: hermetic PE32/PE32+ identity, PE entry/TLS/import, PDB
type/layout, and Mach-O x86-64/ARM64 thin lanes all exist (`8c0a89f6`,
`99113bc8`, `c7200d2d`, `ba2fe5c2`). Mach-O fat slices, the fetched-fixture
zero-input guard, and full semantic parity are open.

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

Current state: an instruction baseline and determinism tests exist and the
gate fails closed and is scheduled (`4f4f88e3`). Provenance, RSS, output and
body-completeness evidence, and the unified release artifact remain open.

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

### R8 status

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
* records the outcome in [`test-estate/EXECUTION.md`](../test-estate/EXECUTION.md)
  — including evidence that changed the next decision, and any finding that
  falsifies a premise of one of these plans.

This planning work itself remains documentation-only and internal.

## DecBench evaluation (on demand only)

**Read this section only when refreshing published metrics.** It is not a work
queue, and none of its open boxes appears in the workstream map, the milestone
map, or the bounded increments above. A box here going unticked for a year is
not a defect.

The project's correctness ground truth is `tests/decompiler_fixtures/`, which
compiles the corpus, executes the recompiled decompiler output, and diffs it
against the original. GED / TypeMatch / ByteMatch measure something else, on a
harness that costs tens of minutes per run and reports its own resource
contention as cell failures. Reach for this section when refreshing the paper
or preparing a submission artifact — never to decide what to work on next.

**The boundary.** The running gate is `scripts/decbench-local-gate.sh` lanes
1–3, which are our own fixture corpus. Lanes 4–5 are this section and require
`--decbench` or `GLAURUNG_RUN_DECBENCH=1`. In pytest the same boundary is the
`decbench` marker, which `pytest.ini` deselects by default. Separately and
absolutely: the DecBench upstream contribution rule in `CLAUDE.md` stands —
no agent authors or posts a DecBench issue, comment, or pull request. Stop at
the boundary and hand the evidence to a human.

**Audit trail (closed).** Three submissions were merged upstream and are the
reason the backend is now part of DecBench rather than a pending submission:
PR #61 (empty-disassembly ByteMatch correctness fix) as `af02672db6dd`, PR #62
(reproducibility/efficiency follow-up) as `3db5d557a6ae`, and PR #56 (the
deterministic Glaurung backend, pinned to its evaluated commit) as
`08f891581e6b`. The `-marm` A32 lane and the GCC-15 x86-64 control were added
and are ratcheted in `arch_baseline.json`.

**Open, if and only if a metric refresh is being prepared.**

- [ ] Obtain a fresh official-evaluator score. With #56 merged this is a
  question of running the current upstream evaluator against a pinned image,
  not of getting a backend accepted. The last artifact pins `fb4ee6ba`; decide
  deliberately whether the next score describes that commit or a fresh package.
- [ ] Score the exact current artifact and compute union from exact row-level
  joins, never adjusted aggregate arithmetic.
- [ ] Keep raw outputs, package hashes, evaluator revision, metric schema,
  compiler versions, target triples, and exact function joins in every ledger.
- [ ] Keep public publication separate from local evaluation, and require
  explicit authorization for any result or site change.
- [ ] Explain the historical `linkedlist:clang:O0` ByteMatch drop from 0.47 to
  0.10. GED was already 0.0, so "structurally closer" is not an explanation.
- [ ] Diagnose the AArch64-only failures at the first wrong semantic stage.
- [ ] Preserve the ILP32-versus-ARM distinction, the missing-lane caveat, and
  the control-compiler caveat in the evidence register.

**Acceptance policy for any score-campaign change.** Reproduce on a real binary
and name the first wrong semantic stage; add a failing test before implementing;
advance the intended owner rather than add a duplicate heuristic path; include
near-miss controls; rerun affected cells plus every current perfect and canary
cell; report coverage, mean, median, perfect count, union and regressions;
compare exact function identities; use fresh no-cache evaluation where cache
identity is in doubt; and delete superseded workaround code when the
foundational owner replaces it.

Note on the historical metric-attack order (TypeMatch/GED first, textual
normalization last): it is recorded in the archived roadmap as the explanation
of how the campaign chose work when the metrics were the scoreboard. It no
longer selects work — execution ground truth does — and the changes that
actually moved fixture cells were missing capabilities it does not mention.

## Package validation

The package is structurally complete when:

* R0–R8 and M1–M8 each map to an authority and completion evidence;
* the failure counts reconcile to 217 plus the separate thirteen E1 rows;
* local Markdown links resolve;
* no plan claims an unimplemented selector, baseline, runner, or matrix exists;
* stale older-plan claims are corrected where discovered; and
* concurrent implementation work remains untouched.

## Function identity and signature libraries

A separate live list, because it is judged by retrieval and coverage
measurements rather than by fixture cells:
[`function-identity-and-signatures.md`](function-identity-and-signatures.md)
collects every open item across the identity ladder and the signature
program, each with its precondition and the measurement that deferred it.
