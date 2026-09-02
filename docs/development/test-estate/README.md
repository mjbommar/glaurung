# Test estate plan

> **Kind:** plan · **Status:** proposed

A phased plan to improve and extend the tests and assets, written against the
inventory at `docs/test-inventory/` (986 entries, 6,282 test functions,
commit `2ce51f9d`). Every number in these files was counted, not estimated;
where a claim depends on a tool being present, the tool's version was checked
on this machine and is recorded in the phase file.

**[`EXECUTION.md`](EXECUTION.md) is the live status.** It carries the commit
for every landed item and the current state of everything still open; the
phase files below state the *design*, and each one's status is in the table.
A phase file read on its own will look more open than it is.

The product-facing ordering layered on top of this estate-hygiene work is
[`development/roadmap/`](../roadmap/README.md).

## The frame

The measurement that opened this plan, at commit `2ce51f9d`. It is stated in
the past tense because most of it has since been acted on; it is kept because
it is the argument for the sequencing, and the sequencing still holds.

The estate's problem was **skew and reachability, not volume**:

* 62% of the Rust unit suite sat in `src/ir/` (1,847 tests), against 1 test in
  `src/demangle/`, 2 in `src/similarity/`, 4 in `src/flirt/`, 1 in
  `src/target/`. Phase 5 closed the four thin modules; the skew itself is now
  tracked as R8 in the roadmap.
* 89 of 986 inventory entries were reachable by **nothing** — including 28
  tests in `tests/triage/` that had never compiled and all five fuzz targets.
  Phase 1 and the fuzz work took that to 74 classified entries, of which 42
  are feature-gated and accounted for.
* No CI workflow ran `cargo test` or the general Python suite; 6 of 445 Python
  test files executed in CI. Both are fixed (`f6ade219`, and the facet split
  in phase 11).
* Of six behavioural ratchets, the only one in the default suite measured code
  size.
* The components that consume hostile bytes deepest — disassembler, lifter,
  CFG discovery, structurer — had never seen a fuzzer. Three deeper targets
  landed at `f57014dc`.

The consequence for sequencing: **adding tests before fixing reachability
grows the pile of 89.** Phase 1 was not optional groundwork; it is the thing
that made every later phase land somewhere that stays alive.

## Phases

Status is from [`EXECUTION.md`](EXECUTION.md), checked 2026-09-02. **Archived**
means the file moved to `docs/history/` because its work landed or was absorbed
elsewhere; the link points there.

| # | file | status | what | depends on |
|---|------|--------|------|------------|
| 1 | [01-reachability.md](../../history/development/test-estate/01-reachability.md) | **done**, archived | Wire the dead tests, invert the CI split, make unreachability impossible to reintroduce | — |
| 2 | [02-canary-determinism.md](../../history/development/test-estate/02-canary-determinism.md) | **done**, archived (`b4d23221`) | A behavioural canary in the default suite; a determinism gate | 1 |
| 3 | [03-fuzzing.md](03-fuzzing.md) | **partial** — 3.1–3.4 done, 3.5 open | Fuzz the disasm/lift/structure path, not just triage | 1 |
| 4 | [04-pe-macho.md](../../history/development/test-estate/04-pe-macho.md) | **merged**, archived → [pe-pdb-macho-parity.md](../roadmap/pe-pdb-macho-parity.md) | PE+PDB fixtures via clang-cl on Linux; Mach-O via zig | 1 |
| 5 | [05-thin-modules.md](05-thin-modules.md) | **done**, one target missed (demangle corpus 2,115 < 5,000) | Corpus-driven tests for demangle, similarity, flirt, target | — |
| 6 | [06-perf-ratchet.md](../../history/development/test-estate/06-perf-ratchet.md) | **merged**, archived → [performance-determinism-ratchet.md](../roadmap/performance-determinism-ratchet.md) | A performance baseline something actually compares against | — |
| 7 | [07-matrix-extension.md](07-matrix-extension.md) | **partial** — 7.5 done, 7.1 opt-in, 7.2–7.4 open | Wire Go; add stripped-O0, LTO, musl lanes; structural baseline at O2 | 1 |
| 8 | [08-dwarf-oracle.md](08-dwarf-oracle.md) | **open** — nothing built | Ground truth at scale from DWARF twins | 2, 7 |
| 9 | [09-asset-hygiene.md](../../history/development/test-estate/09-asset-hygiene.md) | **done**, archived (`937425d0`) | Delete the broken, dedupe the doubled, retire the dead | — |
| 10 | [10-ci-environment-gap.md](10-ci-environment-gap.md) | **open** — a live investigation | 25 CI-only failures the first completed run exposed: tests that crash rather than skip on a machine without every toolchain | 1 |
| 11 | [11-tiers-and-facets.md](11-tiers-and-facets.md) | **done**, three follow-ups open | Tier by what a test NEEDS, not its subject: seven facets applied as markers; `core` (no LFS) and `extended` both required per push; wheel matrix gated on tags; fixture cache measured and deferred | 1 |

Phases 3, 5 and 9 were independent of each other and ran in parallel once 1
had landed; 4 and 6 were absorbed into the roadmap plans named above. 7 needs
1's baseline-refresh discipline; 8 is last because it consumes 7's lanes and
2's canary harness.

## Related

**[`../roadmap/README.md`](../roadmap/README.md)** — the live plan set,
mapping R0–R8 and M1–M8 to evidence, detailed authorities, dependencies, first
increments, and completion proof. Each plan below is one of its authorities.

* [`real-binary-decompiler.md`](../roadmap/real-binary-decompiler.md) — the
  product-facing order after the complete 94,575-function run. It promotes
  missing-body identity, large-function coverage, optimized structural
  quality, and PE/PDB ahead of lower-signal breadth work while retaining this
  plan's reachability and fixture discipline, and it carries the still-open
  items of the archived 2026-08-13 roadmap.
* [`decbench-failure-remediation.md`](../roadmap/decbench-failure-remediation.md)
  — the TDD-level implementation plan for the complete failure taxonomy,
  including ownership boundaries between product, adapter, dataset, and
  evaluator.
* [`test-inventory-authority.md`](../roadmap/test-inventory-authority.md) —
  makes the inventory renewable: committed canonical inputs, a versioned
  schema, atomic generated views, `--check`, explicit runners, and roadmap
  queries.
* [`real-world-malware-assets.md`](../roadmap/real-world-malware-assets.md) —
  audits the existing realistic, packed, adversarial, and Windows assets and
  turns them into a source-grounded hostile-shape program with explicit body,
  structure, compile, execution, resource, and refusal oracles.
* [`performance-determinism-ratchet.md`](../roadmap/performance-determinism-ratchet.md)
  — the successor to phase 6. Fail-closed measurement states, provenance,
  completeness/RSS ratchets, a reference ladder, and retained release evidence.
* [`optimized-structural-quality.md`](../roadmap/optimized-structural-quality.md)
  — expands the GCC-O0 structural baseline into separate GCC/Clang O0/O2
  populations with optimized shape predicates, readability distributions, and
  semantic/performance safety ratchets.
* [`pe-pdb-macho-parity.md`](../roadmap/pe-pdb-macho-parity.md) — the
  successor to phase 4. Hermetic PE32/PE32+, PDB, Mach-O x86-64/ARM64, fixup,
  and universal-slice contracts.
* [`large-functions.md`](../roadmap/large-functions.md) — the size/shape
  ladder and phase telemetry for recovered output that grows.

[`../decompiler-parity-backlog.md`](../decompiler-parity-backlog.md) — a
three-way comparison of glaurung against angr 9.3.3 and Ghidra 12.1.3 on our
own samples, and the 10-item build/fix backlog it produced. Several items
there (structural baseline at O2, the differential harness) are phases of this
plan; the parity doc is the evidence for why they matter.

## Rules that apply to every phase

* **Every new test names its runner.** A test lands together with the entry
  in whatever runs it — a `mod` declaration, a pytest collection path, a CI
  step, a gate lane. "It exists" is not a deliverable; Phase 1's ratchet
  enforces this mechanically where it can.
* **Every new fixture refreshes the side files.** The six known ones:
  `baseline.json`, `structural_baseline.json`, `arch_baseline.json`,
  `defuse_baseline.json`, plus `test_large_module_review.py` and
  `test_stranded_doc_comments.py` registries where a split is involved.
* **Real binaries only.** No mocked analysis output, per `CLAUDE.md`. Where a
  corpus is generated, the generator and its oracle are committed alongside.
* **DecBench stays held out.** Nothing in this plan reads
  `~/.cache/glaurung/decbench-full/` or tunes against `tests/decbench_corpus/`.
* **Measured additions.** A new matrix lane multiplies runtime; each phase
  states the cell-count cost before adding one.

## Definition of done for the plan as a whole

1. `docs/test-inventory/` regenerated shows **0 unreachable** entries that are
   not on an explicit, reasoned allowlist. *(Open — 74 entries are classified
   but the allowlist is not mechanical, and the generator's inputs are not
   committed; that is R0 in the roadmap.)*
2. `uv run pytest python/tests/` on a fresh checkout exercises the decompiler
   end-to-end (canary lane) and fails if output is nondeterministic. *(Met,
   `b4d23221`.)*
3. A CI workflow runs `cargo test --features python-ext` and the Python suite.
   *(Met, `f6ade219`; the local/CI denominator gap it exposed is phase 10.)*
4. `cargo fuzz run` has targets for disasm, CFG discovery, lifting and
   structuring, with a committed seed corpus, and CI runs them nightly.
   *(Met, `f57014dc` and `665fe25d`.)*
5. PE and Mach-O each have at least one fixture lane with reachable tests.
   *(Met, `8c0a89f6` and `ba2fe5c2`; semantic parity continues under R4.)*
6. demangle/similarity/flirt each have a corpus-driven suite (>100 cases).
   *(Met, `4c0f2ffe` and `36d0e0f3`; demangle fell short of its own 5,000-pair
   bar at 2,115.)*
7. A perf regression >25% on the reference set turns a gate red. *(Met and
   proved by injection, `a938d897`; the gate now also fails closed on
   non-evidence, `4f4f88e3`.)*
