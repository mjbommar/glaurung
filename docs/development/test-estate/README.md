# Test estate plan

A phased plan to improve and extend the tests and assets, written against the
inventory at `docs/test-inventory/` (986 entries, 6,282 test functions,
commit `2ce51f9d`). Every number in these files was counted, not estimated;
where a claim depends on a tool being present, the tool's version was checked
on this machine and is recorded in the phase file.

## The frame

The estate's problem is **skew and reachability, not volume**:

* 62% of the Rust unit suite is in `src/ir/` (1,847 tests); `src/demangle/`
  has 1, `src/similarity/` 2, `src/flirt/` 4, `src/target/` 1.
* 89 of 986 inventory entries are reachable by **nothing** — including 28
  tests in `tests/triage/` that have never compiled and all five fuzz targets.
* No CI workflow runs `cargo test` or the general Python suite. 6 of 445
  Python test files execute in CI.
* Of six behavioural ratchets, the only one in the default suite measures
  code size.
* The components that consume hostile bytes deepest — disassembler, lifter,
  CFG discovery, structurer — have never seen a fuzzer.

The consequence for sequencing: **adding tests before fixing reachability
grows the pile of 89.** Phase 1 is not optional groundwork; it is the thing
that makes every later phase land somewhere that stays alive.

## Phases

| # | file | what | depends on |
|---|------|------|------------|
| 1 | [01-reachability.md](01-reachability.md) | Wire the dead tests, invert the CI split, make unreachability impossible to reintroduce | — |
| 2 | [02-canary-determinism.md](02-canary-determinism.md) | A behavioural canary in the default suite; a determinism gate | 1 |
| 3 | [03-fuzzing.md](03-fuzzing.md) | Fuzz the disasm/lift/structure path, not just triage | 1 |
| 4 | [04-pe-macho.md](04-pe-macho.md) | PE+PDB fixtures via clang-cl on Linux; Mach-O via zig | 1 |
| 5 | [05-thin-modules.md](05-thin-modules.md) | Corpus-driven tests for demangle, similarity, flirt, target | — |
| 6 | [06-perf-ratchet.md](06-perf-ratchet.md) | A performance baseline something actually compares against | — |
| 7 | [07-matrix-extension.md](07-matrix-extension.md) | Wire Go; add stripped-O0, LTO, musl lanes; structural baseline at O2 | 1 |
| 8 | [08-dwarf-oracle.md](08-dwarf-oracle.md) | Ground truth at scale from DWARF twins | 2, 7 |
| 9 | [09-asset-hygiene.md](09-asset-hygiene.md) | Delete the broken, dedupe the doubled, retire the dead | — |

Phases 3, 4, 5, 6 and 9 are independent of each other and can run in
parallel once 1 has landed. 7 needs 1's baseline-refresh discipline; 8 is
last because it consumes 7's lanes and 2's canary harness.

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
   not on an explicit, reasoned allowlist.
2. `uv run pytest python/tests/` on a fresh checkout exercises the decompiler
   end-to-end (canary lane) and fails if output is nondeterministic.
3. A CI workflow runs `cargo test --features python-ext` and the Python suite.
4. `cargo fuzz run` has targets for disasm, CFG discovery, lifting and
   structuring, with a committed seed corpus, and CI runs them nightly.
5. PE and Mach-O each have at least one fixture lane with reachable tests.
6. demangle/similarity/flirt each have a corpus-driven suite (>100 cases).
7. A perf regression >25% on the reference set turns a gate red.
