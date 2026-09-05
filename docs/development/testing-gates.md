# Testing gates

> **Kind:** guide · **Status:** maintained

Which gate protects what, which baseline it reads, and whether CI runs it.
`CLAUDE.md` carries the short version of this table; this file is the long
version, with the refresh command for every committed baseline.

Run everything from the repository root with `TMPDIR` exported:

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
mkdir -p "$TMPDIR"
```

## The nine gates

| # | Gate | Command | What it protects | Baseline / input it reads | In CI? |
|---|---|---|---|---|---|
| 1 | Rust tests, bindings included | `cargo test --features python-ext` | `src/` plus `src/python_bindings/` (the real decompiler entry point) and `src/exec/`. A bare `cargo test` does not compile the bindings tree at all. | — | yes: `test-suite.yml`, job `rust` (also sets `GLAURUNG_REQUIRE_TOOLCHAINS=1` so a missing fixture compiler fails instead of skipping) |
| 2 | Symbolic engine tests | `cargo test --features symbolic` | `src/symbolic/` — 26 files that neither `cargo test` nor `--features python-ext` compiles | — | yes: `test-suite.yml`, job `symbolic`, which additionally fails if fewer than 50 `symbolic::` tests are listed |
| 3 | Python suite | `uv run pytest python/tests/` | everything Python-visible, including the structural/hygiene gates below | `tests/test_facets.json` (marker assignment at collection) | yes, tiered: `test-suite.yml` jobs `python-core` (`-m "core and not decbench"`) and `python-extended` (`-m "not core and not fixtures and not decbench"`), both `-n auto` |
| 4 | Lint and format | `uvx ruff format --check python/` and `uvx ruff check python/` | Python style across `python/` | `[tool.ruff]` in `pyproject.toml` | yes: `test-suite.yml`, job `lint` |
| 5 | Types | `uvx ty check python/` | Python type errors, including a lying `.pyi` | `python/glaurung/_native/*.pyi` (generated) | **no** — developer-only; no workflow runs `ty` |
| 6 | Feature build gate | `scripts/feature-build-gate.sh` | 12 `cargo check --all-targets` lanes: every feature configuration, including the four solver backends and the separate `fuzz/` crate | — | yes: `feature-build-gate.yml`, job `feature-matrix` (also runs `cargo fmt --all -- --check`) |
| 7 | Fixture matrix + structural lane | `uv run pytest -m slow python/tests/test_decompiler_fixture_matrix.py python/tests/test_decompiler_fixture_structural.py` | execution-differential semantic fidelity on x86-64, and the textual/structural shape of the output | `tests/decompiler_fixtures/baseline.json`, `tests/decompiler_fixtures/structural_baseline.json` | yes: `decompiler-fixtures.yml`, job `matrix`, on every push to `master` and on PRs that touch decompiler paths |
| 8 | Cross-architecture round trip | `uv run python tools/dectest.py @o0 @o2 --arch i386 --arch armv7 --arch aarch64 --arch x86_64_gcc15`, or `uv run pytest python/tests/test_decompiler_arch_roundtrip.py` | the same execution differential for i386, ARMv7, AArch64, and a second x86-64 toolchain | `tests/decompiler_fixtures/arch_baseline.json` | **no** — run it by hand |
| 9 | Def-use census | `uv run pytest python/tests/test_decompiler_defuse_census.py -q` | definition-before-use violations per lane; moves whenever a recovered signature changes | `tests/decompiler_fixtures/defuse_baseline.json` | **no** — run it by hand |
| 10 | Control-skeleton census | `uv run pytest python/tests/test_fixture_structure_census.py -q` | the tree edit distance between each source function's control skeleton and the decompiled one's, per `fixture:cc:opt:function` over the C corpus. The only gate that compares recovered STRUCTURE against the source: the execution differential is blind to it (goto soup passes every fixture) and the structural lane's `switch`/`goto`/`break` counts are absolute, with no source to be right about. Publishes the null-decompiler floor beside every number | `tests/decompiler_fixtures/structure_baseline.json` | **no** — run it by hand |
| 11 | S5 equivalence scorecard | `( ulimit -v 12000000; cargo test --release --features symbolic --lib -- --test-threads=1 csource::equiv )` | `src/csource/equiv/` — bounded equivalence between two lowered C functions, scored over 1,810 labelled mutants from `tools/metric_mutation.py`'s own catalogue. The only oracle here that is not a proxy: it separates `demorgan`, `if-else-swap` and `duplicate-tail`, which every structural metric scores as damage. Prints sensitivity, specificity and the `unknown` breakdown; asserts a **named** allow-list (`VERIFIED_EQUIVALENT`) rather than a percentage, because a percentage floor passes with a false `Equivalent` inside it — which is how one was nearly lost | `tests/csource_equiv/mutants.jsonl`, **generated and gitignored**: run `uv run python tools/equiv_mutants.py` first or the test records a missing fixture and skips | **no** — run it by hand; the symbolic lane in CI provisions no solver |

Gates 8, 9 and 10 are the ones the iteration loop forgets, because
`tools/dectest.py` is not pytest and the census lanes are `slow`-marked. See
[traps.md](traps.md#a-signature-change-moves-the-def-use-census-and-no-ci-job-will-tell-you)
and
[traps.md](traps.md#o0-and-o2-are-host-lanes-only).

### Scheduled and opt-in lanes

| Lane | Command | Notes |
|---|---|---|
| Wheel builds | — | `CI.yml` builds linux / musllinux / windows / macos wheels and an sdist on push and PR; a tagged push releases |
| Fuzzing | `cargo fuzz run <target> -- -max_total_time=120`, seeded by `uv run python fuzz/seed_corpus.py` | `fuzz-nightly.yml`, 04:17 UTC, one job per target across the 8 targets |
| Perf gate | `uv run python tools/perf_gate.py --json` | `perf-nightly.yml`, 05:37 UTC. Exit 3 means *this run is not evidence* (hosted runners block instruction counting) and is reported as a warning, never as a pass; any other nonzero exit fails the job. `python/tests/test_perf_gate_fails_closed.py` pins that behaviour |
| Windows corpus drift | — | `windows-corpus-guard.yml` on PR and weekly |
| Windows/Ghidra parity refresh | — | `windows-ghidra-parity-refresh.yml` |
| DecBench evaluation | `scripts/decbench-local-gate.sh --decbench` | **Opt-in only.** Lanes 4–5 spawn a Joern JVM per cell, take tens of minutes, and report their own resource contention as cell failures. `pytest.ini` deselects `-m decbench` by default. Do not run without being asked |

### The heavy local gate

`scripts/decbench-local-gate.sh` runs, in order: `cargo test`; the 12-lane
feature matrix; the not-slow, not-decbench Python lanes; the fixture matrix;
and the cross-architecture round trip. Those are lanes 1–3 and are the ones
that can actually prove a decompiler change sound, because they execute
recompiled output and diff it against the original. `--decbench` adds the two
evaluation lanes. When they are skipped the script's final line says so — an
absent metric lane must never read as a green metric lane.

For iteration, use `tools/dectest.py` instead: seconds rather than tens of
minutes.

```bash
uv run python tools/dectest.py --list-sets                       # named slices
uv run python tools/dectest.py @smoke                            # six canaries, ~8s
uv run python tools/dectest.py 13_loop_early_exit:gcc:O0:bisect --show
```

`tests/decompiler_fixtures/sets.toml` defines the sets; `@smoke` is capped at
six lanes and `python/tests/test_dectest_selection.py` fails when a set names a
fixture or function that no longer exists.

## Every committed baseline and how to refresh it

Regenerate deliberately. A ratcheting baseline fails on *any* change, an
improvement included, so refreshing one is an assertion that the movement was
independently confirmed — never a way to make a red gate green. Run
`uv run python tools/build_guard.py` first: a baseline written against a stale
`.so` records the old behaviour under the new commit and nothing downstream can
tell.

| Baseline | Records | Refresh with | Gate |
|---|---|---|---|
| `tests/decompiler_fixtures/baseline.json` | per-function pass/fail for each `fixture:cc:opt` host lane, plus the toolchain fingerprint | `uv run python tools/fixture_harness.py --write-baseline` | `test_decompiler_fixture_matrix.py` |
| `tests/decompiler_fixtures/arch_baseline.json` | the same verdicts keyed `fixture:arch:opt` over six architectures × O0/O2 | `uv run python tools/arch_roundtrip.py --write-baseline` (`--check` to verify) | `test_decompiler_arch_roundtrip.py` |
| `tests/decompiler_fixtures/structural_baseline.json` | per-function, per-render-style structural facts: closure, effects, gaps, placeholder, readability, verify | `uv run python tools/gen_structural_baseline.py` | `test_decompiler_fixture_structural.py` |
| `tests/decompiler_fixtures/defuse_baseline.json` | definition-before-use violation counts per lane, with accepted regressions recorded inline | `uv run python tools/gen_defuse_baseline.py` (a rise must be named through `tools/defuse_ratchet.py`) | `test_decompiler_defuse_census.py` |
| `tests/decompiler_fixtures/structure_baseline.json` | per-`fixture:cc:opt:function` control-skeleton edit distance from the source, with the null-decompiler distance beside it, plus per-lane, per-size-band and per-construct rollups. Abstentions above `MAX_SKELETON_NODES` carry no distance | `uv run python tools/fixture_structure_census.py --write` (`--report` prints the stratified table; a regression needs `--allow-regressions`) | `test_fixture_structure_census.py` |
| `tests/decompiler_fixtures/stripped_divergences.json` | debug-versus-stripped divergences per function | `uv run python tools/stripped_differential.py --write-divergences` | `test_decompiler_stripped_lane.py` |
| `tests/open_defects/known_failures.json` | every decompiler failure the corpus can demonstrate against DWARF ground truth, as strict xfails | `uv run python tools/gen_known_failures.py` | `test_known_decompiler_failures.py` (`-m fixtures`; run in `decompiler-fixtures.yml` after the matrix, so a fix goes red in CI) |
| `tests/decompiler_output_canaries/baseline.json` | per-function undefined reads and which pass first introduced each | `uv run python tools/decompiler_output_canaries.py` (`--check`) | `test_decompiler_output_canaries.py` |
| `tests/decompiler_profile/baseline-*.json` | cold/warm decompile timings, max RSS, per-stage durations, output hash | `uv run python tools/decompiler_profile.py --output <path>` | `test_decompiler_profile.py` |
| `bench/perf_baseline.json` | instruction counts over three large sample binaries | `uv run python tools/perf_gate.py --write-baseline` | `test_perf_gate_fails_closed.py`; `perf-nightly.yml` |
| `tools/fitness_baseline.json` | file-count, median, mean and largest-file LOC measures, plus accepted regressions | `uv run python tools/fitness_report.py --write-baseline` (`--check-ratchet` to check) | `test_fitness_report.py`, `test_large_module_review.py` |
| `tests/test_census_baseline.json` | declared `#[test]` count per Rust module, and how many are never executed | `uv run python tools/gen_test_census.py` | `test_test_census.py` |
| `tests/test_facets.json` | every Python test file classified by what it needs; `conftest.py` turns these into markers | `uv run python tools/gen_test_facets.py` | `test_test_facets.py` |
| `tests/sample_duplication_baseline.json` | byte-identical file groups under `samples/` (ratcheted, not deduplicated) | `uv run python tools/gen_sample_duplication_baseline.py` | `test_sample_corpus_duplication.py` |
| `tests/realistic_corpus/discovery_baseline.json` | function-discovery recall on stripped, packed and lying binaries, with the building toolchain's versions | `uv run python tools/gen_realistic_baseline.py` (`--check`) | `test_realistic_corpus.py` (corpus built by `tools/realistic_corpus.py`) |
| `tests/decbench_scoreboard/baseline-ledger.json` | DecBench metrics, dimensions, head-to-head and union rows | `uv run python tools/decbench_score_ledger.py` (`--check-baseline`) | `test_decbench_score_ledger.py` — fast, needs no fork |
| `tests/decbench_corpus/baseline.json` | per-`project:cc:opt` GED, byte match and type match | `tools/decbench_matrix.py` | DecBench lane; **opt-in only** |

Generated Python stubs are not a baseline but behave like one:
`uv run python tools/gen_native_stub.py` rewrites `python/glaurung/_native/*.pyi`,
`--check` exits 1 when they are stale, and `test_native_stub_current.py`
regenerates and diffs.

## What a module split touches

Six side files, not four. Splitting a module and refreshing only the fixture
baselines leaves three path-keyed registries pointing at a file that no longer
exists.

1. `tests/decompiler_fixtures/baseline.json`
2. `tests/decompiler_fixtures/structural_baseline.json`
3. `tests/decompiler_fixtures/arch_baseline.json`
4. `tests/decompiler_fixtures/defuse_baseline.json`
5. `python/tests/test_large_module_review.py` — `REVIEWED_LARGE_MODULES`. A file
   that drops under 1,000 LOC must have its entry **deleted**, or
   `test_no_review_entry_outlives_the_file_it_reviewed` fails. A review is also
   a licence that expires: a reviewed file drifting more than 150 LOC past its
   last blessed size fails too.
6. `python/tests/test_stranded_doc_comments.py` — `REVIEWED_DOC_SUMMARIES`,
   keyed by file path, and `python/tests/test_src_dependency_boundaries.py` —
   an env-var allowlist with the same shape. Moving a registered doc summary or
   an `os.environ` read into a new module orphans its key silently.

Adding a fixture is the same list: a new numbered fixture under
`tests/decompiler_fixtures/src/` plus its `manifest.py` contract needs all four
baselines refreshed, and the def-use census is the one that hides.

## Adding a CLI command drifts a tutorial fixture

`docs/tutorial/_fixtures/01-install/help-head.out` records the first three
lines of `glaurung --help`, which include the full subcommand list. Any new
entry in `python/glaurung/cli/main.py`'s registry drifts it and
`test_verify_tutorial.py::test_check_mode_does_not_rewrite_install_fixtures`
fails. Refresh with:

```bash
uv run python scripts/verify_tutorial.py --chapter 01-install --capture
```

Then read the diff: it should be the command list and nothing else. Never
hand-edit a fixture.

## Code quality, composition, and file-size program

A long-running decomposition effort, measured rather than remembered.
`tools/fitness_report.py` computes nine LOC measures over product code
(`#[cfg(test)]` excluded) and compares them with `tools/fitness_baseline.json`;
`python/tests/test_fitness_report.py` and
`python/tests/test_large_module_review.py` are the gates.

```bash
uv run python tools/fitness_report.py                # report
uv run python tools/fitness_report.py --check-ratchet # no-regression check
uv run python tools/fitness_report.py --write-baseline
```

Measured at `13faa6f7` (2026-09-02) with the command above:

```
Product code: 455 files, 185318 LOC (src/ir: 181 files, 90302 LOC)

measure                               current       target  status
------------------------------------------------------------------
Product-code mean                       407.3          450  OK
Product-code median                       301          250  over target
Product files above 1,000 LOC              23           35  OK
Product files above 2,000 LOC               3            5  OK
Product LOC in files above 1,000         18.0           25  OK
src/ir median                             404          500  OK
src/ir files above 1,000 LOC               13            5  over target
Largest product file                     2268         1000  over target
Product LOC in files above 1,000        33355        42000  OK
```

The three largest product files at that commit are `ir/lift_x86.rs` (2,268),
`ir/lift_arm64.rs` (2,059) and `ir/ast/dec_render.rs` (2,033).

Four things this program has established, and which govern any further split:

- **A split counts only if it creates a narrower API and one reason to change.**
  Arbitrary fragmentation is not architecture, and a split that leaves the same
  responsibilities coupled by private mutation is a stop condition.
- **Count measures move the wrong way while a decomposition is working.**
  Dividing one large file into two necessarily adds a file to every "above N"
  bucket and moves both medians. `Largest product file` is the measure that
  moves in the direction the work moves; judge the program by it and treat the
  counts as secondary.
- **A "no further split" verdict is a licence that expires.** It is recorded
  against the file's size at review time and re-opens when the file drifts
  past it, because a fix inside an oversized file legitimately grows it and a
  gate that fails on that teaches people to stop fixing them. The aggregate
  measures cannot catch this: `Product LOC in files above 1,000` is a sum with
  thousands of lines of slack, so a single file can grow by that much while the
  ratchet reports no regressions. `--check-ratchet` prints a per-owner trend
  line for every oversized file that grew, reported rather than enforced.
- **The purity standard for a lift-and-shift is a token diff, not a claim.**
  Extract the moved region from `git show HEAD:<parent>` and compare token
  streams against the new file. A cut that cannot produce that diff has its
  behaviour argued line by line instead. And verify the move with the fixture
  lanes: for a pure move, an *improvement* is as suspicious as a regression.

One Rust namespacing fact this program proved by compiled probe on 2026-08-17,
because the opposite had been assumed and had blocked a real cut: **a sibling's
`use super::X` does not pin `X` to the parent.** Moving `X` into a different
child and adding `use child::X;` to the parent re-binds the name in the
parent's namespace, so `use super::X` in a sibling — and a rustdoc
`` [`super::X`] `` link — keeps resolving with no edit. The caveat that
survives: a re-export whose only consumer is a `#[cfg(test)]` module is unused
in the shipped lib build and *adds* a warning.

## Documentation gates

| Gate | Command | What it enforces |
|---|---|---|
| Kind/status vocabulary | `uv run pytest python/tests/test_docs_manifest.py` | every live document declares a `Kind:` and a `Status:` in its first five lines; every `docs/history/` file declares `Kind: record` with a date and is listed in the history index |
| Link resolution | `uv run pytest python/tests/test_docs_links.py` | every relative markdown link resolves, and every `docs/...` path named in `src/`, `python/`, `tools/`, `scripts/`, `.github/` or the three top-level files exists |
| Tutorial output | `uv run python scripts/verify_tutorial.py --check` | every documented tutorial command still produces its checked-in fixture |

[contributing-docs.md](contributing-docs.md) explains the vocabulary and the
tutorial harness.
