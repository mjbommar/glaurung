# Testing the decompiler locally

Which command answers which question, and how much it costs. The gate is not the
only tool, and using it as one is why iteration was slow: it compiles and
executes 56 lanes to tell you about the one function you just changed.

Everything below is local. `tools/build_guard.py` resolves the `glaurung` CLI
itself (`GLAURUNG_BIN`, then `.venv/bin/glaurung`, then PATH), so **no venv
activation is needed** for any of it.

## The ladder

Measured on a 24-core host at `GLAURUNG_FIXTURE_JOBS=8` (the default is
`min(8, cores-1)`), so lane counts matter less than you would expect — 12 lanes
cost barely more than 4.

| you want to know | command | measured |
|---|---|---|
| is my build even current | `tools/build_guard.py` | instant |
| what does this one function decompile to, and is it right | `tools/dectest.py FIX:cc:opt:func --show` | **2.9 s** |
| did I break anything obvious | `tools/dectest.py @smoke` | **5.6 s** |
| did I break this lane | `tools/dectest.py FIX:cc:opt` | 13 s |
| did I break this shape family | `tools/dectest.py @switch` / `@loops` | 48 s / 54 s |
| did I break anything, behaviourally | `pytest -m slow python/tests/test_decompiler_fixture_matrix.py` | ~2 min |
| did I move the metrics on this program | `tools/decbench_matrix.py --check --only statemachine` | ~3 min |
| is it safe to push | `scripts/decbench-local-gate.sh` | ~40 min |

## `tools/dectest.py` — the iteration loop

Same harness, same compilers, same seeded vectors, same baseline comparison as
the gate. Only the scope differs, and
`python/tests/test_dectest_equivalence.py` pins that a scoped verdict equals the
gate's verdict for that function — for both a passing and a failing one. A fast
answer that disagreed with the gate would be worse than no fast answer.

```bash
tools/dectest.py                                  # @smoke: 3 lanes, the default
tools/dectest.py 13_loop_early_exit               # one fixture, all 4 lanes
tools/dectest.py 13_loop_early_exit:gcc:O0        # one lane
tools/dectest.py 13_loop_early_exit:gcc:O0:bisect # one function  (~3 s)
tools/dectest.py '*:clang:O0:ternary*'            # globs in any position
tools/dectest.py @loops --show                    # a named set, with the C
tools/dectest.py @region --list                   # resolve only; run nothing
tools/dectest.py --list-sets                      # what sets exist
```

Selector grammar is `fixture[:cc[:opt[:func]]]`, each component defaulting to
`*`. Functions come from `baseline.json` unioned with `manifest.REQUIRED_FUNCTIONS`
— the manifest declares only about a third of the corpus, so selecting from it
alone would leave `mul_widen`, `two_latches`, `tailcall_to_sum4` and 69 others
unaddressable.

`--show` prints the source and our C side by side for every failing function in
scope. That is the check no metric performs: `structs:dist2` scores a *perfect*
graph edit distance while reading two locals nothing assigns.

### Two rules it will not let you break

**A selector that matches nothing is an error.** `03_loop_shape` (missing the
`s`) exits 2 rather than reporting "no regressions in 0 lanes", which is what
success looks like.

**A scoped run cannot become a baseline.** There is no `--write-baseline`, the
result map carries no `__toolchain__` fingerprint (so `fixture_harness` refuses
it), and every summary line names its scope:

```
SCOPED: 1 lane of 56 (2%) — no regressions in scope
```

Refreshing from a partial run would record fresh verdicts for the lanes that ran
and leave the rest of the file describing an older build.

## Named test sets

Committed in `tests/decompiler_fixtures/sets.toml`, so an iteration corpus is
`@loops` rather than a remembered selector string. Each set must resolve to at
least one lane and carry a description, both enforced by
`test_dectest_selection.py` — a set that rots fails the fast suite instead of
silently shrinking someone's loop.

| set | covers |
|---|---|
| `@smoke` | six passing canaries across four shape families, 5.6 s. Run constantly. |
| `@region` | the Phase 4 acceptance set — 114 of the 209 known failures |
| `@switch` / `@loops` / `@early-exit` | the three worst shape families |
| `@flags` / `@widths` / `@polarity` | the Phase 3 and Phase 2 canaries |
| `@calls` / `@structs` | argument-and-result recovery; aggregates |
| `@o0` / `@o2` / `@clang-o0` | whole-corpus lane cuts |

`tools/dectest.py --list-sets` prints them with live lane counts.

## The staleness guard

Every verdict is a judgement of `python/glaurung/_native*.so`. Nothing in the
harness notices that it predates `src/ir/structure.rs`, so a run against a stale
build measures the previous commit and looks identical to a fresh run. It has
already cost a full gate cycle here once.

So `dectest` and `scripts/decbench-local-gate.sh` refuse to run against one:

```
STALE BUILD: src/ir/structure.rs is newer than the built extension.
  Every verdict below would describe the PREVIOUS build, not your change.
  Rebuild:  VIRTUAL_ENV=.venv uvx maturin develop --release
  Override: --allow-stale (or GLAURUNG_ALLOW_STALE=1)
```

## Metrics, scoped

`tools/decbench_matrix.py` scores GED / `type_match` / `byte_match` over 56
cells, each spawning a Joern JVM — about 37 minutes. Affordable before a push,
not in a loop, so scope it:

```bash
tools/decbench_matrix.py --check --only statemachine     # all 4 of its cells
tools/decbench_matrix.py --check --only '*:clang:O0'     # one lane, 14 programs
tools/decbench_matrix.py --list --only sort              # what would run
```

Same two rules: a pattern matching no cell is an error, and `--only` with
`--write-baseline` is refused. Within the cells that ran, a regression is still
a regression; cells never selected are absent by construction, not lost — and
the summary says `SCOPED: ... across N of 56 cells`.

Needs `DECBENCH_DIR` (defaulted to `/nas4/data/workspace-infosec/decbench`).
DecBench does not discover out-of-tree Python plugins, so Glaurung owns
`tools/decbench_glaurung.py`: the matrix launches it with the DecBench
checkout's Python, registers the backend, and then delegates to DecBench's
normal CLI. Set `DECBENCH_PYTHON` only when that interpreter is not at
`$DECBENCH_DIR/.venv/bin/python`; do not patch the external checkout.

Metric similarity is not a behavioral verdict. For the undergraduate
curriculum, add `--behavior` to consume the exact combined C artifact produced
by the selected DecBench backend, compile each required function, and execute
the fixture's deterministic boundary and seeded fuzz vectors against the
original binary:

```bash
DECBENCH_DIR=/nas4/data/workspace-infosec/decbench \
  tools/decbench_matrix.py --backend ghidra --corpus curriculum --behavior \
  --only '27_newton_raphson:gcc:O0' --json
```

The lane fails closed when an artifact is absent or malformed, a required
function has no verdict, the generated C does not compile, a worker crashes or
does not terminate, a return value differs, or any mutable output buffer
differs. Decompiler-dialect scalar names such as Ghidra's `uint` and
`undefined4` have explicit fixed-width compatibility typedefs in the shared
recompile prelude; they are not guessed per result.

When the same backend/binary revision has already been scored, use
`--behavior-only` to skip Joern entirely. It calls only the DecBench decompiler,
then runs the identical rebuild/execution differential. On the Newton GCC-O0
probe this reduced wall clock from roughly three minutes to about eleven seconds:

```bash
tools/decbench_matrix.py --backend angr --corpus curriculum --behavior-only \
  --only '27_newton_raphson:gcc:O0' --json
```

## The full gate

```bash
scripts/decbench-local-gate.sh
```

Three lanes: `cargo test`, the fixture matrix + structural ratchet, and the
per-cell metric ratchet. It now sets up its own PATH and exec tmpdir and checks
the build first, so it runs from a fresh shell.

Lane 3 is a **failure** when `DECBENCH_DIR` is absent, not a skip — a session's
worth of semantic changes once regressed ~25 of 56 cells behind a green gate
because it printed a note and exited 0. `GLAURUNG_ALLOW_NO_METRICS=1` waives it
deliberately, and the waiver is reported in the final line.

## Refreshing baselines

Only from full runs:

```bash
tools/fixture_harness.py --write-baseline      # behaviour, all 56 lanes
tools/gen_structural_baseline.py               # structural facts
tools/decbench_matrix.py --write-baseline      # metrics, all 56 cells
```

An improvement is reported, never auto-absorbed: `dectest` and the gate both
tell you the baseline is stale and leave refreshing to you, after you have read
the changed output.
