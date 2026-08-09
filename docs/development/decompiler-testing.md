# Testing the decompiler locally

> **Status: maintained developer guide.** The commands and gate boundaries are
> current. Lane counts and timings are measured snapshots, not performance
> guarantees; remeasure them before making a current performance claim.

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
| did I break a NON-x86-64 lifter | `tools/arch_roundtrip.py --check` | **4.4 min** |
| does recovered C still build for a 32-bit target | `pytest -m slow python/tests/test_decompiler_wide_arithmetic_width.py` | ~25 s |
| did I move the metrics on this program | `tools/decbench_matrix.py --check --only statemachine` | ~3 min |
| is it safe to push | `scripts/decbench-local-gate.sh` | ~45 min |

Note the `arch_roundtrip` row. Every lane of `fixture_harness` — all 656 cases —
is x86-64 on the host, so it says nothing whatever about `src/ir/lift_arm32.rs`,
`src/ir/lift_arm64.rs`, or the 32-bit half of `src/ir/lift_x86.rs`. Only
`tools/arch_roundtrip.py` executes those, and it costs less than the behavioural
matrix does.

Note also the row under it, and why it is separate. `arch_roundtrip` rebuilds
recovered C **at the host pointer width**, and it declares `__int128` an
*unsupported source* on its 32-bit lanes, so its green i386/armv7 lanes are
compatible with the renderer emitting `__int128` — a type that does not exist on
a 32-bit target — for every 32-bit binary in the corpus. That is not
hypothetical: it shipped, and it cost two DecBench functions their compile. The
wide-arithmetic test recompiles the recovered C **for its own 32-bit target**,
which is the only compile that can reject the type.

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

```text
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

```text
STALE BUILD: src/ir/structure.rs is newer than the built extension.
  Every verdict below would describe the PREVIOUS build, not your change.
  Rebuild:  VIRTUAL_ENV=.venv uvx maturin develop --release
  Override: --allow-stale (or GLAURUNG_ALLOW_STALE=1)
```

## Pass-attributed output health

`GLAURUNG_PASS_HEALTH=1` emits one schema-versioned JSON record to stderr at
every shared AST boundary. It measures the AST itself rather than parsing
formatted C: parameter and declaration counts, generated temporaries, remaining
physical registers, definition-before-use violations, gotos, unresolved
transfers, statement count, verified CFG-edge fidelity, and structuring safety
fallbacks. Named definition violations are retained so a count cannot hide one
identifier replacing another.

```bash
GLAURUNG_PASS_HEALTH=1 .venv/bin/glaurung decompile \
  samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0 \
  --func main --style decbench --no-color \
  >/tmp/hello-main.c 2>/tmp/hello-main.health.jsonl
tools/pass_health_report.py /tmp/hello-main.health.jsonl \
  --output /tmp/hello-main.health-report.json
```

The report groups records by function and names the first pass that changed each
counter and the first pass that introduced each final definition violation.
Ordinary stderr is ignored, but a trace with no health records, an unknown schema,
or malformed counters fails loudly. To include the output/source-CFG size ratio,
pass a JSON object keyed by hexadecimal entry VA:

```json
{"0x2549": 22}
```

```bash
tools/pass_health_report.py /tmp/hello-main.health.jsonl \
  --source-cfg-sizes /tmp/source-cfg-sizes.json
```

The CFG counters describe the region actually lowered to C. If speculative
structuring is rejected, the labelled-CFG fallback should therefore report zero
uncovered and invented edges while `structure_fallbacks` records the rejection.
Tracing is diagnostic-only: the integration test runs the same real binary with
and without the environment variable, requires byte-identical stdout, and
requires the disabled run to emit no health records.

## `tools/arch_roundtrip.py` — the other three architectures

The gate above is x86-64 in every lane. Glaurung lifts three architecture
families, so two of them — plus 32-bit x86 — had **no execution coverage at
all**: a change that inverted a branch in every ARM binary would have left all
656 cases green. That is not hypothetical; it is how the gap was found.

```bash
tools/arch_roundtrip.py                             # the 8-lane matrix, summary
tools/arch_roundtrip.py --check                     # ratchet against the baseline
tools/arch_roundtrip.py --write-baseline            # refresh it
tools/arch_roundtrip.py --arch aarch64 --opt O0 03_loop_shapes   # one cell
```

Matrix: `{x86_64, i386, aarch64, armv7} x {O0, O2}` over the same 30-fixture
corpus, keyed `fixture:arch:opt` and baselined in
`tests/decompiler_fixtures/arch_baseline.json`.

### No emulator, deliberately

The recovered artifact is portable C, so it does not have to run on the target:

```text
fixture.c --(cross cc)--> target .so --(glaurung)--> recovered.c --(cc)--> B
fixture.c ---------------------(cc)-------------------------------------> A
```

A and B are then called with identical seeded vectors and every full-width return
and mutated buffer compared — the same `tools/diff_decompile.py` judgement the
x86-64 gate uses, invoked with `--reference-so` naming the host build.
`qemu-aarch64`/`qemu-arm` are installed on this host and are **not** in the loop:
an emulator bug must never be mistakable for a decompiler bug.

### The control lane is not optional

`x86_64` decompiles a host-architecture object and diffs it against a
host-architecture reference, so nothing about a foreign lifter is involved. It is
always run (adding `--arch aarch64` re-adds it), and `--check`/`--write-baseline`
refuse any run whose control lane is not clean.

Stronger than "clean": the control lane builds the fixture with the same pinned
compiler and byte-identical flags as `fixture_harness.compile_fixture`, so
`fixture:x86_64:{opt}` and the committed `fixture:gcc:{opt}` are the same
question asked through a different code path. `control_gate_disagreements`
requires them to match **function for function** against `baseline.json`, which
costs nothing (those 656 verdicts are already committed) and catches any bug in
the cross-compile plumbing, `--reference-so`, `--lane`, or the export filter.
Measured: 328 executed, 328 pass, **0 disagreements**.

This is the check that matters. The first prototype reported "AArch64 is 37%
correct"; 11 of those failures were the harness executing file-local `static`
roots, and the control lane reproduced the same 11, which is what gave it away.

### Three harness artifacts it caught

1. **File-local `static` roots were executed.** No dynamic symbol, so the
   reference cannot be called at all — and being local, the round-trip closure
   matched their own definition line and prepended the body under test, so the
   rebuild died with `redefinition of ...`. `diff_decompile.run` now executes
   exported functions only.
2. **The rebuilt C was linked against the foreign-architecture object.** That
   link silently fails, the rebuild falls back to unlinked, and every recovered
   body calling an exported sibling dies at load with `undefined symbol` — 44
   cases across the two ARM lanes. It now links against the host reference.
3. **Verdicts were a property of where the gate was run from, not of the
   decompilation.** A recovery that reads an uninitialised local dereferences
   whatever the stack held, and three separate channels fed that residue. Each
   was found by fixing the previous one:

   * *address randomization* — `09_memory_effects:armv7:O2:read_counter`,
     recovered as `*(int *)(*(int *)(var1 + 4) + var1)`, segfaulted on 4 of 8
     identical runs and passed on the other 4;
   * *the caller's environment block*, which sits at the top of the initial stack
     so its size shifts every frame beneath it — the same build then passed in an
     interactive shell and failed under this gate's `env -i`;
   * *the length of the scratch directory's path*, because the dynamic loader's
     own stack use scales with what it is handed —
     `04_switch_shapes:armv7:O0:dense_compute` (a switch whose compare temporary
     is never assigned) said `fail` from `/tmp/aa` and `pass` from a
     65-character sibling.

   Fixed by `setarch --addr-no-randomize`, a canonical fixed-width worker
   environment, and running the worker with `cwd=workdir` so every path in its
   spec is a short relative name (`build_guard.aslr_mode` / `worker_env`,
   `diff_decompile._fixed_name_sibling`). Verified afterwards: the baseline was
   written from an interactive shell and `--check` then reproduced it **exactly**
   from a bare `env -i` with a different scratch root. The x86-64 gate is
   unaffected — 656 pass / 0 fail under both a short and a long scratch root.

### What it currently measures

| lane | executed | pass | fail | structural | skip | correctness |
|---|---|---|---|---|---|---|
| x86-64 (control) | 328 | 328 | 0 | 38 | 0 | **100%** |
| i386 | 272 | 160 | 112 | 38 | 2 | **59%** |
| AArch64 | 317 | 107 | 210 | 9 | 2 | **34%** |
| ARMv7 | 262 | 102 | 160 | 8 | 4 | **39%** |

### Fail-closed, and one declared gap

A missing cross compiler, a failed cross build, a failed reference build, zero
recovered DWARF signatures and a lane that executed no functions are all lane
ERRORS. None can be written into a baseline; an unverified architecture must
never read as "passed".

The single exemption is a source that **cannot exist** for a target: `__int128`
is not a type on a 32-bit machine, and Debian ships `aarch64-linux-gnu-gcc`
without a matching `g++`. Both are derived from a compile probe plus the source
text rather than a hardcoded fixture list, and the lane asserts the build
genuinely fails before recording the gap — a stale exemption is an assertion
failure, not a silent skip.

### Known confound on the 32-bit lanes

`i386` and `armv7` recoveries are rebuilt for the 64-bit host, so a recovery that
hard-codes a 32-bit machine word where an address flows will diverge. That
divergence is real (the C is not portable) but it is *not* evidence about the
lifter's flag or branch semantics. Confirm which before acting on a 32-bit
`fail`. The 64-bit lanes carry no such caveat.

### Toolchain

The reference build and the rebuild of our own decompiled C always run under the
pinned image, exactly as the x86-64 gate does. So does the FIXTURE build for
`x86_64` — that is what makes the control lane comparable to `baseline.json`. The
image ships no cross toolchains and no multilib, so the other three
architectures are built by host compilers; each version string is recorded
per-arch in `__toolchain__`, tagged `pinned:`/`host:`, alongside the ASLR
setting, and all of it is asserted by `--check`. Drift fails loudly with a
refresh instruction instead of producing phantom regressions.

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

Five lanes: `cargo test`, the x86-64 fixture matrix + structural ratchet, the
cross-architecture ratchet, the legacy/curriculum executable round trips, and the
per-cell metric ratchet. It sets up its own PATH and exec tmpdir and checks the
build first, so it runs from a fresh shell.

The metric lane is a **failure** when `DECBENCH_DIR` is absent, not a skip — a
session's worth of semantic changes once regressed ~25 of 56 cells behind a green
gate because it printed a note and exited 0. `GLAURUNG_ALLOW_NO_METRICS=1` waives
it deliberately, and the waiver is reported in the final line.

Lane 3 (`tools/arch_roundtrip.py --check`) is a failure when a cross compiler is
missing, for the same reason: a lane nobody can run is a gap, not a pass. On
Debian/Ubuntu:

```bash
sudo apt install gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf gcc-multilib
```

## Refreshing baselines

Only from full runs:

```bash
tools/fixture_harness.py --write-baseline      # behaviour, x86-64, all 56 lanes
tools/arch_roundtrip.py --write-baseline       # behaviour, 4 arches x {O0,O2}
tools/gen_structural_baseline.py               # structural facts
tools/decbench_matrix.py --write-baseline      # metrics, all 56 cells
```

An improvement is reported, never auto-absorbed: `dectest` and the gate both
tell you the baseline is stale and leave refreshing to you, after you have read
the changed output.
