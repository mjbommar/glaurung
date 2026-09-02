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
| what does this function do on i386 / armv7 / aarch64 | `tools/dectest.py FIX:arch:opt:func --show` | **1.0 s** |
| what does this function look like with no symbols at all | `tools/dectest.py FIX:cc:O2strip:func --show` | **3 s** |
| did I break this shape family on ONE architecture | `tools/dectest.py @loops --arch armv7_a32` | **8.1 s** |
| did I break anything, behaviourally | `pytest -m slow python/tests/test_decompiler_fixture_matrix.py` | ~2 min |
| did I break a NON-x86-64 lifter | `tools/arch_roundtrip.py --check` | **4.4 min** |
| does the decompiler still work with NO debug info | `tools/stripped_differential.py` | **2.5 min** |
| does recovered C still build for a 32-bit target | `pytest -m slow python/tests/test_decompiler_wide_arithmetic_width.py` | ~25 s |
| is it safe to push | `scripts/decbench-local-gate.sh` | ~50 min |
| did I move a PUBLISHED metric (ask first) | `tools/decbench_matrix.py --check --only statemachine` | ~3 min |
| full pre-submission sweep (ask first) | `scripts/decbench-local-gate.sh --decbench` | ~100 min |
| a real DecBench score, no Joern (ask first) | `tools/decbench_redecompile_tree.py` + `decbench evaluate-tree` | ~20 min |

Read that table top-down and stop as soon as it answers your question. Almost
every iteration belongs in the first five rows, which cost seconds. The gate is a
pre-push check; running it as an inner loop wastes an hour to learn what
`dectest.py @smoke` would have told you in six seconds.

Measured lane costs inside the gate (one run, this host): `cargo test` ~2 min,
fixture matrix + structural ~15 min, **arch round trip ~35 min**, behavior
matrices ~24 min, metric ratchet ~25 min. Note that dropping DecBench halves the
gate but leaves `arch_roundtrip` as the dominant cost — and that lane is our own
fixture corpus, cross-built for six architectures and executed under qemu. If the
gate needs to get cheaper, that is where the time is, not in DecBench.

**DecBench is opt-in, and deliberately so.** The bottom two rows spawn a Joern
JVM per cell. They measure *published-metric* movement (GED / `type_match` /
`byte_match`); they do not prove correctness, and they routinely report their own
resource contention as cell failures — one gate run had 11 cells claim
`build failed` that had built and executed successfully in lane 4 minutes
earlier, and re-ran clean in isolation. `tests/decompiler_fixtures/` is the
corpus that actually proves a change sound, because it executes recompiled output
and diffs it against the original. Reach for DecBench when someone asks for it or
when preparing a submission artifact, not as routine verification.

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

### The compiler slot also takes an architecture

```bash
tools/dectest.py 173_float_int_conversions:i386:O2:widen_int_to_float   # 1.0 s
tools/dectest.py @vector-float --arch i386        # a set, retargeted   # 6.6 s
tools/dectest.py 06_calling_conventions:armv7_a32:O2:fib --show
```

`arch_baseline.json` keys its lanes `fixture:arch:opt`, exactly the shape
`baseline.json` uses for `fixture:cc:opt`, so the architecture goes in the same
slot and `Lane.is_arch` decides which baseline judges the result. The two
vocabularies are disjoint — `gcc`/`clang`/`rustc` against six architecture names
— and a test pins that they stay so.

**A glob never reaches an architecture.** `*` in the compiler slot expands over
the host compilers only, so `@o0` and `@o2` are still the 368 host lanes each
that they have always been; an architecture must be named outright or asked for
with `--arch`. Every committed set retargets unchanged, because sets name
fixtures rather than lanes.

Why this is a correctness lever and not just ergonomics: `arch_roundtrip.py` has
no function selection, so asking about one function on one architecture meant
executing every export in the fixture *and* the forced control lane beside it.
Measured on this host, `03_loop_shapes:i386:O2` cost **11.1 s** that way and
costs **1.1 s** now; a set on one architecture went from 16.9 s to 6.6 s. The
two architectures with the worst recorded failure rates — `armv7_a32` at 26.5%
and `i386` at 21.8%, against x86-64's 13.7% (`fail / (pass + fail + nonportable)`
over `arch_baseline.json` as committed; the roadmap's differential table counts a
different thing and reads a little lower) — were exactly the two with no fast
loop, which is at least a plausible cause of the lag rather than a coincidence.

Two things a scoped architecture run deliberately does NOT do, both of which
`arch_roundtrip.py --check` still does and must:

* **it does not force the `x86_64` control lane.** That lane exists because the
  sweep PRINTS a per-architecture correctness percentage, and a foreign-lifter
  percentage without the apparatus check beside it is uninterpretable. A scoped
  run makes no such claim — it diffs each function against that function's own
  recorded verdict — so paying double for it would buy nothing.
* **it warns rather than refuses on toolchain drift.** Five of the six
  architectures are built by HOST compilers (the pinned image ships no cross
  toolchains and no multilib), so a machine whose `arm-linux-gnueabihf-gcc` is a
  different release than the baseline's gets a `note:` on stderr naming the
  difference. Failing closed there would mean refusing to start on most hosts;
  the gate is where fail-closed belongs.

Where the time actually goes, since the intuition is usually wrong: of the ~1.1 s
a one-function i386 lane costs, the cross build is 0.08 s and the pinned
reference build is 0.59 s. **Builds were never the dominant cost** — an
unfiltered `03_loop_shapes:i386:O2` spent 11.7 s of its 12 s inside
`diff_decompile`, decompiling and executing eighteen functions to answer a
question about one. Function scoping is what bought the 10x; a build cache would
be worth about 0.6 s on top, on a loop that already runs at the speed of the host
one (1.2 s for the equivalent `gcc:O2` selector). That is why there is no cache.

`--show` prints the source and our C side by side for every failing function in
scope. That is the check no metric performs: `structs:dist2` scores a *perfect*
graph edit distance while reading two locals nothing assigns.

### Three rules it will not let you break

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

**A cell the baseline has never judged is reported, not counted as a pass.**
"No regressions" is the result of a comparison, and a cell with no baseline entry
was never compared. On a fixture added since the last refresh, every cell is in
that state, and the old summary line said:

```text
SCOPED: 4 lanes of 768 (1%) — no regressions in scope
```

with thirteen of the twenty cells under it failing. True, and it read as a pass;
only `--full` showed the verdicts, and even `--full` ended with the same line.
Those cells are now listed under `UNBASELINED` and counted in the summary:

```text
SCOPED: 4 lanes of 768 (1%) — NO VERDICT: all 20 cell(s) are unbaselined,
nothing was compared (use --full to see what they did)
```

Partial coverage gets the shorter form, `..., N of M cell(s) UNBASELINED and not
judged (use --full)`. The status stays 0 — an unjudged cell is not a failure, it
is the absence of a judgement — so the summary line is where it is said out loud.
The same rule is why `--arch` can now name a fixture that `arch_baseline.json`
has never recorded (it used to fail as "no function matches", indistinguishable
from a typo) and why a function present in a built object but in no baseline cell
gets a `note:` naming it.

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

This is the SWEEP and the ratchet. For iteration, reach for
`tools/dectest.py FIX:arch:opt:func` instead — same `_run_lane`, same
`diff_decompile` judgement, same `arch_baseline.json` comparison, scoped to one
function. `--check` and `--write-baseline` still refuse every filter, and still
should: a ratchet refreshed from a partial run records new verdicts for the lanes
that ran and leaves the rest describing an older build.

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

## `tools/stripped_differential.py` — the lane with no debug info

```bash
tools/stripped_differential.py                          # whole corpus
tools/stripped_differential.py --fixture 08_indirect_dispatch --explain
tools/dectest.py 08_indirect_dispatch:gcc:O2strip:dispatch --show
tools/dectest.py @exceptions --stripped
```

`fixture_harness.compile_fixture` compiles **every** lane with `-g`,
unconditionally. So the whole corpus was blind to any defect that only appears
without debug info — which is the configuration real targets ship in, and the
configuration where the decompiler has to work hardest, because function extents,
prototypes and types come from analysis instead of being handed over. The
landing-pad ownership defect fixed in `965f8585` rejected 74% of the LSDA sites in
libstdc++ and emitted C containing dangling `goto`s, and not one lane could see
it: `-O0` masks it, and `-O2 -g` masks it because `apply_dwarf_overrides` hands
the function a wide DWARF range.

The lane costs almost nothing to build because of one fact about `strip`: it
removes `.symtab` and every `.debug_*` section and leaves `.dynsym` alone, so a
shared object's exported functions survive at their original addresses and the
object is still `dlopen`able. Measured on `201_float_bit_stores` at gcc `-O2`:
8 exported `T` symbols before and after, identical addresses, 8 `.debug_*`
sections and a 27-entry `.symtab` before and none after, and
`ctypes.CDLL(stripped).f201_f32_slot_bits(1.5)` still returns `0x1d69`. **The
existing execution differential therefore runs unmodified on the stripped
object** — same compile, `strip` the output, `dlopen` and call exactly as before.

### It is a differential, not a second corpus

For a correct decompiler, debug info should improve **naming** and never
**structure**. So the useful quantity is not "does the stripped cell pass" — most
of the corpus's known failures fail with `-g` too, and a standalone stripped
baseline would record them a second time and call it coverage. The useful
quantity is the difference against the `-g` build of the *same compile*: same
source, same compiler, same flags, same addresses, one variable removed.

| `-g` | stripped | meaning |
|---|---|---|
| `pass` | not `pass` | **regression** — a defect with its own control attached |
| not `pass` | not `pass` | pre-existing; this lane did not find it and does not claim it |
| not `pass` | `pass` | **improvement** — usually a DWARF override injecting something wrong |

The `-g` control is read from the committed `baseline.json` rather than re-run.
That halves the cost and is not a shortcut: `fixture:cc:O2` is the identical
compile of the identical source and is already gated by
`test_decompiler_fixture_matrix.py`.

### Where the lane lives in the key

`O2strip` is an **optimisation-slot** value, so a lane key stays the three-part
`fixture:cc:opt` that all four baselines, `dectest`'s selector grammar and the
manifest's `skip_exec_lanes` are built around. The alternatives were both worse:

* a **third axis** cannot be spelled. `dectest` already spends the fourth colon
  component on the FUNCTION (`13_loop_early_exit:gcc:O0:bisect`), so a four-part
  lane key could not be told from a function selector.
* a **compiler-slot** value multiplies instead of composing. That slot already
  carries the six architecture names from `arch_roundtrip.py`, and putting the
  strip variant there would mean `gcc-strip`, `clang-strip`, `rustc-strip` and
  one per architecture.

The optimisation slot is in practice the build-recipe slot — it already names the
flags handed to the compiler. `-O2` then `strip` is one more recipe, it composes
with every compiler for free, and the control lane is a mechanical string
operation on the key (`O2strip` -> `O2`), which is exactly what the differential
needs.

`-O2` only, and that is a scope decision. At `-O0` a function begins at a
`push rbp` after a `ret`, every local is a frame-pointer offset, and nothing is
inlined or outlined — removing the debug info costs the analysis almost nothing.
`-O2` is where extents, prototypes and types genuinely have to be inferred.
Covering `-O0` as well would double the lane count to buy the cheap half of the
problem.

A stripped lane is only ever selected **deliberately**, like an architecture: `*`
in the optimisation slot still expands over `O0`/`O2` only, so `@o0` and `@o2`
are exactly the lanes they always were, and a stripped lane must be named
outright or asked for with `--stripped`.

### The ratchet

`tests/decompiler_fixtures/stripped_divergences.json` records the divergences
already known — deliberately not named `*baseline*`, because it is not a record
of what the lane produced but the much smaller list of cells where the two sides
disagree. `python/tests/test_decompiler_stripped_lane.py` fails on a divergence
that is not in it **and** on a recorded one that has stopped diverging: a stale
entry silently pre-approves the next occurrence of the same cell. Refresh with
`tools/stripped_differential.py --write-divergences`, which refuses to write over
any infrastructure problem.

### One harness artifact it forced out

A recovery that calls a `static` helper is normally completed from the original
`.symtab` (`diff_decompile.include_referenced_local_callees`). A stripped object
has no `.symtab` at all, so every such recovery died at load time with
`undefined symbol: sub_7100` — a harness artifact indistinguishable from a
decompiler bug, and the same one that accounted for 44 of the first ARM run's
"failures". The fix is exact rather than a guess: Glaurung spells an unnamed
function `sub_{va:x}` (one spelling, four sites), so the identifier *is* the
address, and reading it back supplies precisely the fact the symbol table would
have. It removed 4 of the first run's 11 Rust/C++ "regressions".

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

## The same corpus, used to measure function identity

`tests/decompiler_fixtures/build/` is a matched-build matrix — the same 206
sources under two compilers at two optimisation levels with symbols intact —
which makes it ground truth for a second question the decompiler lanes do not
ask: **can we tell that two binaries contain the same function?**

[`identity-measurement.md`](identity-measurement.md) is that harness. It reads
the same build directory (via `GLAURUNG_IDENTITY_CORPUS`, or the same
manifest-relative path), applies the published retrieval filters, and scores
any identity scheme over Marcelli's XO / XC / XM tasks with AUC, MRR10 and
Recall@k. Two schemes already in the tree are retro-scored there: CTPH is at
chance, and the Python structural fingerprint reaches AUC 0.73 cross-compiler
and collapses to 0.52 when the optimisation level is also free.

```bash
cargo test --features python-ext --test identity_retrieval   # ~13s
uv run pytest python/tests/test_identity_retrieval_protocol.py -q   # ~70s
```

## The full corpus, from the published dataset

The section below scores the 250-function **sample set**. The whole 94,575-function
corpus is also scorable here, from published data, with no Joern and no help from
the DecBench maintainers.

### Why this matters: our published row is a coverage artifact, not a score

The published full-corpus leaderboard has Glaurung **11th of 13 at 0.09%** —
`82 / 94,267`. That number is not a measurement of the decompiler, and the proof
is that the numerator never changed:

```
sample-set submission   82 perfect / 250 attempted   = 32.8%
published full-corpus   82 perfect / 94,267 total    =  0.09%   (rank 11)
                        ^^ bit-identical
```

Glaurung is registered `sample_set_only`. The 82 perfect functions are the entire
**250-function** sample-set submission, divided by the full corpus denominator.
Every function we never submitted counts as a miss.

Do **not** try to read this off `total_functions_evaluated`, which is tempting
because our row shows `0`. That field is `0` for all thirteen columns —
including angr, which is ranked 3rd with 34,879 perfect functions. It is
unpopulated, not a signal. The identical numerator is the evidence.

Score each column over the functions it *actually produced output for* — same
file, same `perfect_values`, their definitions throughout — and the picture
inverts:

| decompiler | perfect | scored | rate |
|---|---:|---:|---|
| ida | 35,973 | 87,156 | 41.27% |
| kuna | 36,348 | 88,593 | 41.03% |
| angr | 34,879 | 88,045 | 39.61% |
| ghidra | 25,565 | 76,914 | 33.24% |
| binja | 22,135 | 66,678 | 33.20% |
| **glaurung** | **82** | **250** | **32.80%** |
| fission | 56 | 250 | 22.40% |
| dewolf | 2,856 | 35,583 | 8.03% |

Our per-function quality sits with Ghidra and Binary Ninja. What we lack is
**coverage of the board**, and coverage is a submission problem, not a decompiler
problem. (`codex` and `claude-code` show 57% on ~254 functions — per the dataset
card those two are LLM agents that run on a sampled slice, so they have the same
denominator caveat in the other direction.)

`tools/decbench_compare_full.py` computes that table, and is validated by
reproducing the published counts exactly: 82 Union, 69 `ged`, 22 `type_match`,
5 `byte_match`.

### Running it

Everything is pinned, because a run whose inputs float cannot be compared to an
earlier one. The dataset revision is pinned in `tools/decbench_fetch_full.py`;
pin the DecBench commit yourself.

```bash
TREE=~/.cache/glaurung/decbench-full/tree

# 1. Fetch. 803 binaries + 800 Joern-extracted source CFGs, ~680 MB, sha256
#    verified against the manifest, resumable. BSD-2, public, ungated.
uv run python tools/decbench_fetch_full.py "$TREE"

# 2. Decompile, current build. Same discipline as the sample-set path:
#    stripped bytes at DWARF-derived addresses. ~35 min.
export DECBENCH_SAMPLE_TREE="$TREE"
uv run python tools/decbench_redecompile_tree.py "$(git rev-parse --short=7 HEAD)"

# 3. Score with DecBench's own metric code, pinned. Do not restrict metrics:
#    Union includes GED, type_match, and byte_match.
git clone https://github.com/Noelo-Lab/decbench.git && cd decbench
git checkout f76dae075d4d82004fb21132b3f15e43b680e179
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e .
.venv/bin/decbench evaluate-tree "$TREE" \
    -d "glaurung-$(git -C ~/projects/personal/glaurung rev-parse --short=7 HEAD)" -j 12

# 4. Merge the new values into the shared measurable universe. This rebuilds
#    every column's denominator from the 803 raw evaluated fragments.
uv run python tools/decbench_audit_full.py "$TREE" \
    --published ~/.cache/glaurung/decbench-full/published_function_results.json \
    --column "glaurung-$(git rev-parse --short=7 HEAD)" \
    --output ~/.cache/glaurung/decbench-full/audited_score.json
```

`decbench_fetch_full.py` writes `decbench_dataset_provenance.json` beside the
tree recording repo, revision and config — a scored tree whose provenance is not
written down cannot be defended later.

### What it does and does not measure

The materialized path has these limits:

* **All three metrics run.** Stored artifacts do not carry structured variable
  records, but DecBench's `type_match` implementation falls back to parsing the
  emitted C signature and declarations. The 2026-08-30 run scored type match on
  86,612 functions. Do not describe it as a two-metric run.
* **`ged` needs a source CFG.** 800 of 803 binaries have one published; the
  other three have no ground truth and are skipped.
* **The denominator is shared and can move for every decompiler.** DecBench
  includes a function when any column has a finite value for at least one
  metric. A new column can make an old unmeasurable function measurable. Never
  divide only the new column by its own coverage, and never reuse the old
  leaderboard denominator. Merge first with `decbench_audit_full.py`.

The audited 2026-08-30 run illustrates the distinction. The manifest has
94,575 functions; the published measurable universe has 94,267; Glaurung
produced at least one metric for 94,358; and the merged shared universe is
94,423. The comparable Union result is therefore `39,236 / 94,423`, not
`39,236 / 94,267` or `39,236 / 94,358`. See
`docs/design/decbench-full-score-audit-2026-08-30.md`.

### One deviation from DecBench's own adapter, measured

`decbench_redecompile_tree.py` always passes `--vas`. DecBench's adapter
(`decompilers/raw/glaurung_raw.py`) passes `--vas` only when the target set is
`<= _MAX_VAS_INLINE` (400) and otherwise runs `--all --limit 30000` and narrows
afterwards. That threshold is not a corner: **55 of 803 binaries exceed it, and
they hold 65,742 of 94,575 functions — 69.5% of the corpus.**

This means the run is a target-address evaluation, **not an exact replay of the
current DecBench adapter** for those 55 binaries. Decompiling one binary
both ways and diffing the pseudocode for the functions both produced:

    --vas  60 functions      --all  192 functions
    overlap 58  ->  57 byte-identical, 1 different

The single difference is a thunk: `--vas` renders `ret = sub_2560(...)`, `--all`
renders `goto L_2560`. Whole-binary mode sees the callee and folds the jump;
targeted mode does not and calls it. Materially equivalent in that probe, but
real. One probe does not certify all 55 large-target binaries. Report this as
the targeted-VA route unless an exact-adapter full replay has also completed.

## A real DecBench score, without Joern

`decbench_matrix.py` above spawns a Joern JVM per cell, which is why it is
opt-in and costs 37 minutes for 56 cells. There is a second path that scores the
**whole 250-function sample-set** with DecBench's own metric code and needs no
Joern at all, because the expensive Joern product — the source CFGs — is already
extracted and committed in a materialized tree.

`~/projects/personal/decbench-sample-set-glaurung-tree` holds compiled binaries,
**221 pre-extracted `source_cfgs/*.json`**, prior decompiled artifacts, and the
scoreboards from previous runs. `decbench evaluate-tree` scores stored artifacts
against those CFGs. So the loop is: re-decompile into the tree with the current
build, then score.

```bash
# 1. re-decompile (~40 s for 215 binaries / 241 functions)
#    Reads sample_set_manifest.json, resolves each target function's address
#    from the compiled binary's symbol table, strips a COPY, and decompiles at
#    those VAs -- DecBench's discipline: stripped bytes, DWARF-derived addresses.
#    Writes decompiled/glaurung-<sha>_<stem>.{c,toml} beside the existing column.
python3 tools/decbench_redecompile_tree.py "$(git rev-parse --short=7 HEAD)"

# 2. score. SCOPE IT TO THE NEW COLUMN with -d, or it re-scores every stored
#    artifact in the tree: 2,007 of them took >50 minutes, 215 took ~20.
cd ~/projects/personal/decbench-glaurung-integration
uv run decbench evaluate-tree ~/projects/personal/decbench-sample-set-glaurung-tree \
    -m ged -m byte_match -d "glaurung-$(git -C ~/projects/personal/glaurung rev-parse --short=7 HEAD)" -j 12
```

Results land in the tree's `scoreboard.toml` and `function_results.json`.
**Copy the old `scoreboard.toml` aside first** — a scoped run rewrites it with
only the columns it scored, so the previous column's numbers are gone unless you
kept them.

### What it does and does not measure

* **`ged` and `byte_match` only.** `evaluate-tree` says so itself: `type_match`
  needs recovered variables, and stored `.c` artifacts do not carry them. That
  is 2 of 3 metrics — but GED is the dominant one, 69 of our 82 published Union
  points.
* **The denominator moves.** 250 -> 241 in the run below: nine target functions
  had no resolvable symbol in their compiled binary. Perfect-count percentages
  are on the smaller base and are therefore slightly flattered; **mean and median
  distance are unaffected and are the cleaner signal.**
* It scores the sample-set, not the complete board. For the full corpus see
  `decbench-glaurung-fresh-eval-20260808/results/fresh-source-tree-45b233c`,
  which has all 40 projects at O0/O2/O2-noinline with DWARF — but no source
  CFGs, so GED there does need Joern.

### The measured result, 2026-08-27

Same tree, same source CFGs, same metric code; only the decompiler revision
differs. `24b3826` is the column stored in the tree from 2026-07-29.

| metric | `24b3826` | `d8665dd` | change |
|---|---|---|---|
| Union | 48/250 · 19.2% | **65/241 · 27.0%** | **+7.8 pp** |
| GED perfect | 47/239 · 19.7% | **64/231 · 27.7%** | **+8.0 pp** |
| GED mean distance | 41.55 | **28.98** | **-30%** |
| GED median distance | 14.0 | **10.0** | **-29%** |
| byte_match perfect | 2/250 · 0.8% | **10/241 · 4.1%** | **5x** |
| byte_match mean | 0.0423 | **0.2186** | **5.2x** |

The mean-distance column is the one to watch. Our published profile is *best
perfect-count of any deterministic backend, worst mean GED distance of any real
backend* (`docs/design/decbench-native-provenance-2026-08-27.md` §4b) -- the
signature of catastrophic rather than incremental failure. Mean fell 30% and
median 29%, so that axis moved, which is what the diagnosis predicted had to.

This is a month of decompiler work, not one day's: little of the 2026-08-27 ARM
dispatch work shows here, because the sample-set contains almost no ARM table
dispatch. That was the point of `docs/design/decbench-defect-reproductions-2026-08-27.md`
§10a -- rank by occurrence in the functions DecBench SCORES, not corpus-wide.

### The pytest side: the `decbench` marker

`pytest.ini` deselects `-m decbench` by default, so `uv run pytest python/tests/`
cannot reach the fork. Exactly one file carries the marker —
`test_decbench_glaurung_backend.py`, which resolves `$DECBENCH_DIR` and runs the
adapter under that checkout's interpreter. On a box where the checkout happens to
exist it used to spawn the fork on every plain test run.

```bash
uv run pytest python/tests/ -m decbench     # the opt-in; runs the fork
```

The marker replaces `slow` on that file rather than joining it, because CI and
gate lane 2 select `-m slow` and an explicit `-m` replaces the default
expression. The other five `test_decbench_*.py` files are DecBench-*named*, not
DecBench-*dependent*: they are contract tests over committed data in
`tests/decbench_corpus/` and `tests/decbench_scoreboard/`, 116 assertions in
about 0.3 s, and they stay in the default run because they are the only thing
guarding the adapter's schema. `test_local_gate_fails_closed.py` pins that
classification by what each file actually resolves, not by its filename.

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
scripts/decbench-local-gate.sh              # default: our fixtures, lanes 1-3
scripts/decbench-local-gate.sh --decbench   # + DecBench lanes 4-5 (ask first)
```

The default three lanes are `cargo test`, the x86-64 fixture matrix + structural
+ definition-before-use ratchets, and the cross-architecture ratchet — all over
`tests/decompiler_fixtures/`. It sets up its own PATH and exec tmpdir and checks
the build first, so it runs from a fresh shell.

### The definition-before-use lane

`python/tests/test_decompiler_defuse_census.py` gates what the pre-render
verifier (`src/ir/verify_defs.rs::verify_before_render`) found on the exact AST
each function was printed from. A violation means the emitted C reads a value the
machine never produced, so the recompiled function returns garbage — invisible to
`type_match` / `GED` / `byte_match`, because the C still parses and still has the
right shape.

The structural lane already ratchets these, but it builds each fixture once with
`gcc -O0`; that single lane held **7 of the 304** violations in REQUIRED
functions when the census was first taken. This lane censuses every lane each
fixture's language supports and ratchets both directions, at two precisions:
REQUIRED functions per function and per message, everything else emitted against
a per-lane ceiling on totals. Refresh with `tools/gen_defuse_baseline.py`.

That refresh is guarded in one direction only (`tools/defuse_ratchet.py`).
Lowering a ceiling and adding cells for a new fixture are free; RAISING one is
refused unless you name the movement and say why:

```bash
tools/gen_defuse_baseline.py --accept-regression 'rustc:O0=+10: <why>'
```

The acceptance is written into the baseline's own `accepted_regressions`, so the
next person to regenerate inherits it and the drift cannot be regenerated away.
This exists because the refresh is ALSO what the improvement half of the ratchet
tells you to run, so an unguarded rewrite quietly reset the ceiling upward: at
`fd0b6455` it took `rustc:O0` from 7525 to 7535 and `rustc:O2` from 4451 to
4457 with every tracked `required` cell unchanged, and nobody saw it. A new
fixture does not need the flag: the baseline records per-`fixture:cc:opt`
totals, so a rise that belongs entirely to fixture-lanes the baseline has never
seen is not charged to anyone.

Every `glaurung decompile` also now names any function that failed the check on
**stderr** — stdout stays exactly the payload — so the failure is visible without
running the gate at all. `GLAURUNG_VERIFY_DEFS=1` adds the per-violation
`// glaurung-verify:` comments; it stays opt-in because the decbench render is an
artifact external tooling parses and scores.

`--decbench` (or `GLAURUNG_RUN_DECBENCH=1`) adds the legacy/curriculum executable
round trips and the per-cell metric ratchet. Use it when a change could move a
published metric, or before preparing a submission artifact.

Two properties are preserved so an unmeasured run can never read as a measured
one — a session's worth of semantic changes once regressed ~25 of 56 cells behind
a green gate because the metric lane printed a note and exited 0:

- The default run's final lines say `DecBench lanes 4-5 NOT RUN` and
  `GED / type_match / byte_match are UNMEASURED by this run`.
- Under `--decbench`, an absent `DECBENCH_DIR` is a **failure**, not a skip.
  `GLAURUNG_ALLOW_NO_METRICS=1` waives it deliberately, and the waiver is
  reported in the final line.

`python/tests/test_local_gate_fails_closed.py` enforces both.

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
tools/gen_defuse_baseline.py                   # def-before-use, every lane
tools/decbench_matrix.py --write-baseline      # metrics, all 56 cells
```

An improvement is reported, never auto-absorbed: `dectest` and the gate both
tell you the baseline is stale and leave refreshing to you, after you have read
the changed output.

### A baseline is not a property of the directory you built in

Every fixture compile passes `-ffile-prefix-map=$ROOT=.` (`--remap-path-prefix`
for rustc) and runs with its working directory pinned to the repository root, so
the produced object contains no absolute path — see
`fixture_harness.path_remap_flags`. Without it, `DW_AT_comp_dir`, every DWARF
file name, `__FILE__`, and (for rustc) every panic-location literal carry the
checkout's path. Those are strings: a checkout at a different depth has
different string lengths, a different `.rodata`, different section addresses,
and therefore a different set of discovered functions.

That is not theoretical. On 2026-08-18 two independent agents, each working in a
`.claude/worktrees/agent-XXXX` checkout, reported `defuse_baseline.json` stale on
master; the same commit in the main checkout reproduced the committed numbers
exactly. Both were right about their own tree and wrong about master, and either
report, if trusted, would have written a bad baseline. The flags make the objects
byte-identical across roots (proved by `cmp` over gcc, clang, g++ and rustc at
two path depths 60 characters apart), so a worktree and the main checkout now
measure the same corpus.

### ...and `build/` is a cache, so its key has to cover the bytes

`tests/decompiler_fixtures/build/` keeps every compiled fixture object under
`{fixture}-{cc}-{opt}.so`. That name was the entire cache key until 2026-08-18,
which meant the directory could not tell a current object from one built by a
different flag list, a different compiler, or the host toolchain instead of the
pinned one.

The remap flags above are the worked example. When they were added, every object
already on disk kept its old bytes — including the absolute checkout path the
flags exist to erase — and every consumer that READS an object without compiling
it went on measuring the old ones. Measured on the main checkout, 2026-08-19: 17
objects six days older than the flag change survived it, and
`132_cpp_vtable_layout-rustc-O0.so` — a name no lane has produced since
`lanes_for` stopped cross-producting C++ sources with Rust lanes — still
contained the checkout path four times. Two wrong findings came out of that in
one day.

Every compile now writes a sidecar, `<object>.so.build.json`, recording what
produced it:

```json
{
  "argv": ["gcc", "-shared", "-fPIC", "-g", "-O0", "-w",
           "-ffile-prefix-map=$ROOT=.", "-o", "$ROOT/.../13_loop_early_exit-gcc-O0.so",
           "$ROOT/tests/decompiler_fixtures/src/13_loop_early_exit.c"],
  "compiler": "gcc",
  "compiler_version": "gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0",
  "target": "x86_64-linux-gnu",
  "toolchain_mode": "docker",
  "toolchain_image": "sha256:c6845868...",
  "source_sha256": "fa3479d8...",
  "object_sha256": "bff81b43...",
  "schema": 1
}
```

`$ROOT` rather than the literal path, because the remap flags make the object
byte-identical across checkouts — keying on the absolute path would rebuild the
whole corpus in every worktree to prove nothing — while still moving the moment
a flag is added, removed or retargeted. `toolchain_image` is the image CONTENT
digest, not its tag, because `ensure_image` only checks that the tag exists.

`fixture_harness.ensure_fixture(src, cc, opt)` is the entry point for anything
that reads an object it did not compile (`dectest --show`, the determinism and
loop-hoist tests). It reuses the object only when the fingerprint matches and
recompiles otherwise. `compile_fixture` still rebuilds unconditionally: a full
cold build is **33.6s wall for all 768 objects** at `default_jobs()==8` under the
pinned toolchain on a 24-core host, so the gate buys almost nothing by skipping
compiles and would be taking on the risk that the key is missing a field. A warm
sweep over all 768 lanes is 0.2-3.1s.

```bash
python tools/fixture_harness.py --check-cache   # what in build/ cannot be trusted
python tools/fixture_harness.py --prune-cache   # delete it
```

`--check-cache` reports two kinds: STALE (fingerprint disagrees) and ORPHAN (a
name no current lane produces, so nothing will ever overwrite it). Either the
strict compile lane's object (`-Wall -Wextra -Werror`) or the execution lane's
(`-w`) counts as current, since both write that path and whichever ran last is
what is there.
