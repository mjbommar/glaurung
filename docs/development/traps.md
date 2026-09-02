# Traps

> **Kind:** guide · **Status:** maintained

Things this project has already paid to learn. Each section opens with the
durable rule; the dated incident underneath is the evidence for it, kept so
that a reader who doubts the rule can check why it exists.

`CLAUDE.md` states the rules. This file holds the stories. When a rule here is
enforced by an automated gate, [testing-gates.md](testing-gates.md) says which
gate and whether CI runs it.

---

## Build configuration

### A bare `cargo test` does not build `src/python_bindings/`

Use `cargo test --features python-ext` for anything touching that tree.

`src/lib.rs` gates every binding module behind the `python-ext` feature, so a
plain `cargo test` neither runs nor *compiles* that code. On 2026-08-14 a
signature change in `src/python_bindings/` left five test call sites on the
old arity and `cargo test` still reported `2321 passed; 0 failed` — a green
result over code it never built. This is not a corner case:
`src/python_bindings/ir.rs` is the real decompiler entry point, so most passes
are only reachable through it.

`.github/workflows/test-suite.yml`'s `rust` job now pins the feature, and its
own comment records this incident.

### Dead-code counts are a property of the feature configuration, not of the tree

Read a dead-code report only from the configuration you ship.

A plain `cargo build` once reported roughly 98 never-used functions where the
shipped configuration had 4, and two files totalling 1,782 lines looked
unreachable while running on every decompile. Nothing was wrong with the
compiler: the modules that call them are behind `python-ext`.

### `cargo check` is not `cargo test`, even with the right features

`check` is for the inner loop; the command that says a refactor is done is
`cargo test --features python-ext`.

`cargo check --features python-ext --lib` does not compile `#[cfg(test)]`
modules. On 2026-08-28 a signature change to
`select_renderable_dwarf_local_facts` left a test-only call site in
`src/python_bindings/ir.rs` on the old arity: `check` reported 0 errors and
`cargo test --features python-ext` failed to compile. Same class as the bullet
above, different axis — that one is a feature not being built, this one is
test code not being built.

### `--features python-ext` does not build `src/symbolic/` either

Before pushing anything that touches a feature-gated tree, run
`scripts/feature-build-gate.sh`.

`src/lib.rs` gates `symbolic` on its own feature, which is in neither
`default` nor `python-ext`: 26 files and 21,459 lines of product code
(`find src/symbolic -name '*.rs' | wc -l`; `wc -l`, measured 2026-09-02 at
`b8884687`) that `cargo test --features python-ext` never compiles.

Proven by experiment on 2026-08-17: appending invalid Rust to
`src/symbolic/expr.rs` produced 0 errors under `--features python-ext` and 2
under `--features symbolic`. That blind spot is how all three SMT solver
backends sat uncompilable for seventeen days — `BinOp::LogicalAnd` and
`BinOp::LogicalOr` were added on 2026-07-31 and no backend was updated — and
how `triage-parsers-extra` stayed broken for 350 days.

Two gates close it now: `scripts/feature-build-gate.sh` type-checks twelve
configurations including `fuzz/`, which is a separate crate that no
root-manifest check can see; and `test-suite.yml`'s `symbolic` job *runs* the
symbolic tests and fails if fewer than 50 are reachable.

### PyO3 attributes are gated with `cfg`, never folded into `cfg_attr`

`#[cfg_attr(feature = "python-ext", pymethods)]` does not compile. Write two
attributes instead:

```rust
#[cfg(feature = "python-ext")]
#[pymethods]
impl MyStruct { /* ... */ }
```

Field attributes are the opposite case and *must* be wrapped, because an
ungated `#[pyo3(get, set)]` fails when the feature is off:

```rust
#[cfg_attr(feature = "python-ext", pyclass)]
pub struct MyStruct {
    #[cfg_attr(feature = "python-ext", pyo3(get, set))]
    pub field: String,
}
```

Recorded during the 2024-12 pure-Rust / PyO3 separation
([record](../history/pyext-separation-2024-12.md)).

### Never hand-write a `.pyi`

Generate the native stubs with `tools/gen_native_stub.py`; a stale stub does
not merely lose coverage, it makes the type checker confidently wrong.

A `.pyi` shadows the module it describes. On 2026-08-18 `uvx ty check python/`
reported 2,004 diagnostics and 1,618 of them (81%) came from two hand-written
stubs lying. `python/glaurung/__init__.pyi` was a 1,532-line hand
transcription of the native surface that had drifted far enough to deny the
existence of functions the `.so` exports. `python/pytest/__init__.pyi` was
**five lines** on the first-party search path, shadowing the real, fully typed
pytest and blanking the entire module — 417 diagnostics, including every
`pytest.mark` and `pytest.raises` in the suite. Deleting both and generating
`python/glaurung/_native/*.pyi` from the built module took the total to 386.
`python/tests/test_native_stub_current.py` regenerates and diffs, so the
replacement cannot go stale silently.

---

## Measuring the decompiler

### Run `tools/build_guard.py` before every baseline regeneration

A baseline written against a stale `.so` records the old behaviour under the
new commit, and nothing downstream can tell.

On 2026-08-19 a measurement sequence that reverted source files to attribute a
regression restored them **without rebuilding**. The next
`gen_defuse_baseline.py` run measured the reverted binary, reproduced the
committed numbers exactly, and declared two correctly attributed
`--accept-regression` entries stale. The guard names the problem precisely —
`STALE: src/python_bindings/debug.rs is newer than the built extension` — it
just has to be run. Any workflow that reverts `src/` to measure a before-state
must rebuild before the next measurement, **in both directions**.

### A signature change moves the def-use census, and no CI job will tell you

Run `uv run pytest python/tests/test_decompiler_defuse_census.py -q` alongside
the other gates whenever prototypes can move.

The loop people actually iterate in is `tools/dectest.py`, which is not pytest
and never touches the census. Any change that alters a recovered signature —
argument arity, parameter type, return type — changes the emitted body and
therefore the undefined-read count. On 2026-08-19 an arity fix (`11d55613`)
moved `rustc:O0` by +20 and `rustc:O2` by +12 and shipped with the baseline
unrefreshed; attributing it took three A/B experiments, because two later
changes were suspected first and each cost a full build to exonerate.

### `@o0` and `@o2` are host lanes only

A lifter, renderer, or ABI change is not measured until it has run
`dectest @o0 @o2 --arch i386 --arch armv7 --arch aarch64 --arch x86_64_gcc15`,
with `arch_baseline.json` refreshed alongside the other three.

On 2026-08-19 commit `d1365bdb` shipped with `baseline.json`,
`structural_baseline.json` and `defuse_baseline.json` refreshed and
`arch_baseline.json` not refreshed, because `dectest @o0 @o2` reported exactly
two improvements and both were host cells. Four further cells —
`144_inline_asm` at `i386:{O0,O2}` and `x86_64_gcc15:{O0,O2}` — had also gone
`fail -> pass` and were invisible to that command; a parallel agent found them
by running `--arch` on a pristine build of the same commit. No fixture was
added, so this is not the new-fixture case below.

**The selectors are not optional.** `--arch` *retargets whatever selectors you
gave*; with none, it retargets the default `@smoke`. On 2026-08-20 the command
written without selectors reported
`SCOPED: 16 lanes of 3078 (1%) — no regressions in scope`: a green result over
one half of one percent of the matrix, in a form that reads exactly like the
real gate.

### A new fixture needs four baselines refreshed, and one of them hides

`baseline.json`, `structural_baseline.json`, `arch_baseline.json`, and
`defuse_baseline.json`.

The def-use census lane is `slow`-marked, so a scoped `dectest` run and the
three ordinary baseline gates all stay green while the full suite fails. That
is exactly how fixtures `195_by_value_aggregates` and
`196_disjoint_frame_slots` reached `master` with a red census.

### Write the command next to the number

A count or percentage in a document is not a measurement unless the command
that produced it is beside it.

Two tables in the design tree turned out never to have been produced by any
run, and both shaped later decisions. Recorded as a standing convention in the
2026-08-16 roadmap diary.

### Measure the tool's own noise floor before trusting a diff

A byte-identity check over the fixture corpus showed 16 functions changed by a
refactor; running the unmodified build against itself showed 13 changed there
too. Without that control the refactor would have been blamed for a
pre-existing 0.083% non-determinism — which turned out to be `HashMap`
iteration order in `merge_exact_definition_widths`, not the time-based budget
first suspected (2026-08-16 diary, Entry 52).

---

## Performance work

### `maturin develop` builds DEBUG, and the shares in a debug profile are not the shares you ship

Use `uv run maturin develop --release` for anything you intend to measure, and
say which build a number came from.

Profiled on `/usr/bin/bash`, the two builds disagree completely: SIMD/`memchr`
scanning is 12.7% in debug and **0.5%** in release; the allocator is 6.5% in
debug and **26.2%** in release — sixth place versus first. The debug install is
also 276 MB against 974 KB for release. An afternoon of optimisation targets
was picked off the debug profile before anyone checked.
`test-suite.yml`'s Python jobs build `--release` for the same reason.

### `perf` works on this box — check the sysctl before hand-rolling timers

```bash
sudo sysctl -w kernel.perf_event_paranoid=1 kernel.yama.ptrace_scope=0
```

`kernel.perf_event_paranoid` ships at `4` here and `kernel.yama.ptrace_scope`
at `1`, so `perf record` and gdb attach both fail out of the box; passwordless
sudo is available and the change is runtime-only, restored by a reboot.

Four agents built hand-rolled phase timers before anyone checked. The first
real profile immediately surfaced costs none of the timers had seen: SipHash at
7.8%, roughly 11% in `memmove`/`memcmp`, and
`copy_prop::reads::count_reg_uses` as the largest single project function at
8.40%.

### `perf` self-time can be badly wrong for allocation-driven costs

Count allocations with a `GlobalAlloc` when the suspicion is allocation churn;
the sampling profiler will say "don't bother".

`perf` put `disasm::iced` at 2.2% of a discovery profile, and the decoder still
turned out to be worth fixing — its cost was the 12–16 `malloc`/`free` pairs it
*drove* per instruction, charged to libc, which was **47.5%** of that same
profile.

### Do not read a size curve through `Throughput::Bytes`

Pick the denominator the work is actually proportional to.

A four-rung ladder reported CFG discovery at `n^2.13`. The rungs differed 32×
in instructions decoded per file byte; against instructions decoded the
exponent is 0.97. A 12.8 MB fixture finishes faster than a 359 KB one because
12.5 MB of it is DWARF.

---

## Repository operations

### Nothing this project does may write to `/tmp`

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
mkdir -p "$TMPDIR"
```

This is not only about `mktemp`. `maturin develop` writes its wheel to `/tmp`
on every rebuild — a dozen a session — and `cargo`, `pytest` and the fixture
harness all default there too. Verified 2026-08-20: with `TMPDIR` set, the
wheel lands in the cache directory and `/tmp` gains zero entries.

`/tmp` here is a shared, per-user-quota'd tmpfs, so it exhausts long before
`df` shows full and it is not ours alone. **When it fills, it never says "disk
full".** The signatures it has produced instead:

- a plausible assertion failure inside a DecBench test;
- eight fake `pass -> fail` "SEMANTIC REGRESSIONS" in the fixture matrix, with
  13 GB apparently free;
- a pytest `INTERNALERROR` from `OSError: [Errno 122]` inside `terminal.py`'s
  `flush()`, **reporting exit code 0 with no test results**;
- twice, the Bash tool dying completely — every command returning nonzero with
  no output, including `echo`. A successful `Write` is the liveness probe that
  tells that apart from a bad command.

### Sweeping the scratch tmpfs is triage, and only what is ours

On 2026-08-20 the 33 GB under `/tmp/claude-1000` was overwhelmingly other
projects' session data, while this session's own directory was 6.5 MB. Do not
delete another tenant's work to make a test run; say so and ask.

### `git stash` writes a repository-shared ref, across worktrees

Use `git diff > patch` and `git apply [-R]` for A/B measurements.

Two agents in separate worktrees raced a push/pop and swapped each other's
changes. Both recovered from dangling commits, but only because both happened
to notice.

### `cargo fmt -- <files>` ignores the file list and formats the whole crate

Use `rustfmt --edition 2021 <file>` for a single file, and check
`git status` afterwards. This has twice reformatted files owned by other
concurrent work.

### The structural gates are the ones an optimisation loop never runs

After any commit touching `src/`, run `uv run pytest python/tests/` in full,
not the subset.

On 2026-08-31 seven tests were red on pushed `master` for hours — the fitness
ratchet, the large-module review, the env-var allowlist and the stranded-doc
check — while `cargo test --features python-ext`, `dectest @o0 @o2` and a
byte-identity sweep over 419 binaries all stayed green the entire time. Those
gates ask whether the *codebase* is healthy, not whether the decompiler is
correct, so nothing in a perf or fixture loop touches them.
`test-suite.yml`'s two Python jobs catch most of this now, on every push.

### A module split touches six side files

The four fixture baselines, plus three path-keyed registries in the test
suite. [testing-gates.md](testing-gates.md#what-a-module-split-touches) lists
them with their refresh commands.

Three of four splits on 2026-08-31 tripped `REVIEWED_DOC_SUMMARIES` in
`python/tests/test_stranded_doc_comments.py`, which is keyed by file path and
so orphans silently when a registered doc summary moves into a new module.
`python/tests/test_src_dependency_boundaries.py`'s env-var allowlist has the
same shape and the same failure.

---

## Environment provisioning

### Git LFS and `sqlite3` are prerequisites, not conveniences

`git lfs install && git lfs pull` after cloning, and install the `sqlite3`
client.

On 2026-09-02 neither was present on the development box. Every binary under
`samples/` was a 130-byte pointer file, so anything that opened a real sample
read a text stub instead of an ELF, and `scripts/verify_tutorial.py` could not
run its chapters at all. CI hit the same wall first: the first run of
`test-suite.yml` went red across `analysis::elf_plt`, `analysis::gopclntab`,
`analysis::java_class` and every other module that touches the corpus, while
the same commit was 2,944 green locally — because `actions/checkout@v4` does
not fetch LFS objects unless told to. That workflow now sets `lfs: true` on
every job that needs samples, and its header records why.

### The Python suite is tiered, so "the suite passed" needs a tier

`pytest -m core` and the everything-else lane are two different signals.

`tests/test_facets.json` classifies every test file by what it *needs* —
`core` (nothing beyond the built extension), `lfs`, `toolchain`, `docker`,
`llm`, `fixtures`, `decbench` — and `conftest.py` applies those as markers at
collection. `test-suite.yml` runs `python-core` (`-m "core and not decbench"`,
no LFS fetch) and `python-extended` (`-m "not core and not fixtures and not
decbench"`, with LFS and multilib) as separate required jobs, each with its own
timeout, so a timeout in the slow half cannot mask the fast half. Tiering is
how coverage silently degrades, which is why neither lane is nightly-only.
A local `uv run pytest python/tests/` runs both tiers and deselects only
`decbench`.
