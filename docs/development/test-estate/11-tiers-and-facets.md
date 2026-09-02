# Phase 11 — Tiers and facets: what runs where, and why

> **Kind:** plan · **Status:** proposed

The suite is tiered by what each test **needs**, not by what it is about. That
axis is the one a CI job can act on: a runner either has the built fixture
matrix or it does not, has a cross compiler or does not, fetched LFS or did
not. `ir` versus `core` tells you nothing about any of that.

## The facets

`tools/gen_test_facets.py` classifies every Python test file with deliberately
dumb text rules and writes `tests/test_facets.json`; `conftest.py` applies the
result as markers at collection (`tryfirst`, because pytest's own `mark`
plugin deselects inside its collection hook and would otherwise run first).
One reviewable artifact, no decorators in 461 files.

| facet | files | tests | what it needs |
|---|---:|---:|---|
| `core` | 297 | 2,435 | nothing beyond the built extension |
| `lfs` | 101 | 734 | Git LFS sample binaries (`lfs: true` on checkout) |
| `fixtures` | 28 | 1,618 | `tests/decompiler_fixtures/build/` — gitignored, ~40 min to build |
| `toolchain` | 28 | 299 | a compiler at test time |
| `docker` | 18 | 360 | the pinned fixture-toolchain image |
| `llm` | 5 | 27 | a live model endpoint and key |
| `decbench` | 2 | 18 | the out-of-tree DecBench checkout or a Joern JVM |

`core` is the absence of every other facet, and `test_test_facets.py` fails
if a file is ever both. The rules want an **invocation**, not a word — the
first misclassification was the CI wiring test itself, whose docstring merely
talked about Docker.

The Rust suite needs no marker system: its tiers are already its features.
`cargo test --features python-ext` strictly supersets a bare `cargo test`
(there is no `cfg(not(feature = "python-ext"))` anywhere in `src/`), and
`--features symbolic` is the third tier. `dev-oracle` and `solver-*` stay
opt-in because they link external libraries.

## What runs where

| job | selection | needs | measured |
|---|---|---|---|
| `test-suite / rust` | `--features python-ext`, `REQUIRE_TOOLCHAINS=1` | gcc, clang, arm-none-eabi-gcc | 2,957 tests |
| `test-suite / symbolic` | `--features symbolic` | nothing external | 3,025 tests |
| `test-suite / python-core` | `-m "core and not decbench" -n auto` | **no LFS, no cross toolchain** | 2,367 passed, **4:13** parallel (11:19 serial) |
| `test-suite / python-extended` | `-m "not core and not fixtures and not decbench" -n auto` | LFS + multilib | 921 passed, **7:49** parallel (19:11 serial) |
| `decompiler-fixtures / matrix` | `-m slow` then `-m fixtures` | builds the matrix itself | ~40 min + corpus |
| `CI / wheel-smoke` | one x86_64 wheel, no upload | — | push/PR only |
| `CI / linux…sdist` | the 15-job wheel matrix | QEMU for four targets | **tags and dispatch only** |
| `perf-nightly` | `tools/perf_gate.py` | — | nightly; exit 3 on hosted runners |
| `fuzz-nightly` | 8 targets × 2 min | — | nightly |

`python-core` and `python-extended` partition the non-fixture suite exactly:
2,436 + 940 = 3,376, verified by collecting each expression. Both are
**required on every push**. A tier that runs only nightly is how coverage
silently degrades, and this repository has the receipts: `cargo test` unrun
by any workflow until 2026-08-31, 195 symbolic tests type-checked forever and
executed never, seven structural tests red on `master` for hours while every
command anyone typed stayed green. Splitting buys a faster *signal* and an
isolated timeout; it does not buy the right to stop running anything.

## The suite was serial, and that was the actual problem

Everything above reorganises *what* runs where. None of it addressed why a
`core` tier that "needs nothing" took **11 minutes on a 24-core machine using
one of them**. The suite had no `pytest-xdist`: strictly one process, 23 cores
idle by construction — and the one process was not even CPU-bound, because the
time is thousands of 0.3–3 s tests doing real work (compiling fixtures,
spawning the CLI, decompiling) back to back.

Measured 2026-09-02, same box, same selection, `2,367 passed / 0 failed`
both ways:

| tier | serial | `-n auto` (24 workers) | |
|---|---:|---:|---|
| `core` | 11:19 | **4:13** | 2.7× |
| `extended` | 19:11 | **7:49** | 2.5× |

2.7× on 24 cores, not 24×, so a serial bottleneck remains — the next lever is
`--durations=30` under xdist to find the critical path, and it is deliberately
not chased in this phase. The first parallel run reported 110 failures and 95
errors; every one was `FileNotFoundError: 'glaurung'`, because it was launched
with `.venv/bin/python -m pytest` instead of `uv run pytest`, and only the
latter puts the console script on `PATH`. The tests are parallel-safe; the
launch was wrong. Worth recording because it looked exactly like the tests not
being independent.

`-p xdist` is now in `addopts` — under `--disable-plugin-autoload` that is the
only way the plugin loads at all — and `-n auto` stays **opt-in**, because a
24-core box and a 4-core runner want different worker counts and a single
failing test reads better serially. Both CI tier jobs pass `-n auto`; on a
4-core runner expect ~3×, not 2.7×, since the serial run there is slower.

### The inner loop

`-m core -n auto` at four minutes is a pre-commit check, not a development
loop. The loop is narrower than any tier:

```bash
uv run pytest python/tests/test_the_thing_you_touched.py   # seconds
uv run pytest python/tests/ -m core -n auto                  # ~4 min, before a commit
uv run pytest python/tests/ -n auto                          # the full non-fixture suite
```

The Rust loop is `cargo check --features python-ext --lib` (seconds) and
`cargo test --features python-ext <filter>`; `maturin develop --release` only
when Python needs the new `.so`, and `tools/build_guard.py` says whether it
does.

### One product defect found on the way, not fixed here

`glaurung --version` costs **1.6 s**; `glaurung decompile <canary>` costs
0.09 s. With no subcommand the CLI builds every subparser, and `ask`'s pulls in
`glaurung.llm.agents.factory` → `pydantic_ai` → `mcp` → `logfire` — 1.2 s of
imports to print a version string. `test_cli_startup_is_lazy.py` asserts that
`decompile` and `triage` stay lazy, and they do; it never asserts `--version`
or `--help`, and those are exactly the paths that are not. That is the TDD gap
in one sentence. It does not affect test speed — tests spawn subcommands — so
it stays a note here rather than a fix in a phase about tiers.

## What changed, and why each was wrong before

**Fifteen wheel jobs ran on every push and PR and discarded the result.** Six
Linux targets — four under QEMU emulation, tens of minutes each — four
musllinux, two Windows, two macOS and an sdist, on every event, feeding a
`release` job that was already gated on tags. The matrix now runs where its
output is consumed. Pushes get one native wheel as a "does it still package"
smoke. The release path is byte-identical and `test_ci_wiring.py` pins that it
never runs `always()` against skipped builds.

**The 1,162-row known-failure corpus ran nowhere in CI.** It needs the built
matrix, which exists on exactly one job. It now runs there, after the build,
so a fix goes red in CI as an XPASS rather than only on a laptop.

**1,614 tests skipped at runtime on a runner that could never have run them.**
The `-ra` summary that exists to make real skips visible was buried under skips
that were certain in advance. `fixtures` is now deselected by facet on that
runner; `docker`, `llm` and `decbench` stay as runtime skips deliberately,
because those facilities may or may not be present and the self-detected skip
is the honest signal.

**`python-core` skips the LFS fetch.** `core` is defined as needing no sample
binaries, so the ~663 MB checkout is pure cost there. The facet guarantees it,
not the workflow: if a core test ever reads `samples/`, the classifier moves it
and the wiring test notices.

## The cache decision: measured, and deferred

The obvious next step is caching the built fixture matrix so the corpus could
run on the fast job too. Measured: **604 MB raw, 117 MB under zstd -3, 2,934
files**. That fits GitHub Actions cache comfortably and would be seconds to
restore against ~40 minutes to build.

It is **not** done in this phase, for two reasons that both matter more than
the minutes.

First, the matrix job *is* the test. It proves the pinned toolchain still
builds every fixture; restoring a cache and running the corpus against it would
prove something weaker while looking identical. Second, a stale cached fixture
is exactly the failure this repository keeps meeting one level down —
`build_guard.py` exists because a baseline measured against a stale `.so`
records old behaviour under a new commit and nothing downstream can tell. A
fixture cache has the same shape, and a wrong key would produce 1,162 confusing
xfail flips rather than an error.

If it is ever done: key on `sha256(all 219 fixture sources + toolchain image
digest + build flags + harness version)`, verify a per-file manifest on
restore, and keep the matrix job building from scratch regardless. Try the
built-in Actions cache before S3 — no credentials, no IAM, and 117 MB is well
under the 10 GB limit. Reach for S3 only if the 7-day eviction bites.

`Swatinem/rust-cache` and `setup-uv`'s cache are already in use and are kept:
both are keyed on lockfiles by their authors and neither can go stale in a way
that changes what a test proves.

## What was left alone, deliberately

`samples-docker.yml` is path-filtered to `samples/**` and does not push on
PRs. Both Windows PR workflows are path-filtered to their own inputs.
`feature-build-gate.yml` is ~5 minutes of `cargo check`. None of these is the
problem, and touching them without a measured reason would be churn.

## Open

* The `python-extended` timeout (90 min) is inherited, not measured. Its first
  few runs should set it; the job's own duration is the number, not a guess.
* `docker` (360 tests) has no CI home. The runner has Docker but not the
  pinned image; building it there is a decision about whether that job should
  cost the image build every time.
* The per-facet minutes below `core` await the JUnit-timed run.
