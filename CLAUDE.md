# CLAUDE.md — Glaurung

> Hand-maintained project guide for Claude Code. (Historical note: this file
> used to be compiled from `.claude/modules/` by `cm.py`; that system has been
> removed. Edit this file directly.)

## What Glaurung is

A modern, **AI-native reverse-engineering framework** — "what Ghidra would look
like if built today." Rust core for performance/safety, Python for the
analyst-facing surface, and an LLM agent (`pydantic-ai`) integrated throughout
the pipeline rather than bolted on.

- **Rust crate** (`src/`): the analysis engine, exposed to Python via PyO3.
  Key modules: `triage`, `formats` (ELF/PE/Mach-O), `disasm` (x86/x64, ARM/ARM64,
  RISC-V), `analysis` (CFG, function discovery), `ir` (LLIR), `symbols`,
  `demangle` (Itanium/Rust/MSVC), `flirt`, `strings`, `similarity`, `entropy`.
- **Python package** (`python/glaurung/`): PyO3 bindings (`_native…so`), the
  `glaurung` CLI (`cli/commands/`), the `llm/` agent subsystem, and the `kb/`
  knowledge base.
- **Knowledge base**: `.glaurung` SQLite project files persist function names,
  comments, types, xrefs, stack vars, prototypes — with `set_by` provenance
  (manual/dwarf/stdlib/flirt/propagated/auto/borrowed; **manual always wins**).

## DecBench upstream boundary — no autonomous interactions

The DecBench collaborator explicitly requires agents to follow its README AI
rules (introduced in DecBench commit `b909596`): **no autonomous DecBench
issues, comments, or pull requests**. The maintainer also requested that any
follow-up issue be human-written. See the [maintainer comment](https://github.com/Noelo-Lab/decbench/issues/81#issuecomment-5486158431).

Agents may inspect the repository, run local evaluations, implement Glaurung
changes, and prepare internal evidence. They must never author and post, or
otherwise create end-to-end, a DecBench issue, comment, or PR through the web,
API, `gh`, git, or any other tool. Stop at the upstream boundary and hand the
evidence to the human. A user request to perform the upstream action does not
override the upstream project's contribution rule.

**Active frontier:** decompiler quality (control-flow structuring, type-aware
re-render), the Windows port (PDB ingestion/naming, `ioctl_taint`,
`windows-risk`), analyst ergonomics, and the LLM vuln-discovery substrate
(L1–L5 routing + F1–F7 cost guards).

## Build / test / run

```bash
# Install locked dependencies and build the extension
uv sync --locked --dev

# Rebuild after any Rust change (wheel: `uv run maturin build --release`)
uv run maturin develop

# Run the CLI (console script: glaurung = glaurung.cli:main)
uv run glaurung --help
uv run glaurung triage <binary>
uv run glaurung kickoff <binary>        # full analysis → .glaurung KB

# Tests
uv run pytest python/tests/                # Python suite (~345 test files)
uv run pytest python/tests/test_x.py -xvs  # one file, stop on first failure
uv run pytest python/tests/ -m decbench    # OPT-IN: the tests that run the fork
cargo test                              # Rust suite (~125 test modules)
cargo test --features python-ext        # ...PLUS src/python_bindings/ (see below)

# Decompiler: iterate small, gate big — docs/development/decompiler-testing.md
tools/build_guard.py                              # is the .so current?
tools/dectest.py 13_loop_early_exit:gcc:O0:bisect --show   # ONE function, ~3s
tools/dectest.py @loops                           # a named set (sets.toml)
tools/dectest.py --list-sets                      # what sets exist
# Iterate with dectest (seconds). The gate below is a PRE-PUSH check, not a loop.
scripts/decbench-local-gate.sh                    # OUR fixture lanes 1-3 (~50m)
scripts/decbench-local-gate.sh --decbench         # + DecBench/Joern lanes 4-5 (~100m)

# Criterion microbenchmarks over the decompiler (ir/ and analysis/)
cargo bench --bench ir_lift            # lifters: x86/ARM32/ARM64/x87, micro -> whole object
cargo bench --bench ir_dataflow        # 17 passes isolated + pipeline groups
cargo bench --bench ir_structure       # structuring/render, 14-SHAPE sweep
cargo bench --bench analysis_cfg       # CFG discovery, whole-binary Throughput::Bytes
cargo bench --bench decompile_pipeline # end-to-end + an 8-phase split
# NOTE: Criterion has no stored baselines and remains diagnostic. The shipped
# entry-point instruction gate has an initial `bench/perf_baseline.json`, but
# missing/partial/incomparable evidence still fails open; it is not yet a
# provenance-complete release gate.

# Compare our output against angr and Ghidra on one function, side by side
uv run python tools/compare_decompilers.py <binary> main print_sum
# ...needs `uv pip install angr` and/or Ghidra at /opt/ghidra (JDK 21 — 17 is
# too old, 25 is rejected). Both optional; an absent tool is reported, not
# fatal. See docs/development/decompiler-parity-backlog.md.

# Fuzzing. `cargo fuzz` reaches 8 targets; seed them from our own binaries
# first, or libFuzzer spends its first minutes rediscovering the ELF magic.
uv run python fuzz/seed_corpus.py
cargo fuzz run disasm_decode -- -max_total_time=120

# Bench / regression scorecard
uv run python -m glaurung.bench

# Lint / format / types  (modern tools only — see below)
uvx ruff format python/
uvx ruff check python/ --fix
uvx ty check python/

# Type stubs for the PyO3 extension — regenerate after ANY binding change
uv run python tools/gen_native_stub.py          # rewrite python/glaurung/_native/*.pyi
uv run python tools/gen_native_stub.py --check  # exit 1 if stale
```

## Tooling conventions (non-negotiable)

- **Python tooling:** `uvx` for ephemeral tools, `uv add` for real deps. Use
  **`ruff`** (format + lint), **`ty`** (type check). **Never** mypy/pyright,
  black, pylint, flake8, isort, or `pip`. Don't add `[tool.mypy]`/`[tool.black]`.
- **Rust:** `Result<T,E>` with `?` over `.unwrap()`; `///`/`//!` docs on public
  items; `unsafe` only with justification.
- **Naming:** snake_case fns/vars, PascalCase types/classes, UPPER_CASE consts.
- Prefer `pathlib`, type hints on all public Python APIs, Google-style docstrings.

## Working style

This is a **real, production** tool used for actual binary analysis. Hold the line on:

- **TDD.** Write/extend the test first, then make it pass. Run the suite before
  calling something done. New analysis behavior needs a real fixture-backed test.
- **No mocks/fake data without explicit permission** — especially for binary
  fixtures and analysis output. Use real binaries from `samples/`, `tests/`,
  `tests/fixtures/`.
- **Don't claim "done" without running tests + ruff + ty.** Since 2026-08-31
  CI runs them too (`.github/workflows/test-suite.yml`: `cargo test --features
  python-ext`, the full Python suite, and ruff). Before that no workflow ran
  either suite — 6 of 445 Python test files executed in CI and the only
  occurrence of "cargo test" under `.github/` was a comment. That is fixed, but
  the fixture matrix and the six baselines still gate nothing automatically.
- **`cargo test` does NOT build `src/python_bindings/`.** It is behind the
  `python-ext` feature (`src/lib.rs`), so a plain `cargo test` skips ~120 tests
  AND does not compile that code at all. On 2026-08-14 a signature change there
  left five test call sites on the old arity and `cargo test` still reported
  `2321 passed; 0 failed` — a green result over code it never built. This is not
  a corner: `python_bindings/ir.rs` is the real pipeline entry point, so most
  passes are only reachable through it. Use `cargo test --features python-ext`
  for anything touching that tree. The same gate applies to dead-code counts:
  plain `cargo build` reported ~98 never-used functions where the shipped
  configuration had 4, and two files totalling 1,782 lines looked unreachable
  while running on every decompile.
- **`cargo check` is not `cargo test`, even with the right features.** `cargo
  check --features python-ext --lib` does not compile `#[cfg(test)]` modules. On
  2026-08-28 a signature change to `select_renderable_dwarf_local_facts` left a
  test-only call site in `src/python_bindings/ir.rs` on the old arity: `check`
  reported 0 errors, `cargo test --features python-ext` failed to compile. Same
  class as the bullet above, different axis — that one is a feature not being
  built, this one is test code not being built. Use `check` for the inner loop;
  the command that says a refactor is done is `cargo test --features python-ext`.
- **`--features python-ext` does not build `src/symbolic/` either, and that is
  ten times bigger.** `src/lib.rs:80` is `#[cfg(feature = "symbolic")]`, and
  `symbolic` is in neither `default` nor `python-ext`. **26 files, 21,459 product
  LOC that `cargo test --features python-ext` never compiles.** (Re-counted
  2026-08-31: this bullet used to say 21 files / 14,649 LOC and line 65. The
  tree grew 46% while the note stood still, which is its own small lesson about
  numbers in prose.) Proven by experiment on 2026-08-17: appending invalid Rust to
  `src/symbolic/expr.rs` gives 0 errors under `--features python-ext` and 2 under
  `--features symbolic`. This is how all three SMT solver backends sat
  uncompilable for seventeen days (`BinOp::LogicalAnd`/`LogicalOr` added
  2026-07-31, no backend updated) and how `triage-parsers-extra` stayed broken
  for 350 days.
- **Before pushing anything that touches a feature-gated tree, run
  `scripts/feature-build-gate.sh`** — 12 `cargo check --all-targets` lanes,
  ~4m30s, exit 1 on any failure. It is the only thing in the repository that
  builds `solver-*`, `symbolic`, `exec`, `dev-oracle`, `triage-parsers-extra`
  — or `fuzz/`, which is a separate crate that no root-manifest check can see
  and which had therefore been compiling by luck (lane 12, added 2026-08-31). Note `scripts/lint-rust.sh` DOES run
  `cargo clippy --all-targets --all-features`, which would have caught all of
  the above — but nothing calls it, and until 2026-08-17 it died inside
  `build.rs` on any machine without Bitwuzla. It runs now and is red (260
  pre-existing clippy errors under `-D warnings`), which is why the pre-push
  path uses the build gate instead.
- **Never hand-write a `.pyi`.** A stub shadows the module it describes, so a
  stale one does not merely lose coverage — it makes `ty` confidently wrong.
  On 2026-08-18 `uvx ty check python/` reported 2,004 diagnostics; 1,618 of them
  (81%) were two hand-written stubs lying. `python/glaurung/__init__.pyi` was a
  1,532-line hand transcription of the native surface that had drifted so far it
  denied the existence of functions the `.so` exports. `python/pytest/__init__.pyi`
  was **five lines** on the first-party search path that shadowed the real,
  fully typed pytest and blanked the entire module — 417 diagnostics, including
  every `pytest.mark` and `pytest.raises` in the suite. Deleting both and
  generating `python/glaurung/_native/*.pyi` from the built module
  (`tools/gen_native_stub.py`) took the total to 386.
  `python/tests/test_native_stub_current.py` regenerates and diffs, so the
  replacement cannot go stale silently.
- **Adding a CLI command invalidates a tutorial fixture.**
  `docs/tutorial/_fixtures/01-install/help-head.out` records the first three
  lines of `glaurung --help`, which include the full subcommand list, so any new
  entry in `cli/main.py`'s registry drifts it and
  `test_verify_tutorial.py::test_check_mode_does_not_rewrite_install_fixtures`
  fails. Refresh with
  `uv run python scripts/verify_tutorial.py --chapter 01-install --capture`, and
  read the diff — it should be the command list and nothing else.
- **A split has four side files to refresh, not one.** Beyond the four fixture
  baselines: `python/tests/test_large_module_review.py` (a file that drops under
  1,000 LOC must have its `REVIEWED_LARGE_MODULES` entry DELETED, or
  `test_no_review_entry_outlives_the_file_it_reviewed` fails), and
  `python/tests/test_src_dependency_boundaries.py` (its env-var allowlist is
  keyed by FILE PATH, so splitting any module that reads an env var breaks it).
- Surface real results faithfully (if a test fails or a step was skipped, say so).
- **Never run DecBench / Joern unless explicitly asked.** `tests/decompiler_fixtures/`
  is the corpus we verify against: it executes recompiled output and diffs it
  against the original, which is what actually proves a decompiler change sound.
  DecBench (`tools/decbench_matrix.py`, gate lanes 4-5, anything spawning a Joern
  JVM) is an *evaluation* harness for published metrics — it costs tens of minutes
  and reports its own resource problems as cell failures. Default to
  `tools/dectest.py <selector>` while iterating and
  `scripts/decbench-local-gate.sh` before a push. Reach for `--decbench` only when
  the user asks, or when preparing a submission artifact. The same boundary exists
  in pytest: `pytest.ini` deselects `-m decbench` by default, so no ordinary test
  run reaches the fork. `docs/design/decompiler-roadmap.md` Appendix A holds the
  metric/evaluation plan and is explicitly not a work queue.
- **The def-use census is not in the loop people iterate in, so a signature
  change ships without it.** The gate list anyone actually types while working
  (`dectest @o0 @o2` plus the fixture/structural/arch tests) never touches
  `test_decompiler_defuse_census.py`, because `dectest` is not pytest. Any change that alters a
  RECOVERED SIGNATURE -- argument arity, parameter type, return type -- changes
  the emitted body and therefore the undefined-read count, and it will not show
  up until someone runs the census by hand. On 2026-08-19 an arity fix
  (`11d55613`) moved `rustc:O0` +20 and `rustc:O2` +12 and shipped with the
  baseline unrefreshed; it took three A/B experiments to attribute, because two
  later changes were suspected first and each took a full build to exonerate.
  Run `uv run pytest python/tests/test_decompiler_defuse_census.py -q`
  alongside the other gates whenever prototypes can move. (**Correction,
  2026-08-31:** this bullet used to say the census "needs `-m ''` to run at
  all". It does not, and has not for as long as `pytest.ini` has deselected
  only `decbench` — verified by collecting it, which finds 6 tests. The real
  gap is the bullet's second half: iteration happens through
  `tools/dectest.py`, which is not pytest and never touches the census.)
- **Run `tools/build_guard.py` before EVERY baseline regeneration.** A baseline
  written against a stale `.so` records the old behaviour under the new commit,
  and nothing downstream can tell. On 2026-08-19 a measurement sequence that
  reverted source files to attribute a regression restored them **without
  rebuilding**; the next `gen_defuse_baseline.py` run measured the reverted
  binary, reported the committed numbers exactly, and declared two correctly
  attributed `--accept-regression` entries STALE. The guard names it precisely
  (`STALE: src/python_bindings/debug.rs is newer than the built extension`) --
  it just has to be run. Any workflow that does `git stash` / `git checkout --`
  on `src/` to measure a before-state MUST rebuild before the next measurement,
  in both directions.
- **`@o0` and `@o2` are HOST lanes only, so a code change can move cross-arch
  cells invisibly.** On 2026-08-19 commit `d1365bdb` shipped with `baseline.json`,
  `structural_baseline.json` and `defuse_baseline.json` refreshed and
  `arch_baseline.json` NOT refreshed, because `dectest @o0 @o2` reported exactly
  two improvements and both were host cells. Four further cells
  (`144_inline_asm` at `i386:{O0,O2}` and `x86_64_gcc15:{O0,O2}`) had also gone
  `fail -> pass` and were invisible to that command; a parallel agent found them
  by running `--arch` on a pristine build of that same commit. This is NOT the
  new-fixture case the bullet below covers — no fixture was added, and the
  three host baselines were correctly refreshed. Any change to a lifter, the
  renderer or ABI code needs `dectest @o0 @o2 --arch i386 --arch armv7 --arch
  aarch64 --arch x86_64_gcc15` before it is called measured, and
  `arch_baseline.json` refreshed with the other three. **The selectors are not
  optional.** `--arch` *retargets whatever selectors you gave*; with none, it
  retargets the default `@smoke`. On 2026-08-20 the command as this bullet used
  to spell it reported `SCOPED: 16 lanes of 3078 (1%) — no regressions in scope`
  — a green result over one half of one percent of the matrix, in a form that
  reads exactly like the real gate.
- **Extend `tests/decompiler_fixtures/` when a shape has no lane.** A new numbered
  fixture plus a `manifest.py` contract is cheap and permanent; adding one requires
  refreshing **four** baselines: `baseline.json`, `structural_baseline.json`,
  `arch_baseline.json`, and `defuse_baseline.json`. The last one is easy to miss
  because its lane is `slow`-marked, so a scoped `dectest` run and the three
  ordinary baseline gates all stay green while the full suite fails — that is
  exactly how fixtures 195 and 196 reached `master` with a red census.
- **`maturin develop` builds DEBUG, and the shares in a debug profile are not
  the shares you ship.** The workflow above installs `target/debug` (276 MB
  against 974 KB for release), so every Python-side measurement runs
  unoptimized code. Profiled on `/usr/bin/bash`, the two builds disagree
  completely: SIMD/`memchr` scanning is 12.7% in debug and **0.5%** in release;
  the allocator is 6.5% in debug and **26.2%** in release — sixth place versus
  first. An afternoon of optimisation targets was picked off the debug profile
  before anyone checked. Use `uv run maturin develop --release` for anything
  you intend to measure, and say which build a number came from.
- **A split has SIX side files, not four.** Beyond the four fixture baselines
  and the two this file already names, `python/tests/test_stranded_doc_comments.py`
  holds `REVIEWED_DOC_SUMMARIES`, ALSO keyed by file path — moving a registered
  doc summary into a new module silently orphans its key. Three of four splits
  on 2026-08-31 tripped it. `test_src_dependency_boundaries.py`'s env-var
  allowlist has the same shape and the same failure.
- **The structural gates are the ones an optimisation loop never runs.** On
  2026-08-31 seven tests were red on pushed `master` for hours -- the fitness
  ratchet, the large-module review, the env-var allowlist and the stranded-doc
  check -- while `cargo test --features python-ext`, `dectest @o0 @o2` and a
  byte-identity sweep over 419 binaries all stayed green the entire time. Those
  gates ask whether the CODEBASE is healthy, not whether the decompiler is
  correct, so nothing in a perf or fixture loop touches them. After any commit
  touching `src/`, run `uv run pytest python/tests/` in full, not the subset.
- **`perf` works here — check the sysctl before hand-rolling timers.**
  `kernel.perf_event_paranoid` ships at `4` on this box and `ptrace_scope` at
  `1`, so `perf record` and gdb attach both fail. Passwordless sudo is
  available: `sudo sysctl -w kernel.perf_event_paranoid=1 kernel.yama.ptrace_scope=0`
  (runtime only; a reboot restores the defaults). Four agents built hand-rolled
  phase timers before anyone checked. The first real profile immediately
  surfaced things none of the timers had: SipHash at 7.8%, ~11% in
  `memmove`/`memcmp`, and `copy_prop::reads::count_reg_uses` as the largest
  single project function at 8.40%.
- **`perf` self-time can be badly wrong for allocation-driven costs.** It put
  `disasm::iced` at 2.2% of a discovery profile, and the decoder still turned
  out to be worth fixing — its cost was the 12–16 `malloc`/`free` pairs it
  *drove* per instruction, charged to libc, which was **47.5%** of that same
  profile. Count allocations with a `GlobalAlloc` when the suspicion is
  allocation churn; the sampling profiler will say "don't bother".
- **Do not read a size curve through `Throughput::Bytes`.** A four-rung ladder
  reported CFG discovery at `n^2.13`; the rungs differed 32x in instructions per
  file byte, and against instructions decoded the exponent is 0.97. A 12.8 MB
  fixture finishes faster than a 359 KB one because 12.5 MB of it is DWARF.
  Pick the denominator the work is actually proportional to.
- **`git stash` writes a repository-SHARED ref, across worktrees.** Two agents
  in separate worktrees raced a push/pop and swapped each other's changes; both
  recovered from dangling commits, but only because both happened to notice.
  Use `git diff > patch` / `git apply [-R]` for A/B measurements instead.
- **`cargo fmt -- <files>` ignores the file list and formats the whole crate.**
  It has twice reformatted files owned by other concurrent work. Use
  `rustfmt --edition 2021 <file>` for a single file, and check `git status`
  after.
- **Nothing this project does may write to `/tmp`. Export `TMPDIR` first:**

  ```bash
  export TMPDIR="$HOME/.cache/glaurung/tmp"   # on /, ~466 GB; /tmp is a 62 GB quota'd tmpfs
  mkdir -p "$TMPDIR"
  ```

  This is not only about `mktemp`. **`maturin develop` writes its wheel to
  `/tmp`** on every rebuild — a dozen a session — and `cargo`, `pytest` and the
  fixture harness all default there too. Verified 2026-08-20: with `TMPDIR` set,
  the wheel lands in the cache directory and `/tmp` gains *zero* entries.

  `/tmp` here is a **shared, per-user-quota'd tmpfs**, so it exhausts long before
  `df` shows full and it is not ours alone. When it fills, it never says "disk
  full". It has surfaced as a plausible assertion failure in a DecBench test; as
  eight fake `pass->fail` "SEMANTIC REGRESSIONS" in the fixture matrix at 13 GB
  free; as a pytest `INTERNALERROR` from `OSError: [Errno 122]` inside
  `terminal.py` `flush()` that **reported exit code 0 with no test results**; and
  twice as the Bash tool dying completely, every command returning nonzero with
  no output including `echo`. A successful `Write` is the liveness probe that
  tells that apart from a bad command.

  Sweeping is triage, not the fix — and sweep only what is *ours*. On 2026-08-20
  the 33 GB under `/tmp/claude-1000` was overwhelmingly other projects' session
  data while this session's own directory was 6.5 MB. Do not delete another
  tenant's work to make a test run; say so and ask.

## LLM model policy (project-critical — keep in sync with `python/glaurung/llm/config.py`)

Every LLM code path (`glaurung ask`, `name-func`, `windows analyst`, the L2
critic, L3 CWE sweep, L1 findings runner) defaults to:

- **Model:** `openai:gpt-5.4-mini`
- **OpenAI service tier:** `flex`
- Fallback: `anthropic:claude-haiku-4-5`

Wired in `LLMConfig` (`default_model`, `summarizer_model`, `risk_scorer_model`,
`ioc_model`, `openai_service_tier`). `ModelHyperparameters.to_model_kwargs(model_name=…)`
auto-adds `extra_body={"service_tier": …}` for `openai:` models when tier ≠ `default`.

Env overrides: `GLAURUNG_LLM_MODEL`, `GLAURUNG_OPENAI_SERVICE_TIER`
(`flex` | `default` | `priority`).

**Do NOT swap model families to dodge limits:**

- Hitting OpenAI's **128-tool cap** (`Invalid 'tools': array too long…`) is what
  L5 routing exists to solve. Use `--route` (deterministic intent router, ≤30
  tools/question), `tool_filter={…}` in `register_analysis_tools`, or
  `GLAURUNG_AGENT_ROUTE=1`. **Don't** fall back to Anthropic.
- Hitting Anthropic's 4M-tokens/min ceiling → lower `max_parallel` in
  `sweep_binary` (default 1), don't change model family.
- One-off heavier interactive runs may pass `--model anthropic:claude-opus-4-7`
  (or any `provider:model`); the default stays `gpt-5.4-mini` for batched/automated work.

## Custom agents

`.claude/agents/rust-data-model-creator.md` — subagent for adding a new
Rust+PyO3 data model following `docs/architecture/data-model.md` patterns.

## Map of the docs

`docs/` holds the detailed reference: `guides/`, `reference/`, `architecture/`,
`decisions/`, `design/`, `tutorial/`, `development/`, and `history/` (dated
record, not current guidance). Check there before reinventing context.
