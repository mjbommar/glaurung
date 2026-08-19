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
- **Don't claim "done" without running tests + ruff + ty.**
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
- **`--features python-ext` does not build `src/symbolic/` either, and that is
  ten times bigger.** `src/lib.rs:65` is `#[cfg(feature = "symbolic")]`, and
  `symbolic` is in neither `default` nor `python-ext`. **21 files, 14,649 product
  LOC — 8.6% of the tree — that `cargo test --features python-ext` never
  compiles.** Proven by experiment on 2026-08-17: appending invalid Rust to
  `src/symbolic/expr.rs` gives 0 errors under `--features python-ext` and 2 under
  `--features symbolic`. This is how all three SMT solver backends sat
  uncompilable for seventeen days (`BinOp::LogicalAnd`/`LogicalOr` added
  2026-07-31, no backend updated) and how `triage-parsers-extra` stayed broken
  for 350 days.
- **Before pushing anything that touches a feature-gated tree, run
  `scripts/feature-build-gate.sh`** — 11 `cargo check --all-targets` lanes,
  ~4m30s, exit 1 on any failure. It is the only thing in the repository that
  builds `solver-*`, `symbolic`, `exec`, `dev-oracle` or
  `triage-parsers-extra`. Note `scripts/lint-rust.sh` DOES run
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
  renderer or ABI code needs `dectest --arch i386 --arch armv7 --arch aarch64
  --arch x86_64_gcc15` before it is called measured, and `arch_baseline.json`
  refreshed with the other three.
- **Extend `tests/decompiler_fixtures/` when a shape has no lane.** A new numbered
  fixture plus a `manifest.py` contract is cheap and permanent; adding one requires
  refreshing **four** baselines: `baseline.json`, `structural_baseline.json`,
  `arch_baseline.json`, and `defuse_baseline.json`. The last one is easy to miss
  because its lane is `slow`-marked, so a scoped `dectest` run and the three
  ordinary baseline gates all stay green while the full suite fails — that is
  exactly how fixtures 195 and 196 reached `master` with a red census.
- **Never `mktemp -d -t glaurung-...` in `/tmp`.** Use the session scratchpad
  directory. Ad-hoc `/tmp` scratch is never cleaned up: on 2026-08-13 there were
  663 abandoned `glaurung-<topic>.XXXXXX` directories totalling 13 GB from past
  sessions. A full `/tmp` does not fail as "disk full" — it surfaced as a
  plausible assertion failure in a DecBench test, then as `OSError: [Errno 122]
  Disk quota exceeded` mid-baseline, and it took the Bash tool down entirely for
  an hour. Infrastructure exhaustion wearing a product defect's clothes costs far
  more to diagnose than to prevent.

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
Rust+PyO3 data model following `docs/data-model/` patterns.

## Map of the docs

`docs/` holds the detailed reference: `cli/`, `llm/`, `architecture/`, `design/`,
`windows-port/`, `campaigns/` (worklog of analysis efforts), `tutorial/`,
`development/project-structure.md`. Check there before reinventing context.
