# CLAUDE.md — Glaurung

Rules and commands. The evidence is in `docs/development/`:
[traps.md](docs/development/traps.md) holds the incidents,
[testing-gates.md](docs/development/testing-gates.md) the gate-by-gate detail.

## What Glaurung is

A modern, **AI-native reverse-engineering framework** — "what Ghidra would look
like if built today." Rust core for performance and safety, exposed to Python
via PyO3, with an LLM agent (`pydantic-ai`) in the pipeline rather than bolted on.

- **Rust crate** (`src/`): `ir` (LLIR, AST, every decompiler pass — the largest
  tree by far), `analysis` (CFG, discovery, xrefs, jump tables), `disasm`
  (x86/x64, ARM/ARM64, MIPS, PPC, RISC-V), `formats` (ELF/PE/Mach-O), `program`
  (image/session/symbol ownership), `triage`, `symbols`, `debug` (DWARF),
  `demangle`, `flirt`, `strings`, `similarity`, `entropy`, `unpack`, `exec`
  (concrete emulator), `symbolic` (symbolic execution + SMT, own feature). The
  decompiler lifts x86/x86-64 and ARM/ARM64; the rest is disassembly-only.
- **Python package** (`python/glaurung/`): the PyO3 extension (`_native…so`),
  the `glaurung` CLI (`cli/commands/`), and the `llm/` agent subsystem — whose
  `llm/kb/` subpackage is the knowledge base. A Java/JVM front (`glaurung java`,
  `classfile`) parses `.class`/`.jar` and recovers source.
- **Knowledge base**: `.glaurung` SQLite files persist names, comments, labels,
  types, xrefs, stack vars, prototypes and bookmarks with `set_by` provenance,
  defined once in `python/glaurung/llm/kb/provenance.py`; **manual always wins**.

**Where the work is.** The frontier is decompiler correctness — structuring,
type/ABI recovery, lifters — verified by the test/gate/CI estate, with DecBench
scoring and performance adjacent. Windows, LLM routing, Java and symbolic
execution are built and parked, not active fronts.

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

## Commands

```bash
# FIRST, always. Nothing here may write to /tmp: it is a shared, quota'd tmpfs,
# and maturin, cargo, pytest and the fixture harness all default there.
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"

uv sync --locked --dev                  # deps + build the extension
git lfs install && git lfs pull         # samples are LFS objects, not files
uv run maturin develop                  # after ANY Rust change
uv run maturin develop --release        # ...and before measuring anything
uv run maturin build --release          # wheel

uv run glaurung --help                  # console script: glaurung = glaurung.cli:main
uv run glaurung triage <binary>
uv run glaurung kickoff <binary>        # full analysis → .glaurung KB

cargo test --features python-ext        # THE Rust command; bare `cargo test`
                                        # does not build src/python_bindings/
cargo test --features symbolic          # src/symbolic/, which the above skips
uv run pytest python/tests/             # Python suite
uv run pytest python/tests/test_x.py -xvs
uv run pytest python/tests/ -m core     # the tier needing nothing but the .so
uv run pytest python/tests/ -m decbench # OPT-IN: the tests that run the fork
uv run --isolated --with pytest-cov pytest -p pytest_cov.plugin \
  --cov=python/glaurung python/tests/   # coverage (pytest-cov is not locked)

# Decompiler: iterate small, gate big — docs/development/decompiler-testing.md
uv run python tools/build_guard.py                          # is the .so current?
uv run python tools/dectest.py 13_loop_early_exit:gcc:O0:bisect --show
uv run python tools/dectest.py @loops   # a named set; --list-sets to see them
scripts/decbench-local-gate.sh                              # our fixture lanes 1-3
scripts/decbench-local-gate.sh --decbench                   # + DecBench lanes 4-5

# Ten criterion benches: triage, entropy, strings, lang_detect, emulator
# (needs --features exec), ir_lift, ir_dataflow, ir_structure, analysis_cfg,
# decompile_pipeline
cargo bench --bench ir_lift             # ...one of the ten
uv run python fuzz/seed_corpus.py       # seed the 8 fuzz targets from our binaries
cargo fuzz run disasm_decode -- -max_total_time=120
uv run python -m glaurung.bench         # regression scorecard

uvx ruff format python/ && uvx ruff check python/ --fix && uvx ty check python/
uv run python tools/gen_native_stub.py            # after ANY binding change
uv run python tools/gen_native_stub.py --check    # exit 1 if stale
```

## Gates, and which ones CI runs

| Gate | Command | Protects | In CI? |
|---|---|---|---|
| Rust + bindings | `cargo test --features python-ext` | `src/` and `src/python_bindings/`, the real pipeline entry point | yes — `test-suite.yml` job `rust` |
| Symbolic | `cargo test --features symbolic` | `src/symbolic/`, which the other Rust builds never compile | yes — job `symbolic` |
| Python suite | `uv run pytest python/tests/` | everything Python-visible, incl. the structural gates | yes, tiered — jobs `python-core` (`-m core`) and `python-extended` |
| Lint / format | `uvx ruff format --check python/`, `uvx ruff check python/` | Python style | yes — job `lint` |
| Types | `uvx ty check python/` | Python types, incl. a lying `.pyi` | **no** — developer-only |
| Feature build gate | `scripts/feature-build-gate.sh` | 12 lanes: every feature configuration, incl. solvers and the separate `fuzz/` crate | yes — `feature-build-gate.yml` |
| Fixture matrix + structural | `pytest -m slow test_decompiler_fixture_{matrix,structural}.py` | `baseline.json`, `structural_baseline.json` | yes — `decompiler-fixtures.yml` |
| Cross-arch round trip | `tools/dectest.py @o0 @o2 --arch i386 --arch armv7 --arch aarch64 --arch x86_64_gcc15` | `arch_baseline.json` | **no** — by hand |
| Def-use census | `pytest python/tests/test_decompiler_defuse_census.py -q` | `defuse_baseline.json` | **no** — by hand |

The last two are what an iteration loop never reaches: `dectest` is not pytest,
and the census lane is `slow`-marked. `--arch` retargets whatever selectors you
gave, so passing none silently scopes it to `@smoke`. `perf-nightly.yml` fails
closed — exit 3 means *this run is not evidence*, never a pass. `dev-oracle` is
in no feature-gate lane (it needs libunicorn), so nothing builds it. Baseline
refresh commands: [testing-gates.md](docs/development/testing-gates.md).

## Conventions

- **Python tooling:** `uvx` for ephemeral tools, `uv add` for real deps. Use
  **`ruff`** (format + lint) and **`ty`** (types), both scoped to `python/`.
  **Never** mypy/pyright, black, pylint, flake8, isort, or `pip`; don't add
  `[tool.mypy]`/`[tool.black]`. Ruff's `target-version` and the classifiers
  track `requires-python`.
- **Rust:** `Result<T,E>` with `?` over `.unwrap()`; `///`/`//!` docs on public
  items; `unsafe` only with justification. Gate PyO3 with `#[cfg(...)]` +
  `#[pymethods]`, never `#[cfg_attr(..., pymethods)]`.
- **Naming:** snake_case fns/vars, PascalCase types/classes, UPPER_CASE consts.
- **Python style:** stdlib → third-party → local imports, absolute only; type
  hints on every public parameter and return; `pathlib`; Google-style
  docstrings; specific exceptions, never a bare `except:`.
- **Never hand-write a `.pyi`.** A stub shadows the module it describes, so a
  stale one makes `ty` confidently wrong. Generate it.

## Working style

This is a **real, production** tool used for actual binary analysis.

- **TDD.** Write or extend the test first. New analysis behavior needs a real
  fixture-backed test.
- **No mocks or fake data without explicit permission**, especially binary
  fixtures and analysis output. Use `samples/`, `tests/`, `tests/fixtures/`.
- **Surface results faithfully.** If a test failed or a step was skipped, say
  so. Don't claim "done" without running the gates above.
- **A number in a document is not a measurement; write the command next to the
  number.** Say which build it came from: `maturin develop` is DEBUG, and its
  profile shares are not the ones you ship.
- **Never run DecBench or Joern unless explicitly asked.**
  `tests/decompiler_fixtures/` is the corpus that proves a decompiler change
  sound; DecBench is an evaluation harness that costs tens of minutes and
  reports its own resource problems as cell failures. `pytest.ini` deselects
  `-m decbench`. `docs/development/roadmap/README.md`'s DecBench section holds
  the metric plan and is explicitly not a work queue.
- **A module split touches SIX side files:** the four fixture baselines
  (`baseline`, `structural_baseline`, `arch_baseline`, `defuse_baseline`), plus
  `test_large_module_review.py`'s `REVIEWED_LARGE_MODULES`,
  `test_stranded_doc_comments.py`'s `REVIEWED_DOC_SUMMARIES` and
  `test_src_dependency_boundaries.py`'s env-var allowlist — the last three keyed
  by file path. Adding a fixture needs the same four baselines.
- **Adding a CLI subcommand drifts a tutorial fixture.** Refresh with
  `uv run python scripts/verify_tutorial.py --chapter 01-install --capture` and
  read the diff; it should be the command list and nothing else.
- **After any commit touching `src/`, run the whole Python suite**, not the
  subset a decompiler loop touches.
- **`git diff > patch` / `git apply [-R]` for A/B measurements, not `git
  stash`** — the stash is a repository-shared ref across worktrees. And
  `rustfmt --edition 2021 <file>`, not `cargo fmt -- <file>`, which ignores the
  file list and formats the whole crate.

## LLM model policy (keep in sync with `python/glaurung/llm/config.py`)

Every LLM code path (`glaurung ask`, `name-func`, the L2 critic, the L3 CWE
sweep, the findings runner) defaults to **`openai:gpt-5.4-mini`** on OpenAI's
**`flex`** service tier, falling back to `anthropic:claude-haiku-4-5`. Wired in
`LLMConfig` (`default_model`, `summarizer_model`, `risk_scorer_model`,
`ioc_model`, `openai_service_tier`); `ModelHyperparameters.to_model_kwargs()` in
`llm/agents/base.py` adds `extra_body={"service_tier": …}` for `openai:` models
when the tier is not `default`. Env overrides: `GLAURUNG_LLM_MODEL`,
`GLAURUNG_OPENAI_SERVICE_TIER` (`flex` | `default` | `priority`).

**Do NOT swap model families to dodge limits.** OpenAI's 128-tool cap
(`Invalid 'tools': array too long…`) is what routing exists to solve: use
`--route` or `tool_filter={…}` in `register_analysis_tools`, don't fall back to
Anthropic. For an Anthropic tokens-per-minute ceiling, lower `max_parallel` in
`sweep_binary` (default 1). One-off heavy interactive runs may pass
`--model anthropic:claude-opus-4-7` (or any `provider:model`); the default stays
`gpt-5.4-mini` for batched work.

## Pointers

[docs/README.md](docs/README.md) is the documentation index. Under
`docs/development/`: [traps.md](docs/development/traps.md) (the incidents behind
the rules above), [testing-gates.md](docs/development/testing-gates.md) (every
gate and baseline refresh command),
[decompiler-testing.md](docs/development/decompiler-testing.md) (the iteration
loop), [contributing-docs.md](docs/development/contributing-docs.md) (doc kinds,
generators, evidence rules), and
[roadmap/README.md](docs/development/roadmap/README.md) (the live plan set,
whose DecBench section holds the metric plan, on demand only).
[.claude/agents/rust-data-model-creator.md](.claude/agents/rust-data-model-creator.md)
adds a Rust+PyO3 data model, following
[docs/architecture/data-model.md](docs/architecture/data-model.md).
