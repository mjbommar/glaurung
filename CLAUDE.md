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
# Build the Rust extension into the venv (do this after any Rust change)
maturin develop                 # or: maturin build --release
uv sync                         # Python deps

# Run the CLI (console script: glaurung = glaurung.cli:main)
uv run glaurung --help
uv run glaurung triage <binary>
uv run glaurung kickoff <binary>        # full analysis → .glaurung KB

# Tests
uvx pytest python/tests/                # Python suite (~345 test files)
uvx pytest python/tests/test_x.py -xvs  # one file, stop on first failure
cargo test                              # Rust suite (~125 test modules)

# Bench / regression scorecard
uv run python -m glaurung.bench

# Lint / format / types  (modern tools only — see below)
uvx ruff format python/
uvx ruff check python/ --fix
uvx ty check python/
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
- Surface real results faithfully (if a test fails or a step was skipped, say so).

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
