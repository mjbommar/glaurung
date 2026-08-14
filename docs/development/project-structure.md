# Project structure

> **Status: maintained repository map.** The map describes the current source
> tree; `src/lib.rs`, `pyproject.toml`, and the filesystem remain authoritative.

Glaurung is a mixed Rust/Python project. Rust implements the native analysis
engine; Python exposes the scripting, CLI, knowledge-base, and LLM surfaces.

## Top-level layout

```text
glaurung/
├── src/                 Rust library and PyO3 bindings
├── python/glaurung/     Python package
├── python/tests/        Python test suite
├── tests/               Rust integration tests and binary fixtures
├── samples/             Real and synthetic sample binaries
├── data/                Shipped signatures and type/prototype data
├── docs/                User, architecture, design, and development docs
├── scripts/             Repository workflows and regression gates
├── tools/               Focused developer and decompiler tools
├── fuzz/                cargo-fuzz targets
├── reference/           Checked-in projects used for architecture research
├── Cargo.toml           Rust package and feature definitions
├── Cargo.lock           Locked Rust dependency graph
├── pyproject.toml       Python packaging, dependencies, and Maturin settings
├── uv.lock              Locked Python dependency graph
├── README.md            User-facing project overview
├── CLAUDE.md            Hand-maintained development and model policy
└── LICENSE              Apache-2.0 license
```

Build products such as `.venv/` and `target/` are local and ignored by Git.
Generated analysis databases normally use the `.glaurung` extension.

## Rust core

`src/lib.rs` is the library entry point. Major subsystems under `src/` include:

- `triage/` for bounded first-touch analysis;
- `formats/`, `disasm/`, `analysis/`, and `symbols/` for binary recovery;
- `ir/` for LLIR, lifting, optimization, structuring, and pseudocode rendering;
- `exec/` and `symbolic/` for concrete and opt-in symbolic execution; and
- `python_bindings/` for the PyO3 surface exposed as `glaurung._native`.

The exact module list evolves; `src/lib.rs` and `Cargo.toml` are authoritative.

## Python package

`python/glaurung/` contains:

- `cli/` and `cli/commands/` for the `glaurung` console script;
- `llm/` for model configuration, agents, tools, and usage controls;
- `python/glaurung/llm/kb/` for SQLite-backed persistent project workflows;
- format- and analysis-specific Python helpers; and
- `_native.pyi`, `triage.pyi`, and `py.typed` for the native typing surface.

The console entry point is declared in `pyproject.toml` as
`glaurung = "glaurung.cli:main"`.

## Tests and fixtures

- Rust unit tests live next to their modules; integration tests live in
  `tests/`.
- Python tests live in `python/tests/`.
- `samples/` contains binaries used by examples, tutorials, and benchmarks.
- `tests/decompiler_fixtures/` and `tests/decbench_corpus/` contain decompiler
  regression material.

Use real checked-in fixtures rather than inventing mock binary data. See
[`../../samples/README.md`](../../samples/README.md) and
[`../../tests/decompiler_fixtures/README.md`](../../tests/decompiler_fixtures/README.md)
for the corpus-specific contracts.

## Build configuration

- `Cargo.toml` defines Rust dependencies and opt-in features.
- `pyproject.toml` declares Python 3.11+, runtime/development dependencies,
  the console script, and the `glaurung._native` Maturin module.
- `uv.lock` and `Cargo.lock` make source builds reproducible.
- `pytest.ini` contains the active pytest configuration.

## Getting started

The repository-wide modularization work is organized as independently gated
mini-projects in the [architecture refactoring portfolio](../refactoring/README.md).
Those plans supplement the source-tree map; they do not describe already
completed moves.

```bash
uv sync --locked --dev
uv run glaurung --help
```

After a Rust change:

```bash
uv run maturin develop
```

See [setup.md](setup.md) for prerequisites, clean-room validation, build
profiles, tests, and runtime configuration.
