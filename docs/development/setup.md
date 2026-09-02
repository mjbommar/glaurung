# Installation, development setup, and configuration

> **Kind:** guide · **Status:** maintained

This is the supported setup reference for a source checkout of Glaurung.
Commands are written for a POSIX shell and should be run from the repository
root unless noted otherwise.

## Installation status

Glaurung is not currently published on PyPI. `pip install glaurung` therefore
is not a supported installation path. Build from a Git checkout with `uv` and
the Rust toolchain.

The project produces a platform-specific CPython extension. The clean-room
workflow below was validated on Linux x86-64 with Debian 12, CPython 3.11, and
Rust 1.88. Native macOS and Windows builds may require the corresponding
platform compiler tools and are not covered by that Linux validation.

## Prerequisites

- Git.
- CPython 3.11 or newer, as declared by `pyproject.toml`.
- Rust 1.88 or newer. `gimli 0.33`, a direct dependency, requires Rust 1.88.
- A C compiler and linker. On Linux, install the distribution's basic build
  toolchain (`build-essential` on Debian/Ubuntu).
- [uv](https://docs.astral.sh/uv/getting-started/installation/).

Check the tools that matter:

```bash
python3 --version
rustc --version
cargo --version
uv --version
```

## Source install

```bash
git clone https://github.com/mjbommar/glaurung.git
cd glaurung
uv sync --locked --dev
uv run glaurung --version
uv run glaurung --help
```

`uv sync --locked --dev` does four things:

1. creates or updates `.venv`;
2. installs the versions in `uv.lock` without changing the lockfile;
3. builds the Rust extension through Maturin; and
4. installs Glaurung and its development dependencies into `.venv`.

Use `uv run COMMAND` from the repository root. Alternatively, run
`source .venv/bin/activate` once and then invoke installed commands directly.

Verify both the native package and a real analysis path:

```bash
uv run python -c "import glaurung; print(glaurung.__file__)"
uv run glaurung triage \
  samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2 \
  --json
uv run glaurung kickoff \
  samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
```

The triage result should identify an x86-64 ELF. The kickoff report should
contain format, architecture, function-discovery, type-system, and completion
sections. Exact counts can change as analyzers improve, so they are not an
installation invariant.

## Building and rebuilding

Python-only changes are visible immediately in the editable install. Rebuild
after every Rust change:

```bash
uv run maturin develop
```

For optimized local behavior:

```bash
uv run maturin develop --release
```

Build a release wheel without installing it:

```bash
uv run maturin build --release
```

Maturin writes wheels under `target/wheels/`. Wheels are specific to the
selected OS, CPU architecture, and Python ABI; building one is not equivalent
to publishing it.

Optional Rust features are off unless selected. For example, the concrete
execution engine is included by the normal Python build, while symbolic
execution must be requested explicitly:

```bash
uv run maturin develop --features python-ext,symbolic
```

When passing `--features`, include `python-ext`: Maturin treats the CLI feature
list as a replacement for the `[tool.maturin].features` list rather than an
addition to it.

Some solver and differential-oracle features require additional native
libraries. Their authoritative feature definitions are in `Cargo.toml`; see
[the execution-engine decisions](../decisions)
and [Axeyum integration documentation](../architecture/solver-backends.md) before
enabling them.

## Tests and quality gates

Use the smallest relevant test while iterating, then run the complete gates
before claiming a change is finished:

```bash
# Rust. The feature is NOT optional here: `src/python_bindings/` sits behind
# `python-ext` (`src/lib.rs`), so a bare `cargo test` skips ~120 tests and never
# compiles that tree — a green result over code it did not build. Since
# `python_bindings/ir.rs` is the real pipeline entry point, most passes are only
# reachable through it.
cargo test --features python-ext

# Python
uv run pytest python/tests/

# Formatting, lint, and types
uvx ruff format --check python/
uvx ruff check python/
uvx ty check python/
```

To apply Python formatting, replace `ruff format --check` with
`ruff format`. Use `uvx ruff check python/ --fix` only when you have reviewed
the affected scope.

`pytest-cov` is not part of the locked development group. Run it in an
isolated, disposable environment when coverage is needed:

```bash
uv run --isolated --with pytest-cov pytest \
  -p pytest_cov.plugin \
  --cov=python/glaurung \
  python/tests/
```

After changes to Rust code used by Python, run `uv run maturin develop` before
Python tests. Decompiler work has additional focused and broad gates in
[decompiler-testing.md](decompiler-testing.md).

## Reproduce the clean-room install with Docker

The following command copies the checkout into a disposable Debian container,
excluding host build products, and runs the real locked install plus smoke
tests. It deliberately mounts the checkout read-only so container work cannot
modify the host tree.

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  rust:1.88-bookworm \
  bash -c '
    set -euxo pipefail
    export PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin
    apt-get update
    apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates curl git build-essential
    curl -LsSf https://astral.sh/uv/install.sh | \
      env UV_INSTALL_DIR=/usr/local/bin sh
    mkdir /work
    tar -C /workspace \
      --exclude=.git --exclude=.venv --exclude=target \
      --exclude=reference --exclude=out \
      -cf - . | tar -C /work -xf -
    cd /work
    uv sync --locked --dev
    uv run glaurung --version
    uv run python -c "import glaurung; print(glaurung.__file__)"
    uv run glaurung triage \
      samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2 \
      --json
    uv run glaurung kickoff \
      samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
  '
```

This downloads dependencies and compiles the native extension, so the first
run is intentionally not an offline test. Use a pinned image digest as well as
the checked-in `uv.lock` when an immutable CI environment is required.

## Runtime configuration

### Configuration precedence

Most command behavior follows this order, from highest to lowest priority:

1. explicit command-line argument;
2. a subsystem-specific config file, where supported;
3. environment variable; and
4. built-in default.

Always check `uv run glaurung COMMAND --help` for command-specific flags.
Glaurung does not currently have one global user configuration file.

### LLM providers, models, and budgets

LLM-backed commands are optional. The deterministic CLI does not require an
API key. `python-dotenv` searches the current directory and its parents for a
`.env` file when the LLM configuration module loads; existing environment
variables take precedence over values in that file.

| Variable | Purpose | Default |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI credential | unset |
| `ANTHROPIC_API_KEY` | Anthropic credential | unset |
| `GOOGLE_API_KEY` or `GEMINI_API_KEY` | Google/Gemini credential | unset |
| `GLAURUNG_LLM_MODEL` | Default `provider:model` | `openai:gpt-5.4-mini` |
| `GLAURUNG_OPENAI_SERVICE_TIER` | OpenAI tier (`flex`, `default`, or `priority`) | `flex` |
| `GLAURUNG_LLM_TEMPERATURE` | Model temperature | `0.3` |
| `GLAURUNG_REQUEST_LIMIT` | Requests per agent run | `12` |
| `GLAURUNG_INPUT_TOKENS_LIMIT` | Input-token ceiling | `400000` |
| `GLAURUNG_TOTAL_TOKENS_LIMIT` | Total-token ceiling | `500000` |
| `GLAURUNG_MAX_OUTPUT_TOKENS` | Per-request output ceiling | `32768` |

Example `.env`:

```dotenv
OPENAI_API_KEY=replace-me
GLAURUNG_LLM_MODEL=openai:gpt-5.4-mini
GLAURUNG_OPENAI_SERVICE_TIER=flex
```

Do not commit credentials. Where available, a command's `--model` option
overrides `GLAURUNG_LLM_MODEL`. Invalid numeric budget values are ignored with
a warning; provider errors remain runtime errors.

Detailed agent-run reproducibility and budget policy is in
[Model configuration and budgets](../design/agentic-source-recovery/operations/01-model-configuration-and-budgets.md).

### Analysis limits and caches

| Variable | Purpose |
|---|---|
| `GLAURUNG_MAX_FILE_SIZE` | Raise the default file-size cap for triage-backed commands |
| `GLAURUNG_MAX_READ_BYTES` | Raise the default read cap for triage-backed commands |
| `GLAURUNG_CACHE_DIR` | Append-only decompile/name-function cache when the command supports it |
| `GLAURUNG_PDB_CACHE` | Microsoft-style PDB cache directory |
| `_NT_SYMBOL_PATH` | Fallback local PDB cache discovery |
| `GLAURUNG_TYPES_DIR` | Override the generated type/prototype data directory |
| `GLAURUNG_FLIRT_LIB` | Override the default FLIRT-lite signature file |
| `GLAURUNG_JVM_TOOLS_JAR` | Override the optional JVM helper JAR path |

The two global size variables only raise the effective limits; use explicit
CLI flags to request a smaller bound. The operation cache has no eviction or
size limit and must be cleared manually if it grows too large.

### Windows analysis YAML

The shared PE/PDB configuration resolves in this order:

1. `--analysis-config PATH`;
2. `GLAURUNG_WINDOWS_ANALYSIS_CONFIG`;
3. `.glaurung/windows-analysis.yaml`; and
4. built-in defaults.

Unknown keys fail closed with `ValueError`. See
[Windows Analysis Config](../reference/windows-analysis-config.md) for the
schema and current Windows workflow.

### Triage and advanced execution settings

Packer weights are configured through the Python API; see
[Packer Configuration](../reference/packer-config.md). Symbolic solver, Axeyum,
decompiler-debug, and benchmark-only environment variables are specialized
developer controls and are documented with their owning subsystem rather than
treated as general user configuration.

## Troubleshooting

### `glaurung: command not found`

Run `uv run glaurung ...` from the checkout, or activate `.venv` first:

```bash
source .venv/bin/activate
glaurung --version
```

### Native extension import or build failure

Confirm that Python, Rust, and the linker are available, then rebuild:

```bash
python3 --version
rustc --version
cc --version
uv sync --locked --dev
uv run maturin develop
```

Rust older than 1.88 is unsupported by the current dependency graph.

### Sample path does not exist

The sample corpus is in the Git checkout, not in a future wheel. Run examples
from the repository root and check `samples/README.md` for corpus layout and
generation details.

### Python behavior does not reflect a Rust change

The `.so` is stale. Run `uv run maturin develop`, then repeat the Python command.
For decompiler work, `tools/build_guard.py` performs the repository's explicit
freshness check.
