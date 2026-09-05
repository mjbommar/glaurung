# Glaurung

![Glaurung logo](assets/glaurung-logo-512px.png)

Glaurung is a pre-1.0 reverse-engineering framework with a Rust analysis core,
Python bindings, a command-line interface, persistent SQLite project files,
and optional LLM-assisted workflows.

The project is under active development. It is useful today for automated
binary triage and analysis, but it is not yet a drop-in replacement for mature
interactive tools such as Ghidra or IDA Pro. In particular, decompiler output
is still experimental and should be checked against disassembly and runtime
behavior.

## What works today

- ELF, PE/COFF, and Mach-O triage, including symbols, strings, IOCs, entropy,
  packer signals, and common hardening metadata.
- Bounded disassembly for x86/x86-64, ARM/ARM64, and RISC-V. The decompiler
  currently lifts x86/x86-64 and ARM/ARM64; RISC-V is disassembly-only.
- Function discovery, control-flow graphs, call graphs, cross-references,
  stack-frame analysis, type propagation, DWARF ingestion, and PE/PDB support.
- C-like pseudocode through a developing LLIR/SSA/AST pipeline.
- Persistent `.glaurung` project databases for names, comments, labels, types,
  prototypes, xrefs, stack variables, bookmarks, and journal entries.
- A pure-Rust C source front end, with per-function complexity, nesting, size
  and Halstead metrics through `glaurung.source` and `glaurung source-metrics`.
  No JVM and no subprocess, and no input raises: a file that only partly parses
  reports the functions it did recover. See
  [source metrics](docs/reference/source-metrics.md).
- A CLI and Python API for scripting, plus optional PydanticAI agents for
  question answering, naming, vulnerability review, and source recovery.

Run `uv run glaurung --help` for the authoritative command list.

## Install from source

Glaurung is not currently published on PyPI. A source build requires:

- Git;
- CPython 3.12 or newer;
- Rust 1.88 or newer; and
- a native C compiler and linker.

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```bash
git clone https://github.com/mjbommar/glaurung.git
cd glaurung
git lfs install && git lfs pull
uv sync --locked --dev
uv run glaurung --version
```

The `git lfs` step is not optional: the checked-in sample binaries are Git LFS
objects, so without it every path under `samples/` is a small text pointer file
rather than a binary, and the first-analysis commands below fail.

`uv sync` creates `.venv`, resolves the checked-in lockfile, builds the Rust
extension, and installs the Python package. Use `uv run ...` from the repository
root so commands run in that environment without manually activating it.

For platform packages, wheel builds, optional Rust features, and a reproducible
Docker clean-room check, see [the development setup guide](docs/development/setup.md).

## First analysis

The repository includes real sample binaries, so no API key or external tool is
needed for this smoke test:

```bash
SAMPLE=samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2

uv run glaurung triage "$SAMPLE"
uv run glaurung triage "$SAMPLE" --json
uv run glaurung kickoff "$SAMPLE"
uv run glaurung decompile "$SAMPLE" --func main --style c
```

`triage` performs a fast first pass. `kickoff` runs the deeper deterministic
pipeline and uses a temporary project unless `--db PATH` is supplied:

```bash
uv run glaurung kickoff "$SAMPLE" --db hello.glaurung
uv run glaurung repl "$SAMPLE" --db hello.glaurung
```

Other useful entry points include:

```bash
uv run glaurung strings "$SAMPLE"
uv run glaurung symbols "$SAMPLE"
uv run glaurung graph "$SAMPLE" callgraph > callgraph.dot
uv run glaurung detect-packer "$SAMPLE"
```

Every command has focused help, for example
`uv run glaurung decompile --help`. The guided walkthrough starts at
[Tutorial §A — Install](docs/tutorial/01-getting-started/install.md).

## Python API

```python
from glaurung import triage

sample = "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2"
artifact = triage.analyze_path(sample)

if artifact.verdicts:
    verdict = artifact.verdicts[0]
    print(str(verdict.format), str(verdict.arch), verdict.bits)
print(artifact.entropy.overall if artifact.entropy else None)
```

Run it inside the project environment:

```bash
uv run python example.py
```

For repeated decompiler queries, retain one immutable program session so exact
discovery and rendered artifacts can be reused safely:

```python
import glaurung as g

session = g.ir.DecompilerSession(sample)
functions, _ = g.analysis.analyze_functions_path(sample)
entry = int(functions[0].entry_point.value)
print(session.decompile_at(entry, style="decbench"))
print(session.artifact_cache_stats)
```

The cache key includes the function address, every discovery budget, type/style
options, and normalized architecture address. Diagnostic runs and PDB overlays
bypass rendered-output reuse so current evidence is never hidden by a cache hit.

## Configuration

Deterministic analysis needs no credentials. Resource limits are normally set
with command-line flags such as `--max-file-size`, `--max-read-bytes`,
`--max-functions`, and `--timeout-ms`; consult the selected command's `--help`
because not every command exposes every limit.

LLM-backed commands default to `openai:gpt-5.4-mini` with OpenAI's `flex`
service tier. Set `OPENAI_API_KEY` in the environment or in a `.env` file in
the working directory (or one of its parents). Override the model with
`--model provider:model` where the command supports it, or globally with
`GLAURUNG_LLM_MODEL`. Anthropic and Google credentials are also supported for
explicitly selected models.

```bash
export OPENAI_API_KEY=your-key
export GLAURUNG_LLM_MODEL=openai:gpt-5.4-mini
export GLAURUNG_OPENAI_SERVICE_TIER=flex

uv run glaurung ask "$SAMPLE" --route -a "What does this binary do?"
```

Never commit `.env` or API keys. The complete environment-variable reference,
configuration precedence, cache behavior, and Windows analysis YAML schema are
in [the setup guide](docs/development/setup.md#runtime-configuration).

## Development

After a Rust change, rebuild the extension before comparing Python-visible
behavior:

```bash
uv run maturin develop
```

The standard checks are:

```bash
cargo test --features python-ext
uv run pytest python/tests/
uvx ruff format --check python/
uvx ruff check python/
uvx ty check python/
```

`--features python-ext` is required rather than optional: a bare `cargo test`
does not compile `src/python_bindings/` at all.

[CLAUDE.md](CLAUDE.md) is the contributor policy — commands, gates, conventions,
and working style; [AGENTS.md](AGENTS.md) points other agent tooling at it.
[docs/development/testing-gates.md](docs/development/testing-gates.md) lists
every gate and which ones CI runs, and
[docs/development/decompiler-testing.md](docs/development/decompiler-testing.md)
covers the decompiler-specific loop.

## Documentation map

- [Documentation index](docs/README.md)
- [Installation and development setup](docs/development/setup.md)
- [Tutorial](docs/tutorial/README.md)
- [Executable examples](examples/README.md)
- [Analyst workflows](docs/guides/analyst-workflows.md)
- [Architecture](docs/architecture/README.md)
- [Decompiler output format](docs/reference/decompiler-output-format.md)
- [Windows analysis](docs/guides/windows-analysis.md)
- [Agentic source recovery](docs/design/agentic-source-recovery/README.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

Glaurung is a ground-up project, not a Ghidra plugin or extension.
