# §A — Install

Goal: build Glaurung from source and verify the native extension with a real
sample binary.

## Prerequisites

- CPython 3.11 or newer.
- Rust 1.88 or newer.
- Git, a C compiler/linker, and
  [uv](https://docs.astral.sh/uv/getting-started/installation/).

Glaurung is not currently published on PyPI. Do not use
`pip install glaurung`; use a source checkout:

```bash
git clone https://github.com/mjbommar/glaurung.git
cd glaurung
uv sync --locked --dev
```

`uv sync` creates `.venv`, installs the locked Python dependencies, builds the
Rust extension through Maturin, and installs the package as an editable source
checkout.

## Verify the install

Use `uv run` so the command is executed in the project's environment:

```bash
uv run glaurung --version
uv run glaurung --help
uv run python -c "import glaurung; print(glaurung.__file__)"
```

The version command currently prints `glaurung 0.1.0`. The help output is the
authoritative list of commands; the list changes as the pre-1.0 CLI develops.

## Run a real smoke test

```bash
uv run glaurung kickoff \
  samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
```

The report should identify an x86-64 ELF and include function-discovery,
type-system, IOC, and completion sections. Exact function and stack-slot counts
are analyzer results, not installation invariants, and may change between
revisions.

For a smaller JSON-producing check:

```bash
uv run glaurung triage \
  samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2 \
  --json
```

## Optional LLM features

The deterministic tutorial sections need no API key. LLM-backed commands use
`openai:gpt-5.4-mini` with the `flex` service tier by default:

```bash
export OPENAI_API_KEY=your-key
uv run glaurung ask \
  samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2 \
  --route -a "What does this binary do?"
```

You may put the key in a `.env` file in the checkout instead. Do not commit the
file. To select Anthropic explicitly, set `ANTHROPIC_API_KEY` and pass a model
such as `--model anthropic:claude-haiku-4-5`.

## Troubleshooting

**`glaurung: command not found`** — use `uv run glaurung ...`, or run
`source .venv/bin/activate` before invoking `glaurung` directly.

**Native extension import/build failure** — confirm that `rustc --version`
reports 1.88 or newer and that a C compiler/linker is installed. Then rerun
`uv sync --locked --dev`.

**A sample path does not exist** — run commands from the repository root. The
sample corpus is part of the source checkout.

**Python still shows behavior from before a Rust change** — rebuild the native
extension with `uv run maturin develop`.

The complete prerequisite list, Docker clean-room recipe, wheel commands,
quality gates, and runtime configuration reference are in
[Installation, development setup, and configuration](../../development/setup.md).

## Next: §B — First binary

The remaining tutorial chapters use the shorter `glaurung ...` command form.
Activate the environment once before continuing:

```bash
source .venv/bin/activate
glaurung --version
```

If you prefer not to activate it, prepend `uv run` to each command instead.

Continue to [§B — First binary](first-binary.md).
