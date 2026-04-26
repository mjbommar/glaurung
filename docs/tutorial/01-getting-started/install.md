# §A — Install

Goal: a working `glaurung` on your `$PATH` and a fresh clone of the
sample corpus, in under five minutes.

## Prerequisites

- **Python ≥ 3.11.** Glaurung ships native bindings via maturin
  targeting CPython 3.11+.
- **A C toolchain** (gcc / clang) — needed for some sample-binary
  rebuild scripts but not for installing Glaurung itself.
- **Rust toolchain** — only required if you're building from source.

## Option 1 — From a release wheel (recommended once published)

> Status: PyPI publication is not yet wired up
> ([#241](../PLAN.md#functionality-requirements-summary-the-gap-list)).
> For now, build from source via Option 2.

```bash
pip install glaurung
glaurung --version
```

## Option 2 — From source (current path)

```bash
git clone https://github.com/mjbommar/glaurung.git
cd glaurung
uv sync
```

`uv sync` installs `glaurung` as an editable install and builds the
native extension via maturin. Wait for the build to finish (~30s on
first run).

Sanity check:

```bash
$ uv run glaurung --version
```

```text
glaurung 0.1.0
```

(Captured: [`_fixtures/01-install/version.out`](../_fixtures/01-install/version.out).)

If you get an `ImportError` instead, the native extension didn't
build — check that you have a Rust toolchain on `$PATH` and re-run
`uv sync`.

## Option 3 — Build the wheel manually

If you'd rather work outside `uv`:

```bash
git clone https://github.com/mjbommar/glaurung.git
cd glaurung
pip install maturin
maturin develop --release
glaurung --help
```

## Verify the install

```bash
$ uv run glaurung --help | head -3
```

```text
usage: glaurung [-h] [--version]
                {triage,strings,symbols,disasm,cfg,ask,decompile,name-func,repl,graph,detect-packer,diff,kickoff,patch,verify-recovery,export,undo,redo,xrefs,frame,strings-xrefs,view,find,bookmark,journal,classfile,luac} ...
```

(Captured: [`_fixtures/01-install/help-head.out`](../_fixtures/01-install/help-head.out).)

That's 27 subcommands. Every one is documented in
[`reference/cli-cheatsheet.md`](../reference/cli-cheatsheet.md).

## Run the kickoff smoke test

This is the one-liner that confirms the full pipeline works:

```bash
$ uv run glaurung kickoff \
    samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-c-clang-debug
```

```markdown
# Kickoff analysis — hello-c-clang-debug

- format: **ELF**, arch: **x86_64**, size: **17680** bytes
- entry: **0x1060**

## Functions
- discovered: **9** (with blocks: 9, named: 8)
- callgraph edges: **5**
- name sources: analyzer=9

## Type system
- stdlib prototypes loaded: **192**
- DWARF types imported: **0**
- stack slots discovered: **36**
- types propagated: **0**
- auto-struct candidates: **0**

## IOCs (from string scan)
- **path_posix**: 6
- **hostname**: 6
- **java_path**: 4
- **ipv4**: 0

_completed in N ms_
```

(Captured: [`_fixtures/01-install/kickoff-smoketest.out`](../_fixtures/01-install/kickoff-smoketest.out).)

You should see a markdown summary mentioning the format (ELF), arch
(x86_64), function count, and named-vs-unnamed ratio, finishing in
under a second. If it does, your install is healthy and you're
ready for [§B `first-binary.md`](first-binary.md).

If the smoke test errors out, see the [troubleshooting section](#troubleshooting).

## Optional: enable LLM features

Tiers 1-4 of this tutorial are 100% deterministic — no API key
required. **Tier 5** uses LLM-driven memory tools for chat-style
analysis. To enable:

```bash
export ANTHROPIC_API_KEY=...   # or OPENAI_API_KEY
glaurung ask samples/binaries/.../hello-clang-debug "what does this binary do?"
```

The agent has access to 50+ deterministic memory tools and writes
its findings to a citable evidence log. You can skip this section
entirely if you want LLM-free analysis only.

## Troubleshooting

**`glaurung: command not found`** — The `uv sync` flow installs into
the project's `.venv/`. Use `uv run glaurung ...` to invoke it
without sourcing the venv, or `source .venv/bin/activate` to put
it on `$PATH`.

**`ImportError: glaurung native extension`** — The Rust extension
didn't build. Check that `cargo --version` works and `rustc` is at
least 1.75. Re-run `uv sync` (or `maturin develop --release`).

**`samples/binaries/...` doesn't exist** — Make sure you ran
`git clone` and not `pip install` for the source path. The corpus
ships with the source tree, not the published wheel.

**Build is slow** — First-time `maturin develop --release` compiles
the Rust extension in release mode. Expect 1-2 minutes on a slow
laptop. Subsequent rebuilds are incremental and take seconds.

## Next: §B `first-binary.md`

You're installed. Now load a binary and run the full first-touch
pipeline.

→ [§B `first-binary.md`](first-binary.md)
