# Architecture

> **Kind:** architecture · **Status:** maintained

Glaurung is one Rust crate and one Python package. The crate does the analysis;
the package is the analyst-facing surface — a CLI, a persistent knowledge base,
and an LLM agent subsystem — and the two meet at a single PyO3 boundary.

This page is the orientation: what the two halves are, how bytes become
pseudocode, where the entry points are, and where every other architecture
document lives. Sizes and counts elsewhere in this directory carry the command
that produced them; this page carries the shape.

## The two halves

**`src/` — the Rust crate `glaurung`**, 489 files and 290,841 lines, built as
both an `rlib` and a `cdylib`. It owns everything that reads bytes: format
parsers, triage, disassembly, DWARF and PDB ingestion, CFG and function
discovery, the decompiler (57% of the crate on its own), a concrete emulator,
and an opt-in symbolic execution engine with pluggable SMT backends. The
compiled artifact is `glaurung._native`.

**`python/glaurung/` — the package**, 389 files and 158,956 lines. It owns the
`glaurung` console script and its 40 subcommands, the `.glaurung` SQLite
project file and its 35 tables, the LLM agent subsystem with its 219 registered
tools, and a thin typed layer over the extension. Almost none of it computes
over bytes; it orchestrates, persists and presents.

Read [`rust-crate-map.md`](rust-crate-map.md) and
[`python-package-map.md`](python-package-map.md) for what is in each, and
[`data-model.md`](data-model.md) for which representation belongs to which
layer — there is deliberately no single object graph shared across all of them.

## How bytes become pseudocode

```text
bytes on disk
   │
   ├─ triage ─────────── src/triage/  bounded, deterministic first touch:
   │                     sniff format, validate headers, entropy, packers,
   │                     containers, compiler and language detection.
   │                     Everything is budgeted; a budget that fires becomes
   │                     a diagnostic, not a silent truncation.
   │
   ├─ program image ──── src/program/  ProgramSession owns the parse, the
   │                     TargetSpec, the symbol store, the type store and the
   │                     reference resolver. Symbols arrive here from ELF/PE/
   │                     Mach-O tables, DWARF (src/debug/), PDB
   │                     (src/symbols/pdb.rs), gopclntab, CIL metadata and
   │                     FLIRT matching — each tagged with where it came from.
   │
   ├─ discovery ──────── src/analysis/cfg/  a 19-stage worklist: seeds from
   │                     entry points, PLT, PE tables and scanning; then walk,
   │                     control flow, extents, function construction, repair,
   │                     dispatch resolution. Completeness is tracked per
   │                     function, not assumed.
   │
   ├─ decompile ──────── src/ir/  lift to LLIR (x86/x86-64, ARM32, AArch64),
   │                     SSA, dataflow, memory objects, stack locals, call
   │                     arguments, type recovery, structuring, then AST
   │                     lowering and rendering. Rendered C is a view, never
   │                     an input back into recovery.
   │
   └─ surfaces ───────── the KB persists names, types, comments, xrefs and
                         frames with ranked provenance; the CLI presents;
                         the LLM tools read the same facts the CLI does.
```

Two things about that picture are load-bearing.

**It is one-way.** Nothing downstream feeds back upstream. The rule that
rendered C is a view and never an input to semantic recovery is what forbids
reading pretty output to decide a type or an edge, and it is stated as a
boundary in [`module-boundaries.md`](module-boundaries.md).

**Every stage reports incompleteness rather than hiding it.** A fired budget,
an unresolved indirect branch, an undecodable block and a missing symbol are
distinct outcomes with distinct representations. That is why
`src/analysis/completeness.rs` exists and why the structuring verifier must
account for every reachable edge.

## Entry points

There are three, and they are the places to start reading.

| surface | entry point | what it is |
|---|---|---|
| native → Python | `src/python_bindings/` (20 files, 10,511 lines) | `register_python_bindings` in `mod.rs` calls one registrar per subsystem in a fixed order. `ir.rs` holds the four decompiler entry points (`decompile_at`, `decompile_range_at`, `decompile_all`, `decompile_many`) and `ir/pipeline.rs` holds the AST pass order. Everything here is behind the `python-ext` feature. |
| command line | `python/glaurung/cli/main.py` | `_REGISTRY` maps a subcommand name to module and class **as strings**, and only the one being run is imported. `BaseCommand.add_common_arguments` adds the shared flags to every subcommand. |
| agents and tools | `python/glaurung/llm/` | `agents/memory_foundation.py` builds every agent; `agents/memory_agent.py` registers the tools; `llm/kb/` is the store all of them write through. |

The pass order living in `python_bindings/ir/pipeline.rs` rather than in
`src/ir/` is a known boundary violation with a real consequence: most
decompiler passes are reachable only through the bindings, so `cargo test`
alone neither runs nor compiles them. `cargo test --features python-ext` is
the command that says a pipeline change is done. See
[`rust-crate-map.md`](rust-crate-map.md#reachability-what-each-build-compiles).

## Repository map

```bash
ls -d */
```

| path | what it holds |
|---|---|
| `src/` | the Rust crate and the PyO3 bindings |
| `python/glaurung/` | the Python package |
| `python/tests/` | the Python test suite (`pytest.ini` sets `testpaths`) |
| `tests/` | Rust integration tests, the decompiler fixture corpus, the DecBench corpus and adapter, `test_facets.json`, and several baselines |
| `samples/` | real and synthetic sample binaries, some behind Git LFS |
| `data/` | shipped data: `types/` (Windows API prototype bundles), `sigs/` (FLIRT libraries), `baselines/` (the Windows/Ghidra parity dashboards) |
| `benches/` | ten Criterion benchmarks |
| `bench/` | benchmark inputs and `perf_baseline.json`, plus the axeyum harness |
| `examples/` | 15 Rust and 5 Python executable examples |
| `fuzz/` | a separate `cargo-fuzz` crate with eight targets |
| `java/` | the JVM-side tooling the Java analysis path shells out to |
| `reference/` | checked-in third-party specifications used for research; not built |
| `scripts/` | repository workflows and regression gates |
| `tools/` | focused developer tools: generators, the decompiler test driver, guards |
| `assets/` | logos |
| `docs/` | this tree |

Root files: `Cargo.toml` / `Cargo.lock` (Rust package, features, and the
`rust-version = "1.88"` floor), `pyproject.toml` / `uv.lock`
(`requires-python = ">=3.12"`, dependencies, the console script, the maturin
settings), `pytest.ini`, `README.md`, `CLAUDE.md`, `AGENTS.md`, `LICENSE`
(Apache-2.0). `.venv/` and `target/` are build products and are ignored.

`docs/development/setup.md` has the prerequisites, build modes and
troubleshooting; [`../development/testing-gates.md`](../development/testing-gates.md)
has which gate to run before pushing what.

## Everything else in this directory

**The decompiler**

- [`decompiler-pipeline.md`](decompiler-pipeline.md) — the pipeline as built,
  stated against what is *not* built.
- [`register-model.md`](register-model.md) — why register views are owned in
  one place, and the prepare-then-render boundary.
- [`x86-flags.md`](x86-flags.md) — the flag producer/consumer protocol.
- [`../reference/decompiler-passes.md`](../reference/decompiler-passes.md) —
  the ordered stage list, generated from the source that holds it.

**Storage and data**

- [`persistent-project.md`](persistent-project.md) — the `.glaurung` file:
  sessions, lifecycle, schema compatibility, function identity across builds.
- [`data-model.md`](data-model.md) — the representation at each boundary.
- [`../reference/provenance.md`](../reference/provenance.md) — the `set_by`
  ladder, generated from the code that enforces it.

**Execution and solving**

- [`execution-engine.md`](execution-engine.md) — `src/exec/` and
  `src/symbolic/` as built.
- [`solver-backends.md`](solver-backends.md) — the SMT backends and how one is
  selected.
- [`ioctl-taint.md`](ioctl-taint.md) — abstract interpretation over WDM driver
  dispatch routines.

**Surfaces**

- [`llm-subsystem.md`](llm-subsystem.md) — agents, tools, the L1–L5 ladder and
  the F1–F7 cost guards.
- [`windows-port.md`](windows-port.md) — PE/PDB, the `windows` command family,
  the parity baselines, and where the capabilities came from.

**Cross-cutting**

- [`rust-crate-map.md`](rust-crate-map.md) — per-directory sizes, the feature
  table, and which build compiles what.
- [`python-package-map.md`](python-package-map.md) — modules, the KB schema,
  the lazy CLI registry, the generated stubs.
- [`module-boundaries.md`](module-boundaries.md) — seven boundaries to hold,
  with their current status.
- [`competitive-position.md`](competitive-position.md) — what analysts expect,
  ranked, against IDA Pro, Ghidra and angr, with every competitor claim traced
  to a primary source.

Decision records are in [`../decisions/`](../decisions/), live proposals for
things not built in [`../design/`](../design/), and dated evidence — including
the architecture reviews and the refactoring portfolio — in
[`../history/`](../history/README.md). Nothing under `history/` is guidance.
