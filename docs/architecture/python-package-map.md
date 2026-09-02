# Python package map

> **Kind:** architecture · **Status:** maintained

`python/glaurung/` is the analyst-facing surface: the `glaurung` console
script, the LLM agent subsystem, the knowledge base that backs a `.glaurung`
project file, and a thin Python layer over the compiled extension.

Measured at commit `13faa6f7`:

```bash
find python/glaurung -name '*.py' | xargs wc -l | tail -1   # 389 files, 158,956 lines
find python/glaurung/<dir> -name '*.py' | xargs wc -l | tail -1
```

## Modules and subpackages

| module / package | files | lines | what it is |
|---|---:|---:|---|
| `llm/` | 313 | 133,858 | **84% of the package.** Agents, ~242 tool modules, and the KB. See [`llm-subsystem.md`](llm-subsystem.md). |
| `cli/` | 57 | 20,000 | the `glaurung` console script: 40 subcommands, 10 formatters, a lazy registry |
| `windows_analysis.py` | 1 | 1,361 | Windows PE analysis helpers over structured facts |
| `bench/` | 4 | 1,215 | the deterministic no-LLM regression harness (`python -m glaurung.bench`) |
| `types/` | 2 | 604 | Windows API prototype-bundle sync (`glaurung types sync`, opt-in; ordinary analysis reads the checked-in bundle) |
| `triage.py` | 1 | 425 | Python-friendly re-exports of the native triage types |
| `__init__.py` | 1 | 402 | wraps `glaurung._native` and registers its submodules in `sys.modules` |
| `tools/` | 2 | 234 | `build_flirt_library.py` — builds the FLIRT JSON library from named functions in debug binaries |
| `logging.py` | 1 | 204 | structlog configuration |
| `pdb_fetch.py` | 1 | 161 | Microsoft symbol-server PDB fetcher |
| `java/` | 2 | 143 | Java helper integration (shells out to `java/` at the repository root) |
| `java_classfile_policy.py` | 1 | 130 | |
| `windows_config.py` | 1 | 79 | `WindowsAnalysisConfig` — the shared Windows pipeline budget object |
| `windows_baselines.py` | 1 | 74 | the one place the four Windows/Ghidra parity baseline paths are spelled |
| `similarity.py` | 1 | 60 | CTPH clustering helpers over the native module |

`cli/` breaks down as `commands/` (39 files, 16,676 lines), `formatters/`
(10, 2,338), `utils/` (2, 163), and five loose modules of which `main.py` is
199 lines. `llm/` breaks down as `tools/` (242 files, 99,701 lines),
`agents/` (29, 15,916), `kb/` (27, 14,835), and 15 top-level modules
(3,406 lines).

## The knowledge base is a subpackage of `llm/`

```bash
find . -type d -name kb -not -path './.venv/*' -not -path './target/*'
# ./python/glaurung/llm/kb
```

**The KB lives at `python/glaurung/llm/kb/` — not at `python/glaurung/kb/`,
which does not exist.** This is not cosmetic: importing the KB drags in the
`llm` package `__init__`, so a caller who wants only project persistence still
pays for that import. Every doc, tool and test in the tree uses the
`glaurung.llm.kb.*` path.

The 27 modules, largest first: `xref_db.py` (3,557 — the cross-reference
database and every analyst-write setter), `type_db.py` (1,238),
`cfg_db.py` (928), `binary_diff.py` (834), `windows_function_chunks.py` (760),
`function_identity.py` (635), `windows_boundaries.py` (591),
`persistent.py` (578 — the SQLite file itself),
`structural_fingerprint.py` (541), `lock_state.py` (540),
`verify_recovery.py` (521), `export.py` (509), `kickoff.py` (497),
`windows_callsite_facts.py` (436), `patch.py` (366),
`function_disasm.py` (364), `windows_sysinfo.py` (284),
`pe_direct_calls.py` (276), `bundle.py` (270), `packer_detect.py` (248),
`windows_memory_operands.py` (248), `module_group.py` (204),
`provenance.py` (121), `store.py` (112), `adapters.py` (85),
`models.py` (82), `__init__.py` (10).

## The `.glaurung` schema

There is no schema file. Tables are created by `CREATE TABLE IF NOT EXISTS`
statements spread across nine modules, each owning its own:

```bash
rg -n 'CREATE TABLE' python/glaurung/llm/kb | wc -l     # 35
```

| module | tables |
|---|---|
| `persistent.py` | `schema_meta`, `binaries`, `sessions`, `kb_nodes`, `kb_edges`, `kb_node_tags`, `stdlib_bundle_loads` |
| `xref_db.py` | `xrefs`, `function_names`, `function_identity`, `comments`, `xref_index_state`, `data_xref_index_state`, `data_labels`, `function_prototypes`, `evidence_log`, `stack_frame_vars`, `undo_log`, `bookmarks`, `journal` |
| `cfg_db.py` | `basic_blocks`, `cfg_edges`, `cfg_index_state`, `cfg_dominance`, `cfg_dominance_index_state`, `cfg_branch_facts`, `cfg_branch_index_state` |
| `type_db.py` | `types`, `type_field_uses` |
| `windows_callsite_facts.py` | `callsite_argument_facts`, `callsite_path_conditions` |
| `windows_boundaries.py` | `function_boundaries` |
| `windows_function_chunks.py` | `function_chunk_facts` |
| `windows_memory_operands.py` | `memory_operand_facts` |
| `windows_sysinfo.py` | `windows_sysinfo_dispatch` |

The `*_index_state` tables are incremental-indexing bookkeeping, `undo_log`
backs `glaurung undo` / `redo`, and `evidence_log` and `journal` are the audit
trail.

`SCHEMA_VERSION = "1"` (`persistent.py:25`) is the *base* version. Opening a
file whose `schema_meta` row differs **fails closed**, with the literal message
"migrations are not yet implemented". Subsystem tables evolve through
idempotent column and table checks without moving that number, which is why the
SQLite layout is not a stable third-party format and consumers must go through
Glaurung's APIs. Read
[`persistent-project.md`](persistent-project.md) before depending on session
scope or save semantics, and
[`../reference/provenance.md`](../reference/provenance.md) for the `set_by`
ranking every write in these tables is checked against.

## The CLI is a lazy registry

`glaurung = glaurung.cli:main` (`pyproject.toml [project.scripts]`) →
`python/glaurung/cli/main.py`. `_REGISTRY` maps
`name -> (command module, command class, formatter module, formatter class)`
as **strings**, and `create_parser(only=…)` imports only the module for the
subcommand actually being run.

The comment above the registry records the measurement that forced it:
importing every command eagerly cost 1,417 ms of a 1,467 ms
`import glaurung.cli`, all of it `ask` reaching `pydantic_ai`, so
`glaurung --help` took 3.10 s against 0.11 s for the extension itself. The
fixture matrix pays that cost once per function, because
`tools/diff_decompile.py` shells out to `glaurung decompile` per function.
`python/tests/test_cli_startup_is_lazy.py` pins the contract.

There are no hidden or dev-only subcommands: the registry is the whole surface
and `--help` lists all 40 of them. Four commands share `annotate.py`
(`rename`, `comment`, `label`, `proto`), two share `undo.py`, two share
`bookmark.py`. Global flags are added per-subcommand by
`BaseCommand.add_common_arguments`, so `--format`, `--json`, `--no-color`,
`--quiet` and `--verbose` appear on every one; `--version` is the only true
top-level option.

The command-by-command surface is generated into
[`../reference/cli.md`](../reference/cli.md).

## The extension and its stubs

The compiled module is `glaurung._native`. `glaurung/__init__.py` re-exports it
and registers each PyO3 submodule in `sys.modules` under a `glaurung.<name>`
alias, so `import glaurung.ir` works at runtime.

Both sets of `.pyi` files are **generated**, by one tool:

```bash
uv run python tools/gen_native_stub.py           # write
uv run python tools/gen_native_stub.py --check   # exit 1 if stale
```

- `python/glaurung/_native/*.pyi` — 12 files: `__init__.pyi` for the top-level
  classes, functions and constants, and one per PyO3 submodule.
- `python/glaurung/*.pyi` — 6 files (`analysis`, `debug`, `disasm`, `engine`,
  `ir`, `winmd`), 159 lines in total. These are forwarding aliases emitted by
  the same generator's `_alias_source`, one per submodule that
  `glaurung/__init__.py` puts into `sys.modules`. Each name is listed rather
  than star-imported, so a name vanishing from the extension shows up as a diff
  in the file.

Every one of the 18 carries the same header: *"Generated by
tools/gen_native_stub.py — DO NOT EDIT BY HAND."* Parameter and return types
are `Any` on purpose: PyO3 exposes arity, parameter names and defaults, but not
types, so arity and keyword names are checked and types deliberately are not.

`python/tests/test_native_stub_current.py` regenerates and diffs, so a stub
cannot go stale silently — which matters more than coverage, because a stub
*shadows* the module it describes and a stale one makes the type checker
confidently wrong rather than merely uninformed.

## Where analysis actually happens

Almost nothing in this package computes. `triage.py`, `similarity.py` and the
`_native` aliases are projections of Rust types;
[`../reference/decompiler-passes.md`](../reference/decompiler-passes.md) shows
where the decompiler work is. What is genuinely implemented in Python is the
knowledge base, the CLI's presentation and workflow layer, the LLM agent
subsystem, the Windows fact-extraction tools, and the bench harness.

Related: [`rust-crate-map.md`](rust-crate-map.md) for the other half of the
boundary, [`data-model.md`](data-model.md) for which representation belongs to
which layer, and [`module-boundaries.md`](module-boundaries.md) for the
boundaries this split is meant to hold.
