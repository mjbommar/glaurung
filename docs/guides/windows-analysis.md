# Windows / PE analysis

> **Kind:** guide · **Status:** maintained

Glaurung's Windows capability is a PE-specific layer on top of the general
pipeline: PDB-backed symbol naming, a `windows-risk` triage summary, and a
`windows` command family (29 subcommands) that reads and diffs facts
persisted in a `.glaurung` project. This guide walks an end-to-end PE
analysis and indexes the subcommands by purpose. For how the pieces are
built, see [`architecture/windows-port.md`](../architecture/windows-port.md);
for the external collaboration that funded most of it, see
[`docs/history/windows-port-2026-05/`](../history/windows-port-2026-05/).

## End to end: kickoff, then query the project

`kickoff` is the usual entry point. On a PE it fetches and applies PDB
symbols by default:

```bash
DB="${TMPDIR:-$HOME/.cache/glaurung/tmp}/acledit.glaurung"
PE=samples/binaries/platforms/windows/vendor/realworld/win11-acledit.dll

uv run glaurung kickoff "$PE" --db "$DB"
```

Relevant `kickoff` flags (`python/glaurung/cli/commands/kickoff.py`):

| flag | effect |
| --- | --- |
| `--pdb-cache DIR` | Microsoft-style PDB cache directory. Defaults to `$GLAURUNG_PDB_CACHE`, else a local `_NT_SYMBOL_PATH` entry, else `~/.cache/glaurung/symbols`. |
| `--no-pdb` | disable PDB public-symbol naming (on by default for a PE with a CodeView record) |
| `--no-fetch-pdb` | use only what is already cached; do not contact the Microsoft symbol server |
| `--pdb-struct NAME` | import one named PDB struct's layout into the type DB during kickoff (repeatable) |

PDB fetching itself (`python/glaurung/pdb_fetch.py`) reads the PE's CodeView
RSDS record, computes the `<GUID><AGE>` symbol-server key, and downloads the
matching PDB from `https://msdl.microsoft.com/download/symbols` into the
cache in the canonical `<cache_dir>/<pdb_name>/<GUID><AGE>/<pdb_name>` layout
that `g.symbols.pdb_symbol_map` reads. It is pure standard library (no
`pefile` or other external dependency), so it runs as part of `kickoff`
without an extra install step.

Once a project exists, `windows` subcommands query and diff the facts
`kickoff`/`bootstrap-project-facts` persisted into it — see below.

## Quick risk triage without a project

For a single-pass summary — risky imports bucketed by category, string-to-
function xrefs, and decompiled candidate functions — without building a
`.glaurung` project:

```bash
uv run glaurung windows-risk "$PE" --format json
```

Key flags: `--max-candidates` and `--max-decompile` cap how much of the
summary is kept/decompiled (both default to sane non-truncating values as of
2026-05-25; see the command's own `--help` for the pre-2026-05-25 defaults
that used to silently truncate large binaries like `dnsapi.dll`).

## PE structure: resources, manifest, version info

```bash
uv run glaurung pe resources "$PE"
uv run glaurung pe manifest "$PE"
uv run glaurung pe version "$PE"
```

`resources` lists the PE resource-directory leaves; `manifest` decodes
`RT_MANIFEST`; `version` decodes `VERSIONINFO`. Each exits non-zero when the
directory is absent — see `uv run glaurung pe --help`.

## The `windows` subcommand family (29 subcommands)

All names below are the literal `add_parser` first argument in
`python/glaurung/cli/commands/windows.py` (verify with
`uv run glaurung windows --help`, which lists all 29). They group into seven
purposes:

**Project bootstrap and inventory** — build or inspect the persisted fact
cache a `.glaurung` project holds for a PE:
- `bootstrap-project-facts` — create or update the project fact cache (PDB
  import, xref indexing, memory-operand facts, etc. are individually
  toggleable; see `--help` for the `--no-index-*` switches)
- `project-fact-manifest` — inspect what fact coverage a project already has

**Read queries** — answer a specific question against persisted facts:
- `project-xrefs` — IDA/Ghidra-style callers/callees/reads/writes lookups
- `project-callgraph-reachability` — bounded source-to-target or
  upstream-to-target callgraph paths
- `project-function-chunks` — chunk, thunk, tailcall, and shared-tail facts
  for a function
- `project-function-start-explain` — why a VA or symbol is a function,
  thunk, chunk, or contained label
- `project-symbol-ranges` — audit PDB/public symbol ranges against `.pdata`
- `project-memory-access-query` — who reads/writes a field, base object, or
  data target
- `project-data-tables` — recover dispatch tables, callback arrays, vtables,
  jump tables, and selector-indexed globals

**Cross-build diffs** — the patch-Tuesday workflow, comparing two
`.glaurung` projects built from two versions of the same binary:
- `project-callgraph-diff`, `project-guard-condition-diff`,
  `project-function-boundary-diff`, `project-memory-access-diff`,
  `project-data-table-diff`, `project-prototype-diff`

**Driver/IOCTL surface:**
- `ioctl` — map a driver's IOCTL attack surface: dispatchers, codes, MSVC
  switch jump tables, handlers

**Interactive analyst workflows:**
- `analyst` — ask the deterministic Windows analyst workflow a bounded
  question
- `analyst-loop` — run a bounded multi-turn analyst command script
- `analyst-notebook` — import/export analyst notebook decisions for a
  `.glaurung` project

**Similarity and task planning:**
- `symbol-similarity-plan` — plan PDB/symbol-server and BSim extraction for
  a patch pair
- `function-similarity-manifest` — generate a deterministic opcode/body
  similarity manifest (feeds external BSim-style matching)
- `blocker-task-plan` — turn preflight/pipeline blockers into a task plan

**Ghidra-parity corpus and runner tooling** — used to refresh and promote
the regression baselines described below, not part of the analyst
day-to-day flow:
- `diff-ghidra`, `corpus-guard`, `high-volume-preflight`, `target-pipeline`,
  `runner-artifact-review`, `runner-artifact-promotion-plan`,
  `runner-artifact-promotion-apply`

That is 2 + 7 + 6 + 1 + 3 + 3 + 7 = 29.

## Configuration

Shared PE-analysis resource budgets (`max_read_bytes`, `max_functions`,
`timeout_ms`, PDB/symbol cache paths, symbol server, corpus manifest) come
from one `WindowsAnalysisConfig`, loaded in order: an explicit path, then
`$GLAURUNG_WINDOWS_ANALYSIS_CONFIG`, then `.glaurung/windows-analysis.yaml`,
then built-in defaults. See
[`reference/windows-analysis-config.md`](../reference/windows-analysis-config.md)
for the full field table and defaults.

## Type sync (Win32/WDK prototypes)

`uv run glaurung types sync` regenerates the Win32/WDK function-prototype
bundle from a locked NuGet source plus a curated semantic overlay, so
`bootstrap-project-facts` and the pretty-lift path can attach real
prototypes to imported and PDB-named functions. See
[`reference/windows-api-type-sync.md`](../reference/windows-api-type-sync.md)
for the source lock, overlay, and cache-dir flags.

## Ghidra-parity baselines and how to refresh them

`data/baselines/windows-ghidra-parity/` holds the checked-in comparison
artifacts (`glaurung_vs_ghidra_vendor_windows*.json`) that the tools above
read as their "previous" baseline — for example
`windows_function_start_explain` and `windows_function_body_split_candidates`
cite the 30-file post-tiny-stub-gate dashboard there for context, and the
`test_windows_*_tool.py` tests load the same files as fixtures.

The refresh workflow is `.github/workflows/windows-ghidra-parity-refresh.yml`
(self-hosted, needs a local Ghidra `analyzeHeadless`; weekly cron plus manual
dispatch). It runs, in order:

1. `scripts/windows_ghidra_parity.py` against
   `samples/binaries/platforms/windows/vendor/realworld/`, comparing to the
   current baseline and writing a refreshed JSON/Markdown pair.
2. `uv run glaurung windows corpus-guard` to check the refreshed dashboard
   for drift.
3. `uv run glaurung windows runner-artifact-review` to review the refreshed
   artifacts for blockers.
4. `uv run glaurung windows runner-artifact-promotion-plan` then
   `runner-artifact-promotion-apply` to plan, and optionally apply, promoting
   the reviewed artifacts into `data/baselines/windows-ghidra-parity/`.

Do not hand-edit the files under `data/baselines/windows-ghidra-parity/`; run
this pipeline (or the equivalent local `uv run glaurung windows ...` steps)
and let promotion write them.

## History

The Windows port originated as a co-investment with an external
collaborator ("asb"); the roadmap, atomic-tool proposals, PDB/PE hardening
design records, and the pre-refresh-automation Ghidra comparison snapshots
that funded and shaped it are archived under
[`docs/history/windows-port-2026-05/`](../history/windows-port-2026-05/).
Read there for design rationale and campaign history — not for current
command syntax, which lives in this guide and in `--help`.
