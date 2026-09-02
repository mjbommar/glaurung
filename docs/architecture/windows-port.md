# The Windows port

> **Kind:** architecture · **Status:** maintained

Windows support is the largest single capability in the tree that is not the
decompiler, and the most self-contained: a PE/PDB ingestion path in Rust, a
`glaurung windows` command with 29 subcommands, 113 Windows tool modules, and a
parity harness that measures function discovery against Ghidra on real vendor
binaries. All of it is **deterministic** — no part of the shipped Windows path
calls a model.

For how to use it, read
[`../guides/windows-analysis.md`](../guides/windows-analysis.md). This page is
about what the pieces are and where they came from.

## What is in the tree

Measured at commit `13faa6f7`.

**Native.** PE parsing is `src/formats/pe/` (11 files, 4,365 lines) — headers,
sections, types, utils, and `directories/` covering export, import, resource,
debug and TLS. Symbol extraction is `src/symbols/pe.rs` (787) and
**`src/symbols/pdb.rs` (1,629)**: native PDB loading through the Rust `pdb`
crate, struct/class/union layout lookup, field-list walking, bitfield metadata,
function-prototype type records, and PE/PDB build provenance. The PE path parses
CodeView RSDS metadata and resolves cached PDBs from the Microsoft
symbol-cache layout or a flat fixture layout.

**PDB is not under `src/debug/`.** That tree is DWARF only (`dwarf.rs`,
`dwarf_signatures.rs`). It is a natural assumption and it is wrong.

`src/winmd.rs` (203 lines) is a narrow Windows-metadata helper —
`WinmdPrototypeParam`, `WinmdPrototype`, `WinmdExport`, and
`export_winmd_prototypes()` — feeding the generated Windows API prototype
bundle.

`src/analysis/ioctl_taint.rs` (1,511 lines) is abstract interpretation over
`LlirFunction` for WDM driver dispatch routines; see
[`ioctl-taint.md`](ioctl-taint.md).

**CLI.** Three subcommands are Windows-specific:

- `windows` (`cli/commands/windows.py`, 4,025 lines) with 29 subcommands:
  `diff-ghidra`, `ioctl`, `analyst`, `analyst-loop`, `analyst-notebook`,
  `corpus-guard`, `high-volume-preflight`, `project-fact-manifest`,
  `project-xrefs`, `project-callgraph-reachability`, `project-callgraph-diff`,
  `project-guard-condition-diff`, `project-function-chunks`,
  `project-function-boundary-diff`, `project-function-start-explain`,
  `project-symbol-ranges`, `project-memory-access-query`,
  `project-memory-access-diff`, `project-data-tables`,
  `project-data-table-diff`, `project-prototype-diff`,
  `bootstrap-project-facts`, `blocker-task-plan`, `symbol-similarity-plan`,
  `function-similarity-manifest`, `runner-artifact-review`,
  `runner-artifact-promotion-plan`, `runner-artifact-promotion-apply`,
  `target-pipeline`.
- `windows-risk` (`cli/commands/windows_risk.py`, 2,652 lines) — imports,
  string xrefs, dynamic API dispatch flows, risky function shapes.
- `pe` (`cli/commands/pe.py`) with `resources`, `manifest`, `version`.

```bash
grep -c 'add_parser(' python/glaurung/cli/commands/windows.py   # 29
```

`glaurung types sync` (`cli/commands/types.py`) is the fourth, and is Windows
work wearing a general name: it regenerates the Windows API prototype bundle
from a source lock, with `--source-lock`, `--overlay`, `--output`,
`--generated-dir`, `--cache-dir`, `--header`, `--clang`, `--clang-arg`,
`--offline`, `--no-overlays`. It is **opt-in**; ordinary analysis reads the
checked-in bundle under `data/types/`.

**Configuration.** `WindowsAnalysisConfig`
(`python/glaurung/windows_config.py`) is one frozen dataclass holding the whole
Windows budget: `max_read_bytes`, `max_file_size`, `max_functions`,
`max_blocks`, `max_instructions`, `timeout_ms`, `total_timeout_ms`,
`pdb_cache_dir`, `symbol_cache_dir`, `symbol_server`, `corpus_manifest`.
Resolution order is explicit path → `$GLAURUNG_WINDOWS_ANALYSIS_CONFIG` →
`.glaurung/windows-analysis.yaml` → defaults; unknown keys raise, and hyphen
and underscore spellings are both accepted. Field-by-field reference:
[`../reference/windows-analysis-config.md`](../reference/windows-analysis-config.md).

**Tools.** 113 of the 242 modules under `python/glaurung/llm/tools/` are
`windows_*`, and 112 of them are registered on the memory agent. They are
deterministic fact extractors and queries — chunks, thunks, boundaries,
callsite arguments, memory operands, symbol ranges, data tables, dispatch
facts — not model prompts. Thirteen `agents/windows_*` modules orchestrate
them; only one imports `pydantic_ai`, and its constructor has no caller outside
a test. See [`llm-subsystem.md`](llm-subsystem.md).

**Persistence.** Six of the nine KB modules that create tables are Windows-
specific: `windows_boundaries`, `windows_callsite_facts`,
`windows_function_chunks`, `windows_memory_operands`, `windows_sysinfo`, and
the shared `cfg_db`. The tables are listed in
[`python-package-map.md`](python-package-map.md).

## The Ghidra parity baselines

Four JSON dashboards compare Glaurung's function discovery against Ghidra on a
vendored Windows corpus. They live at
`data/baselines/windows-ghidra-parity/`:

| file | what it is |
|---|---|
| `glaurung_vs_ghidra_vendor_windows.json` | the full corpus comparison |
| `glaurung_vs_ghidra_vendor_windows_30.json` | the thirty-sample run, before the tiny-stub gate |
| `glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json` | the current thirty-sample dashboard — the default every tool reads |
| `glaurung_vs_ghidra_vendor_windows_30_diagnostics.json` | per-function missing/extra starts for that run |

Every consumer spells those paths **once**, in
`python/glaurung/windows_baselines.py`. That module exists because the paths
are argparse defaults in `windows.py`, pydantic field defaults in eleven agent
and tool modules, and inputs to a workflow; before it, each of them carried its
own literal.

They are regenerated, not frozen: `scripts/windows_ghidra_parity.py` drives
Ghidra headless over
`samples/binaries/platforms/windows/vendor/realworld`, diffs against the
previous JSON, and emits a refreshed dashboard plus a markdown table.
`.github/workflows/windows-ghidra-parity-refresh.yml` runs it weekly on a
self-hosted runner that has Ghidra, then writes a corpus review note with
`glaurung windows corpus-guard`. The human-readable `.md` table beside each JSON
in that directory is the rendered form of the same run. The narrative reviews of
the original May 2026 comparison —
[`glaurung-vs-ghidra-regression-review.md`](../history/windows-port-2026-05/glaurung-vs-ghidra-regression-review.md)
over ten fixtures and
[`glaurung-vs-ghidra-full-debug-review.md`](../history/windows-port-2026-05/glaurung-vs-ghidra-full-debug-review.md)
over thirty — are dated evidence and stay in `history/`.

The refresh workflow needs `analyzeHeadless` on the runner and does not run in
ordinary CI. `windows-corpus-guard.yml` and `windows-target-pipeline.yml` are
the two workflows that exercise the Windows path without Ghidra.

## Where the capabilities came from

Four design documents drove the port. All four are archived in
[`../history/windows-port-2026-05/`](../history/windows-port-2026-05/); this is
what each one contributed and where the shipped answer diverged.

**Atomic tools** (`atomic-tools.md`). The argument for encoding
bug-class invariants as `memory_agent` tools rather than as rule files, on the
grounds that a tool is reused by the autonomous loop, by interactive `ask`, by
the bench scorecard, and by any later agent, whereas a rule file is
single-purpose. That argument held. The specific catalogue did not: it proposed
twelve to fifteen named files (`find_dpc_callbacks.py`,
`paged_pool_deref_under_dispatch.py`, `classify_attacker_for_pe_fn.py`,
`pdb_struct_layout.py`, …) and none of those filenames exists. What shipped
instead is 113 differently-named composable fact and query tools — a different
architecture answering the same question, not a delivery of that list.

**PDB ingestion** (`pdb-ingestion-design.md`). Planned where PDB support would
live, which crate to use, and how PDB type records map onto the existing type
model — including the discipline of build-tagging fixtures so a PDB is only
ever paired with the binary it was produced for. The core ingestion shipped as
`src/symbols/pdb.rs` with the Rust `pdb` crate, and the design's separation of
"parse the PDB" from "map its types into ours" is visible in the shipped split
between `src/symbols/pdb.rs` and the `type_db` import path. Two sketched files
under `src/symbols/analysis/` were never created.

**PE hardening** (`pe-hardening-design.md`). Named four PE data directories
that gated classes of analysis — resources, TLS callbacks, delay imports, and
version/manifest metadata — and argued that malware-triage claims are not
grounded until they parse. All four shipped: the directory constants are in
`src/formats/pe/types.rs`, resource, TLS, import, export and debug parsing under
`src/formats/pe/directories/`, delay-import handling in `src/formats/pe/mod.rs`,
and the resource, manifest and version views through `glaurung pe`.

**BSim-equivalent similarity** (`bsim-similarity-design.md`). Made the case for
body-level rather than name-level function similarity, driven by the Patch
Tuesday n-day workflow: pull pre- and post-patch builds, rank changed functions
by patch density, and walk each change through the bug-class invariants.
`glaurung diff` and `windows function-similarity-manifest` are the deterministic
opcode/byte n-gram answer to it; canonical-PCode hashing, the design's stated
target, is not what shipped.

## The collaboration this came out of

The Windows port was built as a co-investment with an external
`agentic-security-bot` project, which chose Glaurung as its static-analysis
substrate for Windows binaries: campaign needs flowed in as feature work,
bench results flowed back, and no source was vendored in either direction.
The full agreement, including what artifacts may land in this repository, is
archived at
[`../history/windows-port-2026-05/co-investment-policy.md`](../history/windows-port-2026-05/co-investment-policy.md).

That collaboration is why the Windows surface is shaped the way it is —
corpus guards, promotion plans, runner-artifact review, a parity dashboard —
rather than as a set of analyst commands. It is a pipeline someone else's
automation drives, with a human review step at every promotion.

## Related

- [`ioctl-taint.md`](ioctl-taint.md) — the driver-dispatch taint analysis.
- [`../reference/windows-api-type-sync.md`](../reference/windows-api-type-sync.md)
  — regenerating the prototype bundle.
- [`module-boundaries.md`](module-boundaries.md) §5 — the deterministic
  fact-packet contract this surface is supposed to hold, and where it does not.
