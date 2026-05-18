# Windows-specific atomic tools for `glaurung/llm/tools/`

> 12-15 deterministic pydantic-ai tools the `agentic-security-bot`
> (asb) windows-port campaign adds to `memory_agent`. Each tool
> encapsulates one tier-1 or tier-2 bug-class invariant from
> `asb/projects/windows-port/reference/bug-class-invariants.md`.

## Why tools, not glaurung-script rules

asb workstream 02 sec "How rules are encoded" enumerates three
paths: glaurung-script rules (`data/rules/glaurung/<id>/rule.py`),
kg-pe-query SQL (`data/rules/kg-pe/<id>/rule.sql`), and new
`memory_agent` atomic tools. The tool path wins for tier-1
invariants because the same tool gets reused by:

- the `memory_agent` autonomous loop (the asb campaign's primary
  consumer)
- interactive `glaurung ask` sessions (humans debugging a finding)
- `python -m glaurung.bench` regression scorecard
- future agents Glaurung adds (vulnerability agent, decompile
  agent)

A rule file under `data/rules/` is single-purpose; a tool
multiplies its leverage.

## The 14 tools

The full table, mirroring asb workstream 02 sec "Windows-specific
atomic tools". Each row's "invariant" column is the load-bearing
property the tool encodes; "bug-class ref" cites the
`reference/bug-class-invariants.md` entry the tool implements.

| tool (file) | invariant | bug-class ref |
|-------------|-----------|---------------|
| `find_dpc_callbacks.py` | enumerate functions registered via `KeInitializeDpc` (second-arg function pointer in the call) | #2 |
| `paged_pool_deref_under_dispatch.py` | from a starting fn, walk callgraph until either a paged-pool deref or an IRQL-lowering call; report paths that hit the deref first | #1, #2 |
| `find_irp_completion_then_use.py` | within a fn, find any deref of an Irp variable that is downstream (CFG) of a call to `IoCompleteRequest(Irp, ...)` | #3 |
| `find_cancel_routine_no_unset.py` | within a fn that calls `IoSetCancelRoutine(Irp, non-NULL)`, find paths to `IoCompleteRequest(Irp)` not gated by a matching `IoSetCancelRoutine(Irp, NULL)` | #4 |
| `find_obref_untyped.py` | callsite of `ObReferenceObjectByHandle(...)` with `ObjectType == NULL`, followed by a cast of the returned `Object` | #5 |
| `find_xxx_callback_uaf.py` | win32k fn whose name starts `xxx` or `zzz`, calls `KeUserModeCallback`, then derefs a pre-callback pointer without re-validation | #6 |
| `find_probe_then_reread.py` | callsite of `ProbeForRead/Write(p, size)` followed by >=2 derefs `*p`, `*(p+const)` without intervening copy to kernel memory | #7 |
| `find_mmprobelock_no_unwind.py` | fn calls `MmProbeAndLockPages`; any error edge that returns without `MmUnlockPages` + `IoFreeMdl` | #8 |
| `find_ndrservercall_unbounded_array.py` | RPC server entry (reached from `NdrServerCall2`) with an unbounded conformant array param read from the marshalled stream before any size cap | #9 |
| `find_alpc_handler_no_attr_validation.py` | ALPC port handler (reached from `AlpcpDispatchMessage`) reads `Message->Attributes` without `AlpcGetMessageAttribute` precheck | #10 |
| `find_dxgkrnl_ioctl_no_probe.py` | dxgkrnl IRP_MJ_DEVICE_CONTROL handler derefs `Irp->AssociatedIrp.SystemBuffer` or `Irp->UserBuffer` without prior `ProbeForRead/Write` | #14 |
| `classify_attacker_for_pe_fn.py` | walk asb's `data/kg/pe-sources.yaml` + `pe-gates.yaml`; return `(attacker_class, gates_on_path)` -- pins AV/PR | (analog of the Linux `bot/kg/` tool `classify_attacker_for_target`) |
| `find_canonical_pe_binaries.py` | given `nt!Symbol`, return list of (binary, build) tuples from the `/nas4/data/binary-analysis/glaurung/windows-*` corpus | helper |
| `pe_xref_callers_recursive.py` | bounded-depth reverse callgraph walk against the `.glaurung` SQLite KB; mirrors `cscope -L1` ergonomics | helper |
| `pdb_struct_layout.py` | given struct name, return field offsets + types from PDB-derived type DB (depends on #179) | helper |

That is 15 (the campaign's "12-15" is approximate). The
`pdb_struct_layout.py` helper is now unblocked by the #179 type
DB import path, and public PDB function names are available through
the persistent `function_names` table for xref-heavy tools. Direct
PE code-to-data refs also persist as `data_read` rows, so string and
global-data use-site tools can answer direct `.rdata` questions from
the KB. UTF-16 strings now reach Python triage on the real
`ntoskrnl.exe` fixture, and register-held string/table bases recover
direct exact refs above the comparison-05 bar. Known-index pointer
loads recover the straightforward one-hop table refs; residual
PARAM/table-entry refs are still tracked by comparison 05.

## Landed metadata and patch-diff tools

The current Windows-port bridge also includes deterministic tools that
sit below full IR/CFG bug-class scanners:

- `windows_build_corpus` resolves ASB's priority Windows target
  manifest against caller-supplied corpus and `.glaurung` project
  roots.
- `windows_bootstrap_project_facts` creates or updates a `.glaurung`
  project for one Windows PE by composing callgraph indexing,
  code-to-data xref indexing, optional PDB fact import, and a
  conservative PE `E8 rel32` direct-call fallback when generic
  callgraph recovery produces no call edges. It returns per-step
  counts, elapsed time, coverage, and remaining missing capabilities
  so agents can prepare a project before running rules.
- `windows_project_fact_summary` inspects a `.glaurung` SQLite project
  read-only and reports available PE project facts: function names,
  call/data xrefs, prototypes, stack variables, comments, and CFG table
  coverage.
- `windows_project_fact_manifest` exposes ASB's persisted project-fact
  coverage records, including `.glaurung` project paths, selected row
  counts, available fact classes, and missing Ghidra-parity substrate
  such as call xrefs, CFG facts, dominance summaries, or branch
  condition facts.
- `windows_pdb_identity_manifest` exposes ASB's target-to-PDB identity
  coverage, including CodeView GUID+age values, cached/missing status,
  and whether public symbols, type layouts, or prototypes are expected
  for a target.
- `windows_reconcile_pdb_identity` extracts live CodeView/PDB identity
  from a PE, checks Microsoft-style PDB cache resolution, optionally
  asks native PDB ingestion for type/public-symbol counts, and compares
  the live identity with ASB's manifest.
- `windows_import_pdb_facts` persists matching PE/PDB public names,
  requested struct/union layouts, and PDB procedure type records into a
  `.glaurung` project, returning explicit import counts and remaining
  gaps so agents can promote a project from cached-PDB state to
  queryable type/name facts.
- `windows_component_profile` exposes ASB's high-risk component
  profiles: entrypoint families, expected gates, validation
  requirements, initial rule families, evidence-packet fields, and VM
  harness strategy.
- `windows_ghidra_delta_manifest` exposes ASB's explicit Ghidra-parity
  gap records, so agents can ask which fact classes are present,
  partial, missing, or blocking automated Windows triage.
- `windows_surface_catalog`, `windows_source_reachability`, and
  `windows_target_surface_profile` expose attacker-surface and
  validation context from ASB metadata.
- `windows_project_callsite_facts` enumerates exact callsite VAs and
  caller/callee identity from persisted `.glaurung` `xrefs` and
  `function_names` rows. When callee names match `pe-sinks.yaml`, it
  attaches operation metadata so agents can query project-backed sink
  callsites before decompiling for operands.
- `windows_project_callgraph_slice` returns incoming callers and
  outgoing callees around one project function, with exact callsite VAs
  and caller/callee names from persisted `.glaurung` call xrefs.
- `windows_project_call_argument_snapshot` uses a project callsite VA
  plus nearby disassembly to recover a conservative Windows x64
  RCX/RDX/R8/R9 argument snapshot plus obvious stack argument stores
  at Windows x64 outgoing stack slots such as `[rsp+0x20]` and
  `[rsp+0x28]`. It also resolves simple straight-line register aliases,
  incoming caller-parameter aliases, same-window frame-slot
  spill/reload chains, and simple LEA-derived address expressions such
  as `[caller_arg0 + 0x20]` in the local setup window. It also labels
  conservative rbp-relative local stack addresses such as
  `[rbp - 0x40]` and simple memory loads from known bases such as
  `load([caller_arg0 + 0x20])`. It is local evidence, not full alias,
  stack-frame, or path proof.
- `windows_callsite_operand_facts` enumerates structured callsite
  argument facts from supplied or decompiled pseudocode, attaches
  optional callsite VA markers when present, and joins operation-backed
  calls to `pe-sinks.yaml` roles. This gives later source-gate-sink
  rules a reusable argument table instead of re-parsing snippets.
- `windows_source_sink_operand_match` checks whether a traced source
  value is exactly a selected sink argument, reaches it through a
  simple alias, appears in a transformed expression, or does not match,
  while attaching sink argument role metadata.
- `windows_vulnerability_seed_catalog` loads prior-public Windows
  vulnerability seeds as reusable invariant metadata for
  patch-regression triage, without using public PoCs as the scanner
  substrate.
- `windows_binary_diff_summary` wraps Glaurung's function-level binary
  diff engine as an agent-callable Patch Tuesday primitive, returning
  changed/added/removed function rows with hashes and sizes.
- `windows_seed_binary_diff_triage` composes prior-public seed
  metadata with a pre/post binary diff and reports whether seed-named
  functions changed, stayed unchanged, or are absent from the pair.
- `windows_cfg_dominance` checks whether a gate basic block dominates
  a sink basic block using persisted `.glaurung` CFG tables, native PE
  function CFG recovery, or supplied fixture CFG rows. It reports
  `dominated`, `not_dominated`, `same_block`, `unreachable`, or
  `unknown`.
- `windows_bootstrap_project_facts` can now persist native PE basic
  blocks and CFG edges into `.glaurung` projects via its `index_cfg`
  step, then precompute immediate dominator/post-dominator summaries
  via `index_cfg_dominance`, and capture simple conditional
  branch/compare facts via `index_branch_conditions`, so project
  summaries can report CFG coverage without re-running on-demand
  function recovery.
- `windows_project_cfg_path_query` reads persisted `.glaurung` CFG
  tables to resolve containing blocks, branch/source-to-sink
  reachability, and whether every entry-to-sink path passes through a
  candidate gate. When coverage fails, it returns a compact bypass
  block path for review packets.
- `windows_project_branch_condition_facts` reads persisted
  `cfg_branch_facts` rows, returning conditional branch mnemonics,
  nearby `cmp`/`test` operands, condition classes, and target/fallthrough
  block ids. It also renders simple taken/fallthrough predicates by
  inverting the branch condition, preserves same-block flag-setting
  arithmetic/logical instructions such as `sub`, `add`, `and`, `or`,
  `xor`, `inc`, and `dec`, and can filter to a path from
  `windows_project_cfg_path_query`.
- `windows_cfg_gate_to_sink` composes ASB gate/sink metadata with
  concrete gate and sink callsite VAs, runs CFG dominance, and returns
  a packet-ready gate status for candidate evidence.
- `windows_compose_source_gate_sink_packet` composes source/sink
  operand matching with CFG gate-to-sink evidence and emits a normal
  candidate review packet for operator triage.
- `windows_emit_review_packet` and `windows_compose_candidate_packets`
  preserve structured PDB identity, component-profile, and patch-diff
  context in every emitted candidate packet, so downstream ranking and
  validation can see which build/PDB, expected gates, harness plan, and
  regression signals backed the hit.

These tools do not replace the Ghidra-grade facts this document still
tracks: function matching across renamed builds, instruction-level
diffs, richer callsite operands, full path predicates over persisted
CFG, and PDB-backed type facts.

## Per-tool authoring template

Each tool is one file under
`/nas4/data/workspace-infosec/glaurung/python/glaurung/llm/tools/`,
following the existing `hash_file.py` shape:

```python
"""find_dpc_callbacks.py -- enumerate functions registered via
KeInitializeDpc as DPC callbacks. Used by paged_pool_deref_under_dispatch
to seed the DPC-context walk.
"""

from __future__ import annotations

from typing import List
from pathlib import Path

from pydantic import BaseModel, Field

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


class FindDpcCallbacksArgs(BaseModel):
    project_path: str = Field(
        ...,
        description="Path to .glaurung SQLite project for the binary",
    )
    include_chained: bool = Field(
        False,
        description="If true, also include fns registered indirectly via "
        "a vtable slot that flows into KeInitializeDpc",
    )


class DpcCallbackRow(BaseModel):
    fn_name: str
    fn_va: int
    register_callsite_va: int
    binary: str


class FindDpcCallbacksResult(BaseModel):
    callbacks: List[DpcCallbackRow]


class FindDpcCallbacksTool(
    MemoryTool[FindDpcCallbacksArgs, FindDpcCallbacksResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="find_dpc_callbacks",
                description=(
                    "Enumerate DPC callbacks (fns registered via "
                    "KeInitializeDpc); seeds dispatch-IRQL walks."
                ),
                tags=("windows", "kernel", "dpc", "irql"),
            ),
            FindDpcCallbacksArgs,
            FindDpcCallbacksResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: FindDpcCallbacksArgs,
    ) -> FindDpcCallbacksResult:
        # 1. Open args.project_path as the .glaurung SQLite KB
        # 2. Query xrefs table: rows where dst_func_name = "KeInitializeDpc"
        # 3. For each callsite, recover the second-arg operand (the
        #    function-pointer constant). Use the existing operand parser
        #    from `analysis.type_propagation` (issue #195).
        # 4. Lift each resolved VA to its containing function name.
        # 5. Return rows; also write to kb as Node(kind="dpc_callback")
        #    so subsequent agent turns can reuse without re-querying.
        ...


def build_tool() -> MemoryTool[
    FindDpcCallbacksArgs, FindDpcCallbacksResult
]:
    return FindDpcCallbacksTool()
```

### Authoring checklist

For each tool:

1. Args model: pydantic `BaseModel` with `Field(..., description=...)`
   so the LLM gets human-readable hints.
2. Output schema: pydantic `BaseModel` with explicit field types.
   Use lists of small `BaseModel` rows, not free-form dicts.
3. `MemoryTool[Args, Result]` subclass with `ToolMeta(name, description,
   tags)`. Tags should include `windows` plus the subsystem
   (`kernel`, `win32k`, `dxgkrnl`, `alpc`, `rpc`).
4. `run()` opens the project KB through `ctx.kb` or a per-call
   `KnowledgeBase` path; never instantiates a new SQLite handle
   directly so the existing connection pool / lock semantics are
   preserved.
5. Writes findings as `Node` rows into `kb` so the agent can
   chain tools (one tool's output is the next's input).
6. Test: `python/tests/test_<tool>.py` using one of the
   `tests/fixtures/msvc-pdb/` binaries (issue #197). PDB-type
   tools should use the #179 type DB importer rather than hard-coded
   layout JSON.
7. Tool gets auto-registered by `memory_agent` via the existing
   `build_tool()` discovery pattern; no manual entry in a
   registry table needed.

## Output-schema conventions

Each tool returns either:

- a `List[<RowModel>]` shape (when the tool enumerates findings)
- a single `<Verdict>` shape (when the tool classifies one input)

Rows always include enough provenance for the agent to cite:

- `binary` (filename or sha256-prefix)
- `fn_va` or `fn_name`
- `callsite_va` where applicable
- a free-text `evidence` string the agent can quote

This mirrors Glaurung's evidence-tagged tool outputs (issue
#200, shipped) and the kernel-lore MCP convention of returning
freshness metadata per row.

## Integration with `data/kg/pe-{sources,gates}.yaml`

The `classify_attacker_for_pe_fn.py` tool is the only one that
reads YAML at runtime. It accepts:

```python
class ClassifyAttackerArgs(BaseModel):
    fn_name: str
    project_path: str
    pe_sources_yaml: str = Field(
        default="/nas4/data/workspace-infosec/agentic-security-bot/data/kg/pe-sources.yaml"
    )
    pe_gates_yaml: str = Field(
        default="/nas4/data/workspace-infosec/agentic-security-bot/data/kg/pe-gates.yaml"
    )
```

asb workstream 02 "Open questions" notes the alternative of
vendoring the YAMLs into Glaurung's tree. Current recommendation:
keep them in asb, accept a configurable path, default to the asb
checkout location. A Glaurung release does not need to ship them.

## Bug-class-to-tool routing

When a new bug class lands in
`asb/projects/windows-port/reference/bug-class-invariants.md`,
the rule of thumb:

| tier | typical encoding |
|------|------------------|
| 1    | new tool here (preferred), glaurung-script under `data/rules/glaurung/` (fallback) |
| 2    | tool if reusable across rules; glaurung-script otherwise |
| 3    | broad-sweep glaurung-script; tool only if a helper emerges |

asb workstream 03 owns the rule files; this doc only owns the
tools. Tools are language- and campaign-agnostic; rules are
campaign-specific compositions of tool calls.

## Testing the full set

```
cd /nas4/data/workspace-infosec/glaurung
uv run pytest python/tests/test_find_dpc_callbacks.py \
                python/tests/test_find_irp_completion_then_use.py \
                python/tests/test_paged_pool_deref_under_dispatch.py \
                # ... etc
```

Once all 15 ship green against the #197 fixture set,
`memory_agent` running `glaurung ask "what tier-1 Windows
findings exist in ntoskrnl-26100.5?"` returns a real verdict.

## Cross-refs

- `roadmap.md` -- the four upstream issues these tools depend on
- `pdb-ingestion-design.md` -- the #179 work that gives the
  PDB-aware tools (especially `pdb_struct_layout`) something to
  resolve
- asb `reference/bug-class-invariants.md` -- the canonical list
  of bug shapes; each tier-1 entry maps to exactly one tool
- asb `workstreams/02-kg-pe-substrate.md` sec "Windows-specific
  atomic tools" -- the campaign-side table this doc fans out
- existing template: `glaurung/python/glaurung/llm/tools/hash_file.py`
  (smallest), `classify_constant.py` (mid), `view_disassembly.py`
  (largest)
- Glaurung tool-registration pattern: `docs/llm/TOOLS.md`,
  `docs/llm/ROADMAP.md` sec "Implementation Status / Atomic tools"
