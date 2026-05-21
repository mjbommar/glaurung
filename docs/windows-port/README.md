# Glaurung Windows-port working tree

> Living docs for the Windows / PE / PDB readiness sprint driven
> by the sibling `agentic-security-bot` (asb) repo's `windows-port`
> campaign.

## Status

Implementation is active. #197 and #199 have shipped, and #179 now
has the PE/PDB type-ingestion path needed by the comparison-02
contract: cached PDBs produce persisted struct, union, and
function-prototype type records with provenance. Public PDB
function names and PE code-to-data xrefs now persist into the
`.glaurung` KB, which unblocks IDA-style string/use-site queries
for direct `.rdata` references. UTF-16 strings reach Python triage
on the real `ntoskrnl.exe` fixture, and register-held string/table
bases plus known-index pointer loads now recover selected
comparison-05 KB refs above 90%. The Windows regression corpus now
also has a Ghidra parity dashboard, a conservative PE code-pointer
scanner for VA/RVA callback tables, function-start confidence
taxonomy, code-label facts, `glaurung windows diff-ghidra`, and
Python helpers under `glaurung.windows_analysis`. Unknown-end call-target
boundary candidates now only match the exact entry address instead of claiming
unbounded function bodies. Reduced regression-fixture
replay can now assert bug-pattern detectors, syscall-stub extraction, and
individual API-contract primitive extraction with positive/negative pseudocode
cases. The API-contract
substrate now also recognizes Glaurung IR pointer writes, Windows
Rtl string conversion sinks, IOCTL and pool API contracts,
registry/object-manager/IRP/MDL/ALPC/ETW/WPP/callback contracts,
IO_STACK_LOCATION DeviceIoControl fields, IRP buffer fields, WDF request
buffer helpers,
security-boundary contracts for requestor mode, privilege checks, and token
reference/query/release, wrapper-to-sink forwarding, persisted callsite argument facts, Windows
x64 callsite ABI locations, nearby callsite path conditions, and first-class
`NtQuerySystemInformation{Ex}` dispatch facts for high-risk helper
triage. The first evidence-backed pretty-lift path now packages raw
Glaurung IR, API-contract primitives, argument roles, function and call
prototypes, Windows x64 function-entry ABI argument facts, ordered callsite
facts with per-argument ABI facts and prototype-backed argument rendering,
stdlib type-only prototype role inference, import-thunk alias prototype
propagation, and low-confidence local helper prototype inference from argument
names,
callsite return-target facts, selector-table facts, structured path
conditions including status, bounds, selector, NULL, mode, and privilege gates, loop summaries, normalized memory accesses, field-offset groups,
typed C dereference normalization with width metadata,
global/table/global-count/callback/function-pointer-table/jump-table/import-thunk/vtable data-reference facts, explicit unknown/unresolved sections,
output writes, and string-copy sinks into a validated C-like analyst view that
can be consumed by pydantic-ai agents without treating model prose as ground truth. The
pretty-lift validator now rejects candidate lifts that drop required
API-contract source/sink primitives such as probes, copies, IOCTLs, registry
queries, object references, IRP/MDL accesses, ALPC messages, traces, pool calls,
and callbacks. The
remaining windows-port work is PARAM/table-entry string-reference coverage,
broader PDB follow-up surface, BSim-style similarity, and deeper
Windows-specific atomic tools.

## Why this exists in Glaurung (not in asb)

asb chose Glaurung over a Ghidra-headless wrapper as its static-
analysis substrate for Windows binaries (asb ADR 0021). The four
roadmap items below are the gap between today's Glaurung and what
asb needs to ship Windows CVEs:

- `#197` MSVC + .pdb sample fixtures
- `#179` PDB ingestion (mirrors gimli DWARF path)
- `#199` PE format hardening (delay imports, manifest, version
  info, TLS callbacks)
- `#186` BSim-equivalent function similarity

asb commits to driving these features upstream rather than
forking; the contract is asb ADR 0023 (mirrored here as
`co-investment-policy.md`).

## What you can do without leaving this tree

- Read `roadmap.md` for the four roadmap items + per-item scope,
  motivation, design sketch, dependencies, and effort.
- Read `atomic-tools.md` for the 12-15 Windows-specific atomic
  tools the campaign wants registered with `memory_agent`.
  Authoring template included.
- Read `pdb-ingestion-design.md` for the design plan against
  the Rust `pdb` crate, with the llvm-pdbutil JSON fallback.
- Read `pe-hardening-design.md` for the four PE directories
  `#199` lights up, each with a CVE-class rationale.
- Read `windows-api-type-sync.md` for the generated Win32/WDK
  prototype bundle, NuGet source lock, manifest, and curated
  semantic overlay workflow.
- Read `windows-analysis-config.md` for shared Windows PE analysis
  budgets, symbol/cache config, explicit-range decompile usage, and
  the current ntoskrnl/ntdll project-fact bootstrap flow.
- Read `glaurung_vs_ghidra_vendor_windows.md` and
  `glaurung-vs-ghidra-regression-review.md` for the current
  10-file Ghidra parity dashboard and debug notes.
- Read `glaurung-vs-ghidra-full-debug-review.md` and
  `agentic-ai-functionality-roadmap.md` for the 30-file
  Ghidra stress-suite review and the agentic AI functionality
  roadmap derived from it.
- Read `bsim-similarity-design.md` for the Patch-Tuesday-diff
  use case and three competing approaches (4-gram-LSH,
  CodeT5+ embeddings, hybrid).
- Read `co-investment-policy.md` for the issue-first /
  upstream-first contract with asb. This is also where the
  `Assisted-by: Claude:claude-opus-4-7` trailer convention is
  recorded.

## Cross-refs

- asb campaign root:
  `/nas4/data/workspace-infosec/agentic-security-bot/projects/windows-port/`
- asb workstream 02 (the substrate sprint):
  `projects/windows-port/workstreams/02-kg-pe-substrate.md`
- asb workstream 03 (the rules layer that consumes the tools):
  `projects/windows-port/workstreams/03-rules-and-master-data.md`
- asb bug-class invariants (the 13 tier-1 patterns the atomic
  tools encode):
  `projects/windows-port/reference/bug-class-invariants.md`
- Glaurung roadmap board:
  `docs/architecture/IDA_GHIDRA_PARITY.md` (issues #197 / #179 /
  #199 / #186 surface there with one-line status)
- Glaurung pydantic-ai integration:
  `docs/llm/ROADMAP.md` + `docs/llm/TOOLS.md`
- Glaurung persistent KB schema:
  `docs/architecture/PERSISTENT_PROJECT.md`

## Roadmap-item status table

| issue | scope | blocker for | per-doc | status |
|-------|-------|-------------|---------|--------|
| #197  | MSVC + .pdb sample fixtures                | #179 PDB ingest test cases | `roadmap.md` sec 1, `pdb-ingestion-design.md` sec "Test fixtures" | shipped |
| #179  | PDB ingestion (`src/symbols/pdb.rs`)       | every kg-pe rule that needs PDB-derived types | `pdb-ingestion-design.md` | type path + public function-name binding shipped; alias summaries remain |
| #199  | PE hardening: delay-import / manifest / VersionInfo / TLS callbacks | grounded malware triage, driver TLS-callback bug class | `pe-hardening-design.md` | shipped |
| xrefs | PE direct code-to-data refs                | strings-xrefs, data-use queries, and IDA/Ghidra-style navigation over Windows binaries | `IDA_GHIDRA_PARITY.md` #154/#222; `windows_project_xref_query` tool; `glaurung windows project-xrefs` | selected KB-ref coverage exceeds 90%; UTF-16 raw strings fixed; unified callers/callees/reads/writes project queries shipped; bounded project callgraph reachability now answers source-to-target and upstream-to-sink path questions; project callgraph diffing now compares persisted call/jump edges across builds and feeds patch-diff review; project function-start explanation now joins names, boundaries, chunks, xrefs, and comments for "why is this a function?" review; memory access query now answers who reads/writes persisted fields, base objects, and data targets; data-table facts and diffs now group labels/xrefs/chunks into dispatch, callback, vtable, jump-table, selector, import-thunk, and code-pointer table candidates and compare them across builds; residual PARAM/table-entry refs remain |
| parity | Ghidra regression corpus and debug report | Windows function-start confidence and callback-table discovery | `glaurung_vs_ghidra_vendor_windows.md`, `glaurung-vs-ghidra-regression-review.md`, `glaurung-vs-ghidra-full-debug-review.md` | 30-file stress dashboard; SurfacePen callback-table gap closed; adjustor tiny-stub gate reduced Glaurung-only starts from 27,637 to 3,116; unknown-end call targets no longer claim unbounded interiors; functionization replay fixtures now cover tail-jump thunk promotion only when xref/table/.pdata provenance exists; `glaurung windows project-function-chunks` exposes persisted chunk/thunk/tail facts by VA/kind/owner/target; `glaurung windows project-function-start-explain` classifies strict functions, thunks, chunks/funclets, contained labels, and xref candidates from persisted project facts; `glaurung windows project-symbol-ranges` audits PDB/public symbols against `.pdata`, symbol adjacency, containing ranges, and chunk hints; `glaurung windows project-function-boundary-diff` compares ranges, chunks, thunks, tailcalls, and funclets across projects |
| agents | IDA/Ghidra-like agentic analyst workflows | pydantic-ai Windows review agents over deterministic low-level evidence tools | `agentic-ai-functionality-roadmap.md`, `atomic-tools.md` | roadmap added; notebook round trip now covers prototype and stack-variable type overrides plus CLI import/export; project-level function-start explanation over names/boundaries/chunks/xrefs/comments shipped; low-level project boundary/chunk diffing now feeds patch-diff review |
| contracts | API-contract primitives and sysinfo dispatch facts | proactive high-risk path triage in DLL/SYS/EXE RE workflows | `windows-analysis-config.md`, `atomic-tools.md` | Glaurung IR writes, Rtl string sinks, IOCTL, IO_STACK_LOCATION DeviceIoControl fields, IRP buffer fields, WDF request buffer helpers, pool, registry, object-manager, IRP, MDL, ALPC, ETW/WPP, callback, requestor-mode, privilege-check, and token API contracts, CmpQueryDowncastString wrapper semantics, callsite argument persistence, x64 ABI callsite locations, path-condition attachment, persisted memory operand facts, sysinfo dispatch facts, and reduced fixture replay for API-contract primitive expectations shipped |
| lift | Evidence-backed pretty lift for Windows functions | Ghidra/IDA-like analyst readability while preserving Glaurung facts | `windows_function_pretty_lift` tool, `windows_pretty_lift_agent` | deterministic packet, renderer, validator, pydantic-ai agent prompt, ordered callsite facts, per-argument callsite ABI facts, callsite return-target facts, prototype-backed callsite argument rendering, direct import/thunk spelling normalization for `nt!__imp_Foo`/`j_Foo`/`thunk_Foo`/`Foo$thunk`, import-thunk alias prototype propagation, stdlib type-only prototype role inference, low-confidence local helper prototype inference from argument names, Windows x64 function-entry ABI argument facts, function/call prototype facts, structured path-condition facts including status macros, bounds gates, selector gates, NULL/zero gates, mode gates, and privilege gates, loop summaries, persisted/queryable normalized memory-access facts including typed C dereferences with width metadata, field-offset groups, explicit unknown sections, data-reference facts for globals, global count bounds, selector loads, absolute calls, callback pointers, indexed function-pointer-table dispatch, jump-table dispatch, import-thunk dispatch, and vtable-style dispatch, and validator rejection for omitted API-contract source/sink primitives shipped |
| tables | Project data/table recovery | dispatch tables, callback arrays, vtables, jump tables, selector-indexed globals, count-bounded arrays, import-thunk tables | `windows_project_data_table_facts`, `windows_project_data_table_diff` tools; `glaurung windows project-data-tables`; `glaurung windows project-data-table-diff` | first-class project table candidates from persisted `data_labels`, data xrefs, `function_chunk_facts`, and optional native PE code-pointer scans; rows include table kind, VA, type/size, slot size, entry count, xref counts, source functions, sampled entries, confidence, reason codes, and security relevance hints; table diffs report added/removed/changed dispatch, callback, vtable, selector, import-thunk, and code-pointer candidates across projects |
| patch-diff | Changed-function security fact diffing | Patch Tuesday style review of guards, sinks, constants, helper calls, prototype deltas, boundary drift, table drift, callgraph drift, guard/path-condition drift, and memory read/write drift | `windows_diff_security_relevant_facts`, `windows_project_prototype_diff`, `windows_project_function_boundary_diff`, `windows_project_data_table_diff`, `windows_project_callgraph_diff`, `windows_project_guard_condition_diff`, `windows_project_memory_access_diff` tools | security fact snapshots compare gate calls, operation sinks, helper calls, constants, and deterministic pretty-lift path-condition facts such as bounds/status/mode/privilege guards; project prototype diffing now reports added/removed/changed function signatures, parameter roles, return contracts, calling conventions, and buffer/length risk hints across two `.glaurung` projects; project boundary diffing reports changed ranges, thunks, tailcalls, shared tails, and funclets; project data-table diffing reports dispatch/callback/vtable/selector/import-thunk/table target and layout drift; project callgraph diffing reports added/removed/moved call and jump edges, including sink/API-call deltas; project guard-condition diffing reports changed branch guards and callsite path conditions with bounds/status/mode/user-pointer relevance; project memory-access diffing reports changed field/global/buffer reads and writes, and patch-diff review ranks those prototype, boundary, table, callgraph, guard, and memory deltas into validation packets |
| syscalls | User-mode syscall stub atlas, diff, and handler correlation | SSDT-like service-number materialization from `ntdll`/`win32u` before live table comparison | `windows_syscall_stub_atlas`, `windows_syscall_atlas_diff`, `windows_syscall_handler_correlate` tools | PE `binary_path` export scanning, lifted `ret/eax = imm; syscall`, assembly `mov eax, imm; syscall`, and raw x64 `mov r10, rcx; mov eax, imm32; ...; syscall; ret` rows with export symbol or byte offset, RVA/VA/file offset, section, module, service-table family, service number, confidence, byte-pattern evidence, dispatch shape, KUSER_SHARED_DATA syscall-gate detection, legacy `int 2e` fallback detection, coverage flags, optional KB evidence node, reduced replay-fixture coverage, atlas diff rows for added/removed/renumbered/moved/byte-pattern/dispatch-shape-changed service entries, and handler correlation through PDB-backed `.glaurung` `function_names` or an external precomputed handler map shipped; true live SSDT comparison remains future work |
| live-kernel | Read-only live Windows kernel fact import | Ground static RE against observed runtime state without hook/write behavior | `windows_live_kernel_snapshot` tool | Normalizes external WinDbg/PowerShell/collector JSON into kernel build identity, loaded-module ranges, live syscall-table rows, registered callbacks, driver objects, driver dispatch tables, ETW/WPP providers, and object-manager namespace rows; attributes handler/routine/provider VAs to module ranges; joins optional static expected syscall-handler maps; flags syscall handlers outside loaded modules, unexpected modules, and expected-handler mismatches; optional KB evidence node shipped |
| #186  | BSim-equivalent function similarity         | Patch Tuesday cross-build diff for n-day | `bsim-similarity-design.md`, `windows_function_similarity_manifest` tool | initial deterministic opcode/byte n-gram similarity manifest shipped; output feeds `windows_patch_function_identity_extract` as an external similarity manifest; Ghidra BSim extraction remains the high-confidence external path |
| tools | 12-15 Windows-specific `llm/tools/` files   | rule-as-tool encoding for tier-1 bug classes | `atomic-tools.md` | not started |

## Authoring conventions

- ASCII only; no em-dashes, smart quotes, ellipsis, NBSP, arrows.
  These docs and any Glaurung commits they motivate get scrubbed
  before merge (asb has an `ascii-scrub` skill; Glaurung side
  uses `pre-commit` + a similar grep gate).
- Every Glaurung commit asb drives carries the
  `Assisted-by: Claude:claude-opus-4-7` trailer per the kernel
  coding-assistants doc. Do NOT use the
  `Name <email>` form; bot/co-author trailers are the wrong
  shape for assistant attribution.
- Each per-feature doc is 200-500 lines and self-contained: a
  reader landing on `pdb-ingestion-design.md` should not have
  to read `roadmap.md` to understand scope.
