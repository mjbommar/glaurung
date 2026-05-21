# Agentic AI Functionality Roadmap for Windows Analysis

Date: 2026-05-20

This roadmap converts the 30-file Glaurung-vs-Ghidra regression review
into implementation work for agentic Windows analysis. The goal is not
to clone Ghidra or IDA Pro feature by feature. The goal is to give
pydantic-ai agents deterministic, typed, reviewable primitives that let
them behave like a careful analyst: ask why an address is a function,
walk xrefs, inspect evidence, classify uncertainty, preserve notes, and
refuse to promote a candidate when the substrate is weak.

## Evidence Base

The current conclusions come from these checked-in artifacts:

- `glaurung_vs_ghidra_vendor_windows_30.json`: raw 30-file comparison
  over the original 10 fixtures plus 20 additional Windows system,
  application, driver, and vendor binaries.
- `glaurung_vs_ghidra_vendor_windows_30.md`: tabular dashboard for the
  first 30-file run.
- `glaurung_vs_ghidra_vendor_windows_30_diagnostics.json`: per-address
  diagnostics used to inspect missing and extra starts.
- `glaurung-vs-ghidra-full-debug-review.md`: human debug review of all
  30 files.
- `glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.json` and
  `.md`: post-fix comparison after the adjustor tiny-stub gate and
  padded REX import-thunk follow-up.

The post-fix result is the most important baseline for future work:

| Metric | Before | After |
| --- | ---: | ---: |
| Glaurung functions | 98,070 | 73,580 |
| Ghidra internal functions | 71,505 | 71,505 |
| Ghidra-only starts | 1,072 | 1,041 |
| Glaurung-only starts | 27,637 | 3,116 |
| Address recall vs Ghidra | 98.50% | 98.54% |

The lesson is that Glaurung has strong discovery coverage, but the
agent-facing abstraction cannot be a flat list of "functions." It needs
function starts, code labels, low-confidence candidates, and rejected
starts as separate states with explanations.

## What The 30 Files Taught Us

The original 10-file suite still looks healthy. Exact parity remains for
`win10-vwififlt.sys`, `win10-audmigplugin.dll`, and
`windows-update-SurfacePenBleLcAddrAdaptationDriver.sys`; the remaining
small-suite gaps are mostly tiny helpers, shared epilogue labels, or
small thunk/wrapper differences.

The 20-file expansion changed the quality bar. Large COM, C++,
graphics, NPU, XRT, Wi-Fi, and deployment DLLs expose problems that do
not show up in the small suite:

- Tiny helpers remain the largest recall gap. Most Ghidra-only starts
  have very small bodies, and many are wrappers, import thunks, scalar
  return helpers, or short method entries.
- Blind tiny-stub promotion was the dominant precision gap before the
  fix. NPU, XRT, and D3D runtime binaries turned useful local code
  discoveries into thousands of false top-level functions.
- COM and vtable-heavy DLLs expose body over-merge. `webservices.dll`,
  `dismapi.dll`, `wdscore.dll`, `netsetupapi.dll`, and vendor DLLs
  often have Ghidra-like starts inside one broad Glaurung function.
- SIMD-headed starts need context. Some are false starts in the middle
  of a vector instruction region; some are real no-`.pdata` functions
  that Ghidra promotes.
- Data-reference starts are valuable but need stronger boundary gates.
  The SurfacePen callback-table case is a success, while `NETwtw10.sys`
  exposed padding-run false positives.
- Padded `48 ff 25 rel32` import thunks are real Ghidra parity targets.
  They are tiny, no-`.pdata`, and common enough to deserve a dedicated
  thunk catalog.

For bug hunting, these are not cosmetic differences. A human analyst in
IDA Pro or Ghidra relies on function boundaries, labels, xrefs, names,
types, comments, graph views, and decompiler slices as the substrate for
every higher-level decision. If Glaurung gives an agent a noisy function
list, the agent will waste context on false starts and may attach sink,
gate, or source evidence to the wrong body.

## IDA Pro And Ghidra Parity Concepts

The next Glaurung work should emulate the analyst affordances that make
IDA Pro and Ghidra effective, not just their disassembly output:

- Function vs label vs candidate state. Ghidra can carry symbols,
  labels, thunks, and functions separately. Glaurung needs the same
  distinction in public APIs and project facts.
- Explainable function starts. An analyst can inspect prologue,
  `.pdata`, xrefs, imports, padding, table references, and prior bytes.
  Agents need a typed one-call explanation for the same evidence.
- Xref navigation. Callers, callees, data refs, vtables, imports,
  exports, and thunk chains should be cheap to query and bounded.
- Persistent analyst database. Names, comments, labels, confidence
  changes, and suppression decisions must be saved and replayable.
- Diffable views. Patch Tuesday and vendor-driver triage need changed
  functions, function similarity, added/removed imports, and changed
  xref topology.
- Bounded decompiler context. Agents should receive compact function
  packets with disassembly, CFG, operand facts, call arguments, types,
  strings, and known gaps instead of raw whole-binary dumps.
- Worklists. IDA and Ghidra analysts live from sorted lists of unknowns:
  suspicious xrefs, changed functions, unresolved thunks, untyped data,
  and uncertain boundaries. Agents need the same ranked queues.

## Design Principle

Agents should not parse bytes by intuition. They should orchestrate
deterministic tools that return Pydantic models. The LLM layer should
rank, plan, compare, summarize, and ask the next question; the substrate
should perform parsing, mapping, graph queries, and evidence checks.

Every agent conclusion should carry:

- Evidence ids or exact addresses.
- Tool names and input arguments.
- Confidence and reason codes.
- Missing facts and blockers.
- Whether the claim is a functionization fact, triage hypothesis,
  candidate packet, validation plan, or reproduced issue.

This matches the existing `AnalysisResult` and iterative-agent direction
in `python/glaurung/llm/agents/`: confidence, evidence count, tools
used, loop detection, and explicit termination reasons are already part
of the agent API. The missing work is mostly the low-level Windows
evidence tools and replay tests that make those agent loops trustworthy.

## Low-Level Agent Primitives To Build

These are deterministic tools or project facts. They are useful to
humans, agents, and regression tests.

| Priority | Capability | What It Returns | Regression Targets |
| ---: | --- | --- | --- |
| 1 | `windows_function_start_explain` | For one VA: section, bytes before/after, seed kinds, `.pdata` relation, code-pointer provenance, xrefs, padding, thunk shape, Ghidra delta, final state | SurfacePen callback table, NETwtw padding false positives, Dism tiny helpers, WDScore thunks |
| 2 | `windows_function_boundary_diff` | Per-binary Glaurung/Ghidra/IDA-style functionization buckets: missing, extra, label-only, candidate, internal split, thunk mismatch | All 30 fixtures |
| 3 | `windows_candidate_start_worklist` | Ranked uncertain starts with reason codes and expected next evidence query | NPU, XRT, WebServices, Realtek |
| 4 | Public function/label/candidate model | Stable Python and JSON distinction between strict functions, labels, candidates, and rejected starts | NPU/XRT precision cases |
| 5 | `windows_import_thunk_catalog` | IAT/direct thunk inventory, including `ff 25`, `48 ff 25`, `mov rax; jmp rax`, call-return wrappers, and target import names | DismCore, WDScore, NetSetupAPI |
| 6 | `windows_data_ref_confidence` | Code-pointer table provenance, table width, target alignment, target section, padding gates, table consistency, source refs | SurfacePen true positive, NETwtw padding false positive |
| 7 | `windows_function_body_split_candidates` | Strong internal starts inside broad owners, with owner function, evidence class, body overlap, and suggested split confidence | WebServices, RtkAudUService64, DismAPI |
| 8 | `windows_simd_start_classifier` | Context-sensitive SIMD-headed start classification using xrefs, table membership, boundary bytes, and instruction-continuation evidence | NPU Level Zero, ze_loader |
| 9 | `windows_decompile_context_packet` | Bounded function packet: disassembly, CFG summary, calls, operands, strings, data labels, PDB names/types, comments, and known gaps | Any selected candidate |
| 10 | `windows_agent_evidence_bundle` | Standard packet schema for claims, with evidence refs, blockers, project coverage, Ghidra delta, validation status, and claim level | Candidate packet and validation tools |

Implementation status: priorities 1-10 now have initial
agent-callable tools with focused regression coverage. Priority 8 is
implemented as `windows_simd_start_classifier`, which composes
`windows_function_start_explain` and classifies SIMD-headed starts as
strict functions, provenance-backed starts, boundary-review candidates,
body-split candidates, vector-block labels, or rejects. Priority 9 is
implemented as `windows_decompile_context_packet`, a bounded function
packet that joins decompiler text, disassembly, CFG shape, calls,
optional `.glaurung` names/comments/data labels, missing-capability
flags, and the shared evidence-bundle schema.

Several adjacent primitives already exist and should be reused rather
than replaced: project fact summaries, callgraph slices, CFG path
queries, call argument snapshots, memory operand facts, return-value
use snapshots, branch-condition facts, data-label facts, operation risk
summaries, candidate packet composition, VM validation plans, and
runtime artifact bundle import.

Update: `windows_function_start_explain` and
`windows_candidate_start_worklist` now consume native per-address
`scan_rejections` from the comparison stats. A function-start answer can
show the rejected VA, optional source VA, scanner reason, and detail,
and the worklist carries those scanner rejection reasons forward beside
the usual Ghidra/Glaurung diagnostic state. This closes the first loop
from Rust scanner gate to analyst-facing explanation.

Update: `windows_scan_rejection_dashboard` now gives agents a
corpus-level view of scanner rejection gates. It reads cached
Glaurung/Ghidra diagnostics, summarizes aggregate
`scan_rejection_counts`, correlates per-address `scan_rejections` with
Ghidra-only starts when available, and can optionally rerun native
function discovery over local PE paths to get fresh address-level
rejection samples. Rows report cached/native counts, affected files,
Ghidra-missing address hits, precision-guard ratios, recall-risk level,
reason codes, and next actions. This turns rejection gates from
debug-only counters into reviewable precision/recall telemetry.

## High-Level Agents To Implement And Test

The low-level tools become useful when they are composed into specific
agent workflows. These agents should use pydantic-ai structured outputs,
bounded tool budgets, and deterministic replay fixtures.

### 1. Functionization Review Agent

Purpose: behave like an analyst comparing Glaurung against Ghidra or
IDA. It consumes `windows_function_boundary_diff`, samples high-impact
missing/extra starts, calls `windows_function_start_explain`, and emits
one of: accept as function, demote to label, keep as candidate, reject,
or open rule-work item.

Exit criteria:

- It can replay the 30-file suite and produce the same top issue
  classes as the human debug review.
- It never recommends blind promotion without provenance.
- It emits exact addresses and seed kinds for every recommendation.

### 2. Triage Worklist Agent

Purpose: turn large project metrics into a short analyst queue. It
ranks changed functions, sink-heavy functions, uncertain boundaries,
unresolved imports, untyped globals, and missing gate/source evidence.

Exit criteria:

- It produces bounded top-N queues for all 30 fixtures.
- Queue items include why the target matters, what evidence is present,
  and the next tool call.
- Re-running with the same facts is stable enough for regression tests.

Status: initial deterministic replay workflow added as
`glaurung.llm.agents.windows_triage_worklist`. The first version
combines boundary precision gaps, boundary recall gaps, uncertain
function starts, body-split candidates, and import-thunk gaps into a
stable ranked queue with exact next tools, next args, bounded
non-finding claim level, and shared evidence-bundle output. The next
extension should add changed-function, sink-heavy, untyped-global, and
gate/source blocker queues from project facts and patch-diff manifests.

Update: triage worklists now have first-class queue kinds for
`changed_function`, `sink_heavy`, `untyped_global`, and
`gate_source_blocker`. The workflow accepts changed-function facts,
persisted project fact records, and operation-risk groups from existing
project tools, ranks them alongside functionization items, and preserves
the deterministic next tool for patch-diff, sink-to-gate, and project
fact follow-up.

Update: triage worklist now accepts `project_fact_manifest_path` and
loads persisted `.glaurung` project fact records through
`windows_project_fact_manifest` itself. Results include the loaded
manifest path and record count, and project coverage gaps can enter the
queue without the caller pre-materializing `ProjectFactRecord` objects.

Update: triage worklist can now derive two high-value queue sources
directly. When given `diff_binary_a` and `diff_binary_b`, it invokes
`windows_binary_diff_summary` and converts changed/added/removed rows
into `changed_function` work items. When given `project_path` plus
`project_binary`, it invokes `windows_project_operation_risk_summary`
and converts sink-heavy or missing-gate/source groups into `sink_heavy`
or `gate_source_blocker` work items. Results carry derived fact counts
and record both automatic tools in the sequence and evidence coverage.

Update: triage worklist can now accept a `windows_build_corpus` lookup
config and use target/component metadata to resolve corpus binary paths,
`.glaurung` project paths, and two-build diff pairs before queue
ranking. Explicit caller-provided diff/project fields still win. The
result preserves a typed build-corpus resolution record plus evidence
bundle attributes for the manifest path, matched target count, resolved
binary path, project path, and diff pair.

Update: triage worklist can now use build-corpus metadata to create
ranked high-volume target work items without a caller-selected target
filter. `auto_select_high_volume_targets=true` scores corpus targets by
priority label, binary kind, attacker surface, scan role, and resolved
binary/project evidence, then inserts `high_volume_target` queue items
with deterministic reason codes and `windows_triage_worklist` next
args. This gives agents a bounded starting queue from a whole Windows
target manifest instead of requiring a manually chosen component.

Update: triage worklist can now turn those selected high-volume targets
into downstream batch handoffs. With
`fanout_high_volume_target_batches=true`, selected targets get typed
`WindowsTriageTargetFanoutBatch` plans that preserve the target id,
manifest path, corpus/project roots, resolved PE and `.glaurung` paths,
sink/source/gate metadata paths, packet bounds, and blockers. Ready
queue items point at `windows_validation_planning_batch` with exact
handoff args instead of only re-queueing the target name.

### 3. Sink-To-Gate Agent

Purpose: use existing Windows source/gate/sink tools to inspect whether
a candidate sink has local source evidence, local gate evidence, CFG
dominance, and argument-role evidence.

Exit criteria:

- It attaches `windows_project_call_argument_snapshot`,
  `windows_project_cfg_path_query`, branch conditions, and operation
  metadata to every candidate packet.
- It marks blockers explicitly instead of claiming end-to-end
  reachability from local evidence.

Status: initial deterministic replay workflow added as
`glaurung.llm.agents.windows_sink_to_gate_review`. It composes
`windows_source_sink_operand_match`, `windows_cfg_gate_to_sink`, and
`windows_emit_review_packet` through
`windows_compose_source_gate_sink_packet`, preserves operand status,
gate status, missing required gate semantics, promotion blockers, exact
tool sequence, and shared evidence-bundle output. The next extension
should attach persisted project call-argument snapshots, project CFG
path queries, and branch-condition facts directly when a `.glaurung`
project is supplied.

Update: sink-to-gate review now accepts persisted project
call-argument snapshots, project CFG path-query results, and
branch-condition facts as explicit review inputs. It carries their
counts and coverage into the evidence bundle and blocks the packet when
a project CFG query reports bypass/unknown/unreachable gate coverage or
when call-argument snapshots report missing capabilities.

Update: sink-to-gate review now also accepts `project_path` and
`binary_path` for automatic project fact invocation. When supplied, it
calls `windows_project_cfg_path_query`,
`windows_project_branch_condition_facts`, and
`windows_project_call_argument_snapshot` directly, merges those results
with caller-provided facts, records auto tool names in the sequence, and
turns missing or incomplete auto facts into explicit blockers.

Update: sink-to-gate review now resolves automatic project context from
review packets as well as explicit config. If the composed packet or a
handoff `candidate_packet` carries `project_facts.project_path`, the
agent can invoke project CFG and branch-condition tools without a
separate `project_path` field. This also works when
`packet_args.auto_join_manifest_context` populates project facts from a
project-fact manifest. Binary-path inference remains conservative: the
call-argument snapshot tool runs automatically only when `binary_path`
is explicit or the packet binary is an existing path.

Update: sink-to-gate review can now use `windows_build_corpus` metadata
as a fallback resolver for automatic project context. When explicit
paths and packet facts are absent, a build-corpus lookup can provide
the `.glaurung` project path and PE binary path, allowing
`windows_project_call_argument_snapshot`,
`windows_project_cfg_path_query`, and branch-condition extraction to run
from target/component metadata. The result records the resolved paths,
matched target count, and build-corpus manifest path in both the typed
result and evidence-bundle attributes.

Update: sink-to-gate review now has a typed batch runner,
`run_windows_sink_to_gate_review_batch`, with `WindowsSinkToGateReviewBatchConfig`
and result models exported through `glaurung.llm.agents`. A batch keeps
the same non-finding claim level, runs a bounded list of concrete
reviews, aggregates blockers, promotion-precondition counts, child tool
sequences, candidate ids, and shared evidence coverage. This gives
agents a single durable artifact for reviewing a cluster of sink
callsites instead of one manually supplied VA at a time.

Update: sink-to-gate batch review can now consume already-emitted
candidate packets, either in memory or from a JSON/YAML packet artifact
with `candidate_packets`/`packets`. This lets
`windows_project_sink_call_packets`, validation-planning fanout, and
evidence-review handoffs feed static sink-to-gate batch review without
manually reconstructing `WindowsComposeSourceGateSinkPacketArgs` for
each callsite.

### 4. Patch-Diff Review Agent

Purpose: act like a Patch Tuesday analyst. It consumes changed-function
facts, similarity, imports, PDB identities, known seed metadata, and
functionization confidence. It ranks changed areas for review without
turning a public seed into a finding by default.

Exit criteria:

- It can explain why a changed function is high priority.
- It records whether function matching was hash-based, name-based,
  PDB-backed, similarity-backed, or uncertain.
- It preserves low confidence when boundaries differ between builds.

Status: initial deterministic replay workflow added as
`glaurung.llm.agents.windows_patch_diff_review`. It composes
`windows_binary_diff_summary`, optional
`windows_seed_binary_diff_triage`, and optional
`windows_diff_security_relevant_facts` into a bounded changed-function
queue. Review items carry match basis, PDB-backed identity, public-seed
prior-art reason codes, next tools, shared evidence-bundle output, and
functionization blockers that cap confidence instead of hiding boundary
uncertainty. The next extension should consume richer PDB/function
similarity data from real Windows patch pairs rather than synthetic
name/hash fixtures.

Update: patch-diff review now accepts per-function identity records
with match basis, PDB symbol/GUID-age, similarity score, algorithm, and
per-function functionization blockers. Review items preserve
`pdb_backed_identity`, `similarity_backed_function_match`, algorithm
provenance, and confidence caps when the matching substrate is weak.
It also accepts a persisted YAML identity manifest through
`function_identity_path`, validates each entry as a
`WindowsPatchFunctionIdentity`, records
`windows_patch_function_identity_manifest` in the tool sequence, and
threads manifest-derived identity facts through ranking, confidence,
reason codes, and evidence coverage.

Update: patch-diff review can now invoke
`windows_pdb_identity_manifest` directly. When the manifest query
returns cached PDB records for the target/component/build, the agent
synthesizes PDB-backed per-function identity evidence for changed,
added, and removed diff rows without requiring a prewritten
`function_identity_path` YAML artifact. The result records the PDB
identity manifest path, cached record count, tool sequencing, and
per-function identity coverage. The remaining gap is true symbol-level
function matching and BSim/similarity extraction from real Windows patch
pairs.

Update: `windows_patch_function_identity_extract` now produces a
reusable per-function identity manifest for patch-diff review. It runs
`windows_binary_diff_summary`, optionally joins
`windows_pdb_identity_manifest`, computes deterministic size/hash
similarity scores, writes YAML identity records compatible with
`WindowsPatchDiffReviewConfig.function_identity_path`, and records
PDB/similarity provenance. Focused tests verify that the emitted
manifest feeds back into `windows_patch_diff_review` as PDB-backed and
similarity-backed per-function identity evidence. The remaining gap is
external BSim/symbol-server extraction over real Windows patch pairs,
not the internal handoff format.

Update: `windows_patch_function_identity_extract` now accepts
`external_similarity_manifest_path`, a JSON/YAML handoff from an
external similarity system such as BSim. Entries keyed by function name
can provide `similarity_score`, `similarity_algorithm`,
`matched_function`, and evidence strings; those values override the
lightweight size/hash score while preserving the same review-compatible
identity YAML. Focused tests feed a synthetic `ghidra_bsim_export`
manifest into the extractor and verify that `windows_patch_diff_review`
receives the external algorithm provenance. The remaining gap is
automating real Windows BSim/symbol-server extraction, not consuming its
output.

Update: `windows_project_prototype_diff` now compares persisted
`function_prototypes` across two `.glaurung` projects. It reports
added, removed, changed, and unchanged signatures, changed return
types, parameter names/types/roles, variadic state, calling convention,
module, and risk tags. Deltas carry Patch Tuesday relevance hints for
role, buffer/pointer, length/count, and return-contract changes and are
also exposed through `glaurung windows project-prototype-diff`. This is
patch-triage metadata for routing changed functions into source/sink
review, not standalone vulnerability evidence.

Update: patch-diff review now accepts optional before/after
`.glaurung` project paths and invokes `windows_project_prototype_diff`
as part of the deterministic review. Changed prototypes become
first-class `prototype_delta` review items with match-basis and
reason-code evidence, security-relevant prototype changes route to
`windows_sink_to_gate_review`, and `windows_patch_diff_packets`
preserves those items as validation packets.

Update: `windows_symbol_similarity_extraction_plan` now creates the
runner-facing bridge for that gap. Given a Windows patch pair,
target/component labels, optional PDB identity metadata, symbol-cache
root, Ghidra project directory, and artifact directory, it emits
tool-readiness checks, symbol-cache commands, Ghidra import commands,
BSim index/query commands, the expected external-similarity manifest
path, and the exact `windows_patch_function_identity_extract` handoff
args. It can also write a shell script for a prepared Ghidra/BSim
runner. This is still an extraction plan rather than proof that BSim
has run on the current machine, but it turns symbol/similarity blockers
into executable runner work instead of an undefined manual step.

### 5. Validation Planning Agent

Purpose: convert a static candidate packet into a VM/harness plan and
refuse to call the issue reproduced until runtime artifacts exist.

Exit criteria:

- It emits a snapshot, harness, KDNET/debugging preconditions, required
  artifacts, and stock/current comparison plan.
- It imports runtime artifact bundles and maps them back to the static
  candidate.
- It distinguishes `validation_plan_not_reproduction`,
  `runtime_artifact_bundle_not_finding`, and reproduced issue states.

Status: initial deterministic replay workflow added as
`glaurung.llm.agents.windows_validation_planning`. It composes
`windows_emit_vm_validation_plan`, optional
`windows_validation_harness_recipe`,
`windows_record_validation_artifact_bundle`,
`windows_record_candidate_snapshot_mapping`, and
`windows_emit_validation_harness_template`. The workflow emits snapshot,
KDNET/debugger, harness, required-artifact, stock/current comparison,
mapping, runtime blocker, and shared evidence-bundle state without
promoting a finding. It distinguishes plan-only, runtime-artifact
bundle, and crash-observed-needs-human-review states while keeping the
evidence bundle bounded to non-finding claim levels. The next extension
should run it over real candidate packets emitted from `.glaurung`
projects and ASB validation inventories.

Update: validation planning now emits a typed candidate-grounding
record that distinguishes `.glaurung` project packets, ASB validation
inventory handoffs, and manual packets. The grounding record preserves
project path, validation inventory path, project fact coverage, missing
facts, and blockers when project grounding is required but absent.

Update: validation planning now has
`run_windows_validation_planning_batch`, with typed batch config/result
models. It runs the deterministic planning workflow over multiple
candidate packets, preserves per-candidate grounding, reports
ready/blocked/review counts, aggregates blockers and evidence refs, and
keeps the batch claim level at `validation_batch_not_reproduction`.

Update: batch validation planning now accepts a persisted
`candidate_packets_path` JSON/YAML artifact. The loader handles raw
`WindowsReviewPacket` lists as well as project-tool wrapper shapes such
as `{"packets": [{"packet": ...}]}`, validates each packet, records the
artifact path and loaded count, and adds `candidate_packet_artifact_loader`
to the replay sequence.

Update: batch validation planning can now invoke
`windows_project_sink_call_packets` directly from config before running
runtime handoff planning. The batch result records the project path and
emitted packet count, includes `windows_project_sink_call_packets` in
the tool sequence, and passes emitted `.glaurung` project-backed packets
through the same grounding, validation-inventory, mapping, and evidence
bundle path as persisted packet artifacts.

Update: batch validation planning can now use `windows_build_corpus`
metadata to discover project packet sources from target/component
metadata. `WindowsValidationBuildCorpusPacketScanConfig` resolves a
`.glaurung` project path and PE binary path through corpus/project
globs, invokes `windows_project_sink_call_packets`, then feeds the
emitted packets through the same validation-inventory, grounding,
snapshot-mapping, and evidence-bundle path. Results preserve the
build-corpus manifest path, matched target count, emitted packet count,
resolved project path, and resolved binary path.

Update: batch validation planning now accepts multiple
build-corpus-backed project packet scans in
`build_corpus_project_sink_call_packet_batches`. This executes a list of
target fanout scans in one deterministic batch, sums emitted project
packets and matched targets, records the batch count, and then feeds all
emitted packets through the same VM/harness planning path.

Update: validation planning batch can now write the candidate packets it
loaded or emitted to a JSON handoff artifact via
`candidate_packets_export_path`. The artifact uses a non-finding claim
level and the same `candidate_packets` shape consumed by sink-to-gate
batch review and evidence-review handoff paths.

Update: batch validation planning can now consume evidence-review export
manifests as durable handoff inputs. `evidence_export_manifest_path`
loads the manifest, follows its `candidate_packets_path`, validates the
structured `WindowsReviewPacket` artifact, and plans those packets
through the same VM, harness, grounding, mapping, and evidence-bundle
workflow. Results preserve the export-manifest path, candidate-packet
artifact path, loaded packet counts, and loader tool sequence.

Update: batch validation planning can now consume ASB Windows
vulnerability invariant seeds as another bounded packet source.
`windows_vulnerability_seed_packets` converts
`pe-vulnerability-seeds.yaml` records into non-finding
`WindowsReviewPacket`s with public seed ids, invariant family,
expected source roles, expected gates, sinks, diff signals, validation
requirements, and component-profile context. Validation batches preserve
the seed manifest path, emitted seed-packet count, and tool sequence,
then feed those packets through the same grounding, VM/harness planning,
snapshot mapping, and evidence-bundle path as project sink packets.

Update: batch validation planning can now also consume ASB operation
classification backlog entries as bounded packet sources.
`windows_operation_backlog_packets` converts
`pe-operation-classification-backlog.yaml` rows into non-finding review
packets with observed symbol/caller metadata, likely security
relevance, candidate operation kinds, required capabilities, recommended
next actions, and explicit source/gate blockers. These packets are
classifier work items, not sink proof, and flow through the same
validation-planning batch path as project sink packets and vulnerability
seed packets.

Update: batch validation planning can now consume patch-diff review
output as another bounded packet source. `windows_patch_diff_packets`
runs the deterministic patch-diff review workflow, converts ranked
changed-function or security-delta review items into non-finding
`WindowsReviewPacket`s, preserves match basis, identity confidence,
reason codes, binary-diff counts, and diff context, and marks source
proof as missing until project/source/gate/runtime evidence exists.
Those packets flow through the same validation-planning batch path as
project sink packets, public vulnerability seeds, and operation-backlog
packets.

### 6. Analyst Notebook Agent

Purpose: persist analyst decisions as project facts: names, comments,
labels, prototype and stack-variable type overrides, demotions,
suppressions, and rationale. It should be able to export IDA/Ghidra
scripts and re-import known names/comments/types.

Exit criteria:

- Renames and comments survive project rebuilds.
- A demoted false function remains visible as a label or suppression,
  not a silent deletion.
- The notebook can generate a compact review transcript.

Status: initial deterministic replay workflow added as
`glaurung.llm.agents.windows_analyst_notebook_review`. It wraps
`windows_analyst_notebook` in an import-and-verify loop: apply names,
comments, data labels, demotions, and suppressions; re-export the
project; verify each decision survived; and emit a compact transcript
plus IDA/Ghidra script handoff. Demotions remain visible as
function-start decisions, comments, and bookmarks rather than silent
deletions. The next extension should attach notebook decisions directly
to functionization review items and candidate packets.

Update: candidate review packets can now carry analyst notebook
decisions directly. `WindowsEmitReviewPacketArgs` and
`WindowsReviewPacket` include `notebook_decisions`, so comments, names,
function-start decisions, demotions, and suppressions can flow with the
candidate handoff instead of living only in a separate notebook JSON.
`windows_emit_review_packet` adds notebook decisions to packet
provenance and evidence-bundle refs, records
`analyst_notebook_decisions` in coverage, and treats attached demotions
or suppressions as explicit promotion blockers. This closes the
candidate-packet half of the notebook integration.

Update: functionization review can now attach analyst notebook
decisions too. `WindowsFunctionizationReviewConfig.notebook_decisions`
matches comments, function-start decisions, demotions, and suppressions
against reviewed candidate-start, body-split, and import-thunk rows by
VA. Matching decisions are returned as typed `notebook_attachments`,
added to the evidence bundle as `windows_analyst_notebook` refs, and
recorded as `analyst_notebook_decisions` coverage. Suppressions and
demotions become explicit functionization-review blockers, preventing
scanner or baseline promotion from ignoring an analyst's prior
false-start decision.

Update: analyst notebook round trip now includes prototype and
stack-variable type override decisions. Export mode emits project
`function_prototypes` and `stack_frame_vars` as typed notebook
decisions alongside names, comments, labels, and function-start
decisions. Import mode applies prototype and stack-variable decisions
back into the project, and manual prototype writes now participate in
the undo log. The same workflow is exposed as
`glaurung windows analyst-notebook` for command-line import/export.

### 7. Rule Authoring Agent

Purpose: translate repeated evidence patterns into deterministic tool
or scanner work items. It should propose tests first, then a code-level
change.

Exit criteria:

- It can turn the NPU/XRT tiny-stub over-promotion class into a rule
  with true-positive and false-positive fixtures.
- It can propose new seed-class precision metrics without changing
  production code itself.

Status: initial deterministic replay workflow added as
`glaurung.llm.agents.windows_rule_authoring`. It consumes the 30-file
Ghidra parity dashboard through `windows_function_boundary_diff` and
emits test-first scanner work items, not code edits. The first workflow
turns the NPU/XRT tiny-stub over-promotion class into a
`win-pe-tiny-stub-provenance-gate` work item with negative and positive
fixture proposals, non-goals, implementation scope, and seed-class
precision metrics. It also proposes import-thunk, data-ref, and
body-split metric guards when the comparison rows justify them. The
next extension should materialize the proposed fixtures into checked-in
replay YAML before production scanner changes are attempted.

Update: the rule-authoring agent now emits concrete
`WindowsRuleReplayFixture` records and can materialize them with
`materialize_fixtures=true`. The checked-in replay set lives at
`python/tests/fixtures/windows/functionization_rule_fixtures.yaml` and
covers tiny-stub, data-ref, import-thunk, and body-split rule work
items with positive, negative, and metric-guard cases.

Update: `windows_functionization_rule_replay` now consumes the
checked-in fixture YAML directly and replays it against the cached
30-file Glaurung/Ghidra dashboard. It reports per-rule and per-case
pass/fail/unsupported status, can add a compact evidence node to the
KB, and is registered with `memory_agent`. The current dashboard replay
passes all 4 fixture groups and all 9 checked-in cases. This is still a
fixture/dashboard coverage replay, not a production scanner semantic
proof.

Update: `windows_functionization_rule_replay` now has an initial
concrete-byte replay mode. Fixture cases can include `bytes_hex`,
`address`, and provenance flags such as `has_import_target`,
`has_xref`, `has_table_provenance`, `owner_function`, or
`shared_epilogue`; the replay tool classifies those bytes for the
tiny-stub, import-thunk, data-ref padding, and body-split rule families
and reports the expected vs actual state in case details. Focused tests
cover `xor eax,eax; ret`, padded `48 ff 25` import thunks, and `cc`
padding runs without relying on dashboard rows.

Update: `windows_functionization_rule_replay` now also supports native
Glaurung analyzer replay. Fixture cases can include `binary_path` and
`address`; the tool runs
`g.analysis.analyze_functions_path_with_stats` on the named PE and
checks whether the address is emitted as a function start. Case details
record native function count, seed kind, and truncation state, giving
rule fixtures a direct check against current native scanner behavior on
vendored Windows binaries.

Update: native analyzer replay now surfaces structured reason codes
derived from Glaurung's own `function_seed_kinds`, `seed_provenance`,
and `code_labels` stats. Fixture cases can assert `expected_seed_kind`,
and replay details include `seed_kind:*`, `seed_detail:*`,
`code_label_kind:*`, owner labels, and truncation markers. This turns
native replay from a bare emitted/not-emitted check into a scanner
provenance check without adding a new Rust API.

Update: native replay now covers both positive and negative real-PE
fixtures. The focused test includes a SurfacePen entrypoint that must be
emitted with `seed_kind:entrypoint`, and an Intel NPU `ze_loader.dll`
SIMD-headed Ghidra-only address that must remain `candidate_or_label`
with `seed_kind:none`. This gives the rule replay harness regression
coverage for scanner promotion and scanner demotion behavior.

Update: `windows_project_function_start_explain` now provides the
project-workspace version of "why is this a function?" It resolves a VA
or symbol inside a `.glaurung` project, joins persisted
`function_names`, `function_boundaries`, `function_chunk_facts`,
incoming/outgoing xrefs, and comments, then classifies the target as a
strict function, thunk, chunk/funclet, contained label, xref candidate,
symbol-only row, or no-evidence target. The result includes reason
codes, confidence, and a recommended next action, and the CLI exposes it
as `glaurung windows project-function-start-explain`.

Update: the native positive/negative replay cases are now part of the
checked-in `functionization_rule_fixtures.yaml`, so the default replay
path covers 5 fixture groups and 11 cases rather than keeping native
scanner checks only in an isolated unit test. The native group records
emitted and non-emitted real-PE starts with expected seed-kind
provenance.

Update: native replay now reads target PE head bytes for `binary_path`
cases and emits scanner-relevant byte reason codes such as
`native_head:simd`, `native_head:padding`, `native_head:tiny_return_helper`,
and `native_head:indirect_jump_thunk_shape`. The checked-in Intel NPU
SIMD negative fixture now proves both that the address is not emitted
and that the rejected head bytes begin with the SIMD pattern under
review.

Update: Rust function discovery now emits `scan_rejection_counts` in
`analyze_functions_*_with_stats`. The map records scanner-internal
rejection gates such as known prologue/thunk/tiny-stub seeds,
unpromoted tiny-stub candidates, weak data-reference pointers,
known-or-`.pdata` data refs, and body-overlap rejections by seed kind.
`windows_functionization_rule_replay` carries those counters into native
replay details and `scan_rejection:*` reason codes, so fixtures can
distinguish "not emitted" from "not emitted because a specific scanner
gate rejected it."

Update: Rust function discovery now also emits per-address
`scan_rejections` records with rejected VA, optional source VA, reason,
and detail. Python bindings expose those records beside the aggregate
counts, and `windows_functionization_rule_replay` reports
`scan_rejection_at_address:*` reason codes plus
`native_address_scan_rejections=...` details when a native fixture
targets a rejected VA. Focused tests cover structured facts containing
data-reference and body-overlap rejection records and a replay fixture
that proves a specific rejected address carries the scanner gate that
blocked promotion.

Update: `windows_scan_rejection_dashboard` now closes the corpus-level
half of that loop. It summarizes rejection reasons across the cached
30-file diagnostics, can rerun native Glaurung analysis on matching
local PE files, and flags recall risk when rejected addresses overlap
Ghidra-only starts. The first real-PE replay test runs the dashboard
against the vendored SurfacePen driver and proves native
`body_overlap:tiny_stub` rejection rows include concrete address
samples.

Update: address-specific scanner rejection coverage now includes PE
exception-directory gates for `.pdata` `BeginAddress == 0`, zero-size
records, chained unwind records, and non-executable starts. These are
reported as `pdata:zero_begin`, `pdata:zero_size`,
`pdata:chained_unwind`, and `pdata:nonexec` in native
`scan_rejection_counts`/`scan_rejections`. The dashboard real-PE test
uses `win10-vwififlt.sys` to prove `pdata:chained_unwind` records carry
concrete rejected addresses and details.

### 8. Corpus Curator Agent

Purpose: maintain the Windows regression corpus. It chooses diverse
system/app/driver/vendor fixtures, records provenance, runs Ghidra and
Glaurung comparisons, and updates dashboards.

Exit criteria:

- It tracks fixture source, SHA256, binary type, architecture, PDB
  status, and expected stress purpose.
- It keeps a fast baseline and a stress suite separate.
- It detects when a new fixture only duplicates an existing class.

Status: initial deterministic replay workflow added as
`glaurung.llm.agents.windows_corpus_curator`. It inventories the
vendored Windows realworld corpus, joins every local PE to the cached
Ghidra/Glaurung dashboard, computes SHA256, size, binary kind,
architecture, suite membership, source label, stress purpose, and
functionization metrics, then selects a diverse subset for review. It
keeps the original 10-file fast baseline distinct from the 20-file
stress suite, reports missing local/dashboard entries, detects duplicate
coverage classes, and emits the dashboard refresh command to run after
fixture changes. The next extension should write an updated corpus
manifest after curator approval rather than only returning an in-memory
plan.

Update: the curator now supports explicit `write_manifest=true` and
writes an enriched schema-v2 manifest with suite membership, binary
kind, architecture, PDB status, stress purpose, Ghidra/Glaurung
functionization metrics, and preserved source provenance. The vendored
corpus manifest at
`samples/binaries/platforms/windows/vendor/realworld/MANIFEST.json` has
been regenerated through that path.

Update: the curator now has a CI-style drift guard. It compares the
local vendored PE set, cached Ghidra/Glaurung dashboard rows, and
schema-v2 manifest fields for missing dashboard rows, missing local
files, stale manifest entries, stale hashes/sizes, and stale
functionization metrics. `fail_on_drift=true` raises a bounded error for
CI or pre-merge checks; the result also reports structured
`WindowsCorpusManifestDrift` records for agent review.

Update: the guard is exposed through `glaurung windows corpus-guard`.
The command emits JSON/JSONL/plain reports and exits nonzero on drift by
default, with `--allow-drift` available for exploratory reports. This is
now suitable for a pre-merge script or CI job.

Update: the guard now has a dedicated GitHub Actions workflow at
`.github/workflows/windows-corpus-guard.yml`. It runs on pull requests
that touch the Windows corpus, Windows-port docs, corpus tooling, or
the workflow itself, and can also be triggered manually. The job builds
the local Python/Rust package with `uv run` and executes
`glaurung windows corpus-guard --format json`, turning manifest drift
into a CI failure instead of a local-only check.

Update: the drift guard now supports an explicit accepted-drift policy.
`WindowsCorpusCuratorConfig.accepted_drift_path` and
`glaurung windows corpus-guard --accepted-drift-path` load a JSON
policy of file/field drift acceptances with a required human reason and
optional current/recorded/reason match constraints. Accepted drift stays
visible in `manifest_drift` and the evidence bundle, but only
unaccepted drift fails `fail_on_drift` or the CLI default exit code.
This lets intentional fixture refreshes be documented without teaching
CI to ignore unknown corpus/dashboard drift.

Update: the curator can now write corpus review notes through
`WindowsCorpusCuratorConfig.review_notes_path` and
`glaurung windows corpus-guard --review-notes-path`. The markdown
captures the corpus/manifest/dashboard scope, fast/stress counts,
accepted and unaccepted drift, dashboard refresh commands, and a bounded
review sample. This gives release and review threads a durable artifact
that ties accepted-drift policy to the dashboard state being reviewed.

Update: `.github/workflows/windows-corpus-guard.yml` now also runs on a
weekly schedule and uploads `corpus-guard.json` plus
`corpus-review.md` as a `windows-corpus-review` artifact. Pull requests
still use the same guard as a failing check, while scheduled/manual
runs preserve the review evidence for later comparison. Full
Ghidra-backed dashboard refresh artifacts still require a runner with
headless Ghidra installed.

Update: `.github/workflows/windows-ghidra-parity-refresh.yml` adds the
Ghidra-equipped scheduled/manual refresh lane. It requires a
`self-hosted`, `linux`, `ghidra` runner, resolves an executable
`analyzeHeadless`, regenerates the 30-file parity JSON/Markdown under
`artifacts/windows-ghidra-parity/`, runs `glaurung windows
corpus-guard` against the refreshed dashboard, and uploads the refreshed
dashboard plus corpus review note. The remaining gap is validating this
on the actual Ghidra runner and deciding which refreshed artifacts get
promoted back into `docs/windows-port/`.

### 9. Evidence Review Agent

Purpose: act as the skeptical reviewer before a candidate is promoted.
It checks stale artifacts, missing gates, missing runtime evidence,
overclaims, and Ghidra/IDA substrate gaps.

Exit criteria:

- It can reject a high-risk packet when project fact coverage is too
  weak.
- It cites the exact missing fact class or stale artifact.
- It separates triage priority from validation readiness.

Status: initial deterministic replay workflow added as
`glaurung.llm.agents.windows_evidence_review`. It composes
`windows_rank_candidate_packets` and
`windows_candidate_validation_report`, joins optional validation plans,
runtime artifact bundles, snapshot mappings, harness templates, and
explicit Ghidra/functionization substrate gaps, then emits per-candidate
review decisions. The workflow rejects high-priority candidates with
weak static/project facts, keeps runtime substrate blockers separate
from triage priority, and marks crash-observed artifact bundles as
human-review states with `promotion_allowed=false`. The next extension
should add artifact freshness timestamps and `.glaurung` project
coverage checks from persisted project metadata.

Update: evidence review now accepts persisted project fact manifest
records or a manifest path, joins them against candidate binary/build
identity, and blocks packets when required project facts are absent from
the persisted `.glaurung` coverage record. It also performs local
artifact freshness checks for existing runtime artifact paths and
records fresh/stale/not-checked state in each review item and the
shared evidence bundle.

Update: evidence review now emits `operator_validation_markdown`, a
bounded operator-facing report with claim level, candidate counts, stale
runtime artifacts, per-candidate decisions, validation state, blockers,
missing static facts, project coverage gaps, runtime blockers, artifact
freshness, and next actions. This makes stale evidence visible in a
pasteable validation-review artifact without promoting the candidate to
a finding.

Update: evidence review can now persist both operator and validation
markdown. `operator_markdown_path` writes the skeptical evidence-review
report, while `validation_report_markdown_path` is passed through to
`windows_candidate_validation_report`; result models preserve both
paths and tool sequences record the write operations.

Update: evidence review can now emit a higher-level JSON export
manifest. `export_manifest_path` writes candidate ids, blocked/ready
counts, operator markdown path, validation report markdown path,
generated artifact paths, evidence-bundle claim level, and tool
sequence. The result also carries the manifest model and path, and the
shared evidence bundle records all generated handoff paths as
attributes. This gives downstream packet, validation, and operator
handoff workflows a deterministic file to consume instead of scraping
markdown.

Update: evidence review can now write the reviewed candidate packets as
a structured JSON handoff artifact via `candidate_packets_export_path`.
The export manifest records that path as `candidate_packets_path`, and
validation planning can consume the manifest directly. This closes the
first end-to-end machine handoff from skeptical evidence review into VM
validation planning without relying on in-memory objects or markdown
parsing.

Update: evidence review can now start from durable packet artifacts as
well as write them. `candidate_packets_path` loads JSON/YAML packet
exports directly, and `evidence_export_manifest_path` follows a
manifest's `candidate_packets_path` before ranking candidates. Loader
counts and paths are preserved in the result and evidence-bundle
attributes, allowing CI/workflow jobs to invoke evidence review from
files instead of in-memory packets.

### 10. Interactive Analyst Agent

Purpose: provide the day-to-day IDA/Ghidra-like chat interface: show
callers, explain this function, why is this a function, what changed
here, show sink paths, where does this argument come from, what is still
unknown.

Exit criteria:

- Every answer uses bounded deterministic tools.
- Every response includes addresses, project fact coverage, and known
  uncertainty.
- The agent can hand off from navigation to a review packet without
  losing evidence provenance.

Status: initial deterministic replay workflow added as
`glaurung.llm.agents.windows_interactive_analyst`. It routes common
analyst intents to bounded deterministic tools:
`windows_function_start_explain`, `windows_function_boundary_diff`,
`windows_triage_worklist`, `windows_patch_diff_review`, and
`windows_rank_candidate_packets`.
Responses carry addresses, project fact coverage, known uncertainty,
next tools, exact tool sequence, and a shared evidence bundle. The
candidate-handoff path preserves the full `WindowsReviewPacket` so a
navigation answer can move into evidence review or validation planning
without dropping provenance. The next extension should expose this
workflow through the user-facing agent/chat surface.

Update: the deterministic interactive analyst workflow is now exposed
through `glaurung windows analyst`. The CLI supports bounded
`explain_function`, `boundary_gap`, `triage_queue`, and `patch_diff`
intents with plain, JSON, and JSONL output so analyst navigation can be
scripted and replayed without invoking an unbounded chat loop.

Update: interactive analyst calls now support bounded
`WindowsInteractiveAnalystSessionState`. The state carries prior
file/address/address-list context, last intent, and review-packet
candidate handoff IDs across calls. The CLI can read and write this
state via `--state-path` and `--write-state`, allowing scripted
multi-turn analyst sessions while preserving deterministic tool calls.

Update: the analyst CLI now supports named resumable sessions.
`glaurung windows analyst --session-id <name>` loads state from
`.glaurung/windows-analyst/sessions/<name>.json` by default, writes the
updated state back automatically, and still allows `--session-dir` for
artifact-controlled runs. This makes the deterministic analyst behave
like a small REPL over repeated CLI invocations without introducing an
unbounded chat loop.

Update: candidate handoff can now persist review packets as JSON.
`WindowsInteractiveAnalystConfig.review_packet_output_path` writes the
handoff packet when the intent produces one, and
`glaurung windows analyst --intent candidate_handoff` can load a
`--candidate-packet-path` and write `--review-packet-output-path`.
Results preserve the output path and record the write operation in the
tool sequence.

Update: candidate handoff can now consume evidence-review export
manifests. `WindowsInteractiveAnalystConfig.evidence_export_manifest_path`
loads the manifest's `candidate_packets_path`, optionally selects a
specific `candidate_id`, and routes the selected packet through the same
ranked handoff workflow. The CLI exposes this through
`glaurung windows analyst --intent candidate_handoff
--evidence-export-manifest-path ... --candidate-id ...`, so operator
handoffs can resume from the structured evidence-review artifact rather
than a manually copied packet.

Update: the analyst CLI now has a thin deterministic command-loop
wrapper. `glaurung windows analyst-loop --script-path <json>` executes a
bounded list of analyst intents, carries the same session state between
turns, supports named auto-resuming sessions, and emits plain, JSON, or
JSONL transcripts. This provides a scriptable REPL-like analyst surface
without adding an unbounded chat loop or dropping exact tool provenance.

Update: the deterministic analyst workflow is now also exposed to the
memory-agent/chat tool surface as `windows_interactive_analyst`. The
tool wraps `WindowsInteractiveAnalystConfig` and returns the same
bounded `WindowsInteractiveAnalystResult` used by the CLI, so a
user-facing agent can answer "why is this a function", "show the
boundary gap", "build a triage queue", "review this patch diff", or
"handoff this packet" through deterministic tools rather than parsing
bytes or scraping CLI output.

Update: the interactive analyst now has a `pipeline_blockers` intent
that reads a target-pipeline `blocker-worklist.json` artifact and
returns a bounded summary of the top cache, metadata, inventory,
harness, runtime, functionization, or symbol/similarity blockers. The
CLI exposes the same path with `glaurung windows analyst --intent
pipeline_blockers --blocker-worklist-path ...`, and command-loop
scripts can carry `blocker_worklist_path` as another deterministic
turn. This closes the handoff from scheduled high-volume artifacts back
into analyst/chat navigation.

Update: `pipeline_blockers` can now start from the remediation task
plan artifact as well as the raw blocker worklist. Supplying
`blocker_task_plan_path`, or the CLI flag
`--blocker-task-plan-path`, loads either the compact persisted
`blocker-task-plan.json` shape or the full in-memory result schema,
summarizes the highest-priority project-cache, metadata, validation,
runtime, functionization, symbol/similarity, or packet-grounding tasks,
and returns the task-specific deterministic next tool such as
`windows_bootstrap_project_facts`. This lets analyst/chat navigation
resume from the same artifact the runner uploads for remediation.

### 11. Target Pipeline Agent

Purpose: compose the deterministic agents into a one-target-family
pipeline: build-corpus target selection, per-target candidate packet
emission, validation planning, sink-to-gate batch review, and skeptical
evidence review.

Exit criteria:

- It accepts a build-corpus target manifest and produces a bounded set
  of per-target packet scans without manual sink VA entry.
- It preserves durable candidate-packet handoffs between validation,
  sink-to-gate review, and evidence review.
- It never promotes a finding; the output stays a non-finding pipeline
  artifact with explicit blockers and next actions.

Status: initial deterministic replay workflow added as
`glaurung.llm.agents.windows_target_pipeline`. It runs triage worklist
with high-volume target fanout enabled, converts ready fanouts into
`WindowsValidationBuildCorpusPacketScanConfig` objects, runs batch
validation planning, feeds the emitted candidate packets into
sink-to-gate batch review, and then runs evidence review with the
validation plans, snapshot mappings, and harness templates. The result
preserves all child agent outputs, aggregate counts, blockers, tool
sequence, and a shared non-finding evidence bundle. The first regression
test covers a synthetic `.glaurung` driver target from build-corpus
manifest through evidence review.

Update: the target pipeline is now exposed through
`glaurung windows target-pipeline`. The CLI accepts build-corpus
manifest/root filters, validation inventory, sink/source/gate/project
metadata paths, packet bounds, and export paths, and returns plain,
JSON, or JSONL output for deterministic batch runs.

Update: the target pipeline can now write a top-level JSON export
manifest via `pipeline_export_manifest_path` /
`--pipeline-export-manifest-path`. The manifest records selected and
ready target ids, candidate ids, candidate-packet export path, evidence
export manifest path, evidence packet/operator artifacts, aggregate
counts, generated artifacts, and tool sequence. This makes the pipeline
resumable from a single durable artifact rather than a transient
Pydantic object.

Update: the target pipeline now has a dedicated GitHub Actions smoke
workflow at `.github/workflows/windows-target-pipeline.yml`. It runs on
pull requests that touch the Windows target-pipeline agents, CLI,
project packet tooling, Windows-port docs, or the workflow itself, and
executes `uv run pytest python/tests/test_windows_target_pipeline_agent.py -q`.

Update: the target-pipeline workflow now also runs on a weekly schedule
and preserves generated handoff files as a
`windows-target-pipeline-handoffs` artifact by forcing pytest temp files
under `artifacts/windows-target-pipeline/`. The smoke keeps the
candidate-packet export, evidence-review markdown, evidence export
manifest, evidence candidate-packet export, and top-level pipeline
manifest produced by the synthetic target instead of treating them as
ephemeral local files.

Update: `.github/workflows/windows-target-pipeline.yml` now also has a
self-hosted high-volume job gated to scheduled runs or explicit
`workflow_dispatch` opt-in. It runs `glaurung windows target-pipeline`
against ASB's `pe-build-corpus.yaml`, runner-local Windows corpus and
cached `.glaurung` project roots, and ASB sink/source/gate/project-fact
metadata, then uploads candidate packets, evidence review markdown,
evidence exports, and the top-level pipeline manifest as
`windows-target-pipeline-high-volume`. The remaining gap is proving the
job on the actual `windows-corpus` runner and converting recurrent
blockers into corpus/project cache tasks.

Update: target pipeline can now include ASB vulnerability invariant
seed packets by passing `--vulnerability-seeds-path` or
`--include-vulnerability-seeds`. The pipeline threads the seed filters
and manifest context through validation planning, merges seed-derived
packets with project sink-call packets, and preserves the resulting
candidate ids and counts in the same validation, sink-to-gate, evidence
review, and export-manifest handoff path. The high-volume workflow now
passes ASB's `pe-vulnerability-seeds.yaml` when available.

Update: target pipeline can now include ASB operation-classification
backlog packets by passing `--operation-backlog-path` or
`--include-operation-backlog`. The pipeline creates a backlog packet
scan per ready fanout target, filtered by the selected target id and
component, then merges the resulting classifier-work-item packets into
the same validation, sink-to-gate, evidence-review, and export-manifest
handoff path. The high-volume workflow now adds
`pe-operation-classification-backlog.yaml` when that metadata file is
available on the runner.

Update: target pipeline can now include patch-diff changed-function
packets by passing `--patch-diff-binary-a` and
`--patch-diff-binary-b`, with optional seed metadata, PDB/BSim function
identity YAML, PDB-backed marking, and patch-diff row/item bounds. The
pipeline threads these into `windows_patch_diff_packets`, merges the
resulting non-finding changed-function packets with project sink-call,
vulnerability-seed, and operation-backlog packets, and preserves the
patch-diff packet count and tool sequence through validation planning,
sink-to-gate review, evidence review, and pipeline JSON output. The
high-volume workflow now exposes manual `workflow_dispatch`
`patch-diff-binary-a`, `patch-diff-binary-b`, and
`patch-diff-function-identity-path` inputs so a prepared runner can
feed a patch pair and optional PDB/BSim identity manifest into the same
artifact path.

Update: target pipeline now emits a ranked blocker worklist for
high-volume runs. `WindowsTargetPipelineBlockerWorkItem` groups
validation, sink-to-gate, and evidence-review blockers by operational
kind: project cache, source/gate metadata, validation inventory,
harness, runtime artifact, functionization, symbol/similarity, packet
grounding, or unknown. `glaurung windows target-pipeline
--blocker-worklist-path` writes the JSON handoff, the top-level export
manifest records the path and item count, and the scheduled
high-volume workflow uploads `blocker-worklist.json` beside candidate
packets and evidence-review artifacts. This turns recurring blockers
from flat strings into prioritizable cache/metadata/symbol work.

Update: high-volume blockers now feed a deterministic remediation task
plan. `windows_pipeline_blocker_task_plan` consumes
`preflight.json` and/or `blocker-worklist.json`, resolves build-corpus
target metadata, and emits typed tasks such as project-cache refresh,
corpus-binary vendoring, source/gate metadata refinement, validation
inventory updates, harness/runtime artifact work, functionization rule
review, and symbol/similarity extraction. The Windows CLI exposes this
as `glaurung windows blocker-task-plan`, the memory agent registers the
same tool for chat/agent orchestration, and the high-volume workflow now
writes `preflight-task-plan.json` before failing a blocked preflight and
`blocker-task-plan.json` after a successful target-pipeline run. This
turns high-volume failure artifacts into machine-readable next work
instead of a human-only log scrape.

Update: the project-cache remediation tools are now available from the
same Windows CLI surface as the high-volume workflow. `glaurung windows
project-fact-manifest` inspects and filters ASB `.glaurung`
project-fact manifest records by target, binary, build, available
facts, missing facts, and minimum counts. `glaurung windows
bootstrap-project-facts` runs the deterministic
`windows_bootstrap_project_facts` cache builder from a PE path to a
`.glaurung` project path, with switches for callgraph, data xrefs, CFG,
dominance, branch conditions, PDB import, and force reindexing. This
turns `project_cache_refresh` tasks from agent-only tool names into
runnable operator commands.

Update: `windows_bootstrap_project_facts` can now also update the
project-fact manifest row that downstream agents consume. When
`project_facts_output_path` / `--project-facts-output-path` is set, the
tool summarizes the generated `.glaurung` project, hashes the project
file, records size, fact sources, coverage, missing facts, and queryable
counts, then inserts or replaces a stable YAML record keyed by
  `project_fact_id`. This closes the local artifact gap between
project-cache generation and ASB `pe-project-facts.yaml` metadata
refresh; real high-volume target refreshes still need to be run and
reviewed before baseline promotion.

Update: project-cache remediation tasks now carry the manifest update
handoff directly. When `windows_pipeline_blocker_task_plan` has
`metadata_root`, its `project_cache_refresh` tasks include
`project_facts_output_path`, `project_fact_id`, binary filename,
architecture, build label, and a command string with the manifest output
argument. That command is now a copy-pasteable
`uv run glaurung windows bootstrap-project-facts ...` invocation rather
than an internal tool-name sketch. Operators can therefore run the suggested
`windows_bootstrap_project_facts` task and produce both the project
cache and the corresponding project-fact manifest row.

Update: runner artifacts now have a deterministic review gate.
`windows_runner_artifact_review` reviews an uploaded high-volume
artifact directory, parses `preflight.json`, `target-pipeline.json`,
`blocker-worklist.json`, task-plan artifacts, pipeline/evidence export
manifests, and Ghidra parity refresh artifacts when present, then emits
a non-finding promotion-readiness verdict. It separates review
readiness from artifact-baseline promotion readiness, carries task-plan
next actions forward, and records promotable artifacts only when the
preflight, target pipeline, blocker worklist, and task plan are clean.
The high-volume workflow now writes a preflight artifact review before
failing a blocked preflight and a final runner artifact review after
the target pipeline/task-plan run. The Ghidra parity refresh workflow
now writes the same review verdict for refreshed parity JSON/Markdown
and corpus-guard output. This gives self-hosted runner output a
machine-checkable disposition instead of relying on raw uploaded logs.

Update: clean runner reviews can now produce a deterministic promotion
plan. `windows_runner_artifact_promotion_plan` reads
`runner-artifact-review.json`, refuses blocked reviews, hashes each
source artifact, and emits explicit copy/archive actions for docs or
metadata baselines. For Ghidra parity refreshes, refreshed
`glaurung_vs_ghidra_vendor_windows_30_refresh.{json,md}` artifacts map
to the checked-in post-fix docs baseline
`glaurung_vs_ghidra_vendor_windows_30_after_tiny_stub_gate.{json,md}`.
The Ghidra refresh workflow now uploads this promotion plan beside the
artifact review, so accepting a refresh is a reviewed copy plan rather
than an ad hoc manual step.

Update: promotion plans now have a dry-run-by-default verifier/apply
step. `windows_runner_artifact_promotion_apply` reads
`runner-artifact-promotion-plan.json`, refuses plans that are not
`promotion_allowed`, verifies every source artifact SHA256, reports
destination drift, and only copies files when `--apply-changes` is
explicitly requested. The Ghidra parity refresh workflow now runs this
tool in dry-run mode and uploads both the persisted apply result and
stdout JSON, so a refreshed dashboard artifact proves that its reviewed
copy plan is hash-valid before a maintainer applies it to checked-in
docs baselines.

Update: promotion-apply can now write a maintainer-facing Markdown
readiness note. The report records the mode, verification verdict,
baseline-commit readiness, source/destination hashes, action status,
blockers, and warnings. `baseline_commit_ready` only becomes true when
hash verification passes, `--apply-changes` was requested, and every
planned action was applied or already unchanged. The Ghidra parity
refresh workflow and the high-volume target-pipeline workflow now pass
`--review-markdown-path`, so clean runner artifacts upload
`runner-artifact-promotion-apply.md` beside the JSON evidence.

Update: high-volume target-pipeline runner artifacts now use the same
reviewed promotion path. The self-hosted target-pipeline workflow
always writes `runner-artifact-promotion-plan.json` after the final
artifact review; blocked plans stay uploaded as explicit remediation
evidence without failing solely because promotion is not allowed. When
the plan is clean, the workflow also runs
`windows_runner_artifact_promotion_apply` in dry-run mode and uploads
the hash-verified apply result. Target-pipeline promotion actions map
clean pipeline/evidence/candidate artifacts under
`docs/windows-port/runner-artifacts/` for a later reviewed baseline
commit.

## Regression And Evaluation Plan

The test suite should prove both low-level facts and agent behavior.

### Functionization Evals

- Keep the original 10-file suite as the fast parity baseline.
- Keep the 30-file suite as the stress suite for precision, large C++,
  COM/vtable-heavy binaries, drivers, and vendor runtimes.
- Track per-seed precision and recall for `.pdata`, direct call, body
  split, prologue, thunk, tiny stub, data ref, vtable, and tail call.
- Assert that NPU/XRT-style over-promotion does not reappear.
- Assert that SurfacePen-style code-pointer table discovery remains
  intact.
- Add targeted examples for padded `48 ff 25` thunks, SIMD-headed true
  starts, SIMD-headed false starts, padding-run data-ref false starts,
  and internal body split candidates.

### Tool Schema Evals

- Every new tool returns a Pydantic model with stable field names.
- Outputs are bounded by default and include truncation markers.
- Address fields are numeric plus rendered hex strings where useful.
- Confidence and reason-code enums are validated.
- Tools can run against cached comparison JSON when Ghidra is not
  available.

### Agent Replay Evals

- Use deterministic mocked-model or scripted-policy replays for each
  high-level agent.
- Require exact tool-call sequences for narrow scenarios and looser
  evidence-equivalence checks for broad review scenarios.
- Include loop and no-progress tests using the existing iterative-agent
  execution state.
- Add refusal tests: the agent must not promote a candidate when
  required gates, sources, or runtime artifacts are absent.

### End-To-End Scenario Evals

- SurfacePen callback-table recognition: true code-pointer data refs
  become functions or high-confidence starts.
- NETwtw padding-run rejection: adjacent padding bytes are labels or
  rejected starts, not functions.
- Dism/WDScore import thunk recovery: padded REX thunks are cataloged.
- WebServices body splitting: internal Ghidra-like starts become split
  candidates with owner overlap evidence.
- NPU/XRT precision: weak tiny starts are candidates or labels unless
  provenance is strong.
- Patch-diff triage: changed functions are ranked with functionization
  confidence and no unsupported finding claim.
- Candidate validation handoff: static packet becomes a VM plan but not
  a reproduction until runtime artifacts are imported.

## Prioritized Next Ten Steps

1. Implement `windows_function_start_explain` and seed it with examples
   from SurfacePen, NETwtw, Dism, WDScore, WebServices, NPU, and XRT.
   Status: initial artifact-backed tool implemented and registered with
   `memory_agent`; focused tests cover NPU SIMD, NETwtw padding, and
   Dism recovered-thunk cases.
2. Implement `windows_function_boundary_diff` over cached 30-file
   comparison artifacts with cause buckets for missing, extra, label,
   thunk, data-ref, tiny-stub, SIMD, and internal-split cases.
   Status: initial 30-file summary tool implemented and registered with
   `memory_agent`; focused tests cover global totals, missing-gap
   ranking, precision-priority filtering, evidence-node creation, and
   agent registration.
3. Promote the strict function / code label / candidate / rejected-start
   model into public Python helpers and JSON output.
   Status: initial public helper added as
   `glaurung.windows_analysis.classify_function_start_from_facts` plus
   `classify_function_start`; it returns explicit state, confidence,
   reason codes, counts, and recommended action from collected Windows
   facts. `glaurung.windows_analysis.diff_ghidra` now threads a compact
   `function_start_classification` object into every limited
   Ghidra-only and Glaurung-only row, so JSON/CLI consumers can
   distinguish strict functions, code labels, candidates, rejected
   starts, and no-evidence addresses without reparsing raw facts. The
   plain `glaurung windows diff-ghidra` formatter now also displays the
   classification state and recommended action for each row.
4. Add `windows_candidate_start_worklist` so agents can rank uncertain
   starts instead of scanning raw diagnostic JSON.
   Status: initial tool implemented and registered with `memory_agent`;
   focused tests cover NPU SIMD Ghidra-only starts, NETwtw padding-run
   reject candidates, evidence-node creation, and agent registration.
5. Add `windows_data_ref_confidence` and tests for SurfacePen true
   positives and NETwtw padding-run false positives.
   Status: initial tool implemented and registered with `memory_agent`;
   focused tests cover SurfacePen callback-table acceptance, NETwtw
   padding-run rejection, evidence-node creation, and agent registration.
6. Add `windows_import_thunk_catalog` and targeted tests for padded
   `48 ff 25 rel32` and related IAT jump wrappers.
   Status: initial catalog implemented and registered with
   `memory_agent`; focused tests cover recovered DismCore padded REX
   jump thunks, remaining WebServices `jmp rel32` thunk gaps,
   evidence-node creation, and agent registration.
7. Add `windows_function_body_split_candidates` and fixtures for
   WebServices, RtkAudUService64, DismAPI, and WDScore.
   Status: initial tool implemented and registered with `memory_agent`;
   focused tests cover WebServices over-merge ranking, Realtek
   `.pdata` overlap context, evidence-node creation, and agent
   registration.
8. Add a Functionization Review Agent replay test that reproduces the
   top findings of the 30-file human review from tool outputs alone.
   Status: initial deterministic replay workflow added as
   `glaurung.llm.agents.windows_functionization_review`; focused tests
   cover 30-file totals, top issue classes, bounded non-vulnerability
   claim level, exact tool sequence, and shared evidence-bundle output.
9. Define a shared `WindowsEvidenceBundle` Pydantic model and migrate
   candidate packet, diff, validation, and functionization tools toward
   it.
   Status: initial shared bundle tool implemented as
   `windows_agent_evidence_bundle` and registered with `memory_agent`.
   `windows_emit_review_packet`, `windows_function_boundary_diff`,
   `windows_emit_vm_validation_plan`,
   `windows_record_validation_artifact_bundle`, and the
   Functionization Review Agent now emit the common bounded evidence
   schema with claim level, subject, source tools, evidence refs,
   coverage, blockers, next actions, and notes.
10. Add IDA/Ghidra notebook import/export loops for names, comments,
    labels, type overrides, demotions, and function-start decisions.
    Status: initial agent-facing notebook loop implemented as
    `windows_analyst_notebook`, registered with `memory_agent`, and
    exposed through `glaurung windows analyst-notebook`.
    Export mode emits typed notebook JSON plus IDAPython/Ghidra scripts
    from `.glaurung` project names, comments, data labels, function
    prototypes, stack-frame variables, and visible function-start
    decisions. Import mode applies supported names, comments, data
    labels, prototype and stack-variable type overrides, demotions,
    suppressions, and function-start decisions back into the project,
    preserving demotions as comments and bookmarks instead of silent
    deletions.

## Non-Goals For The Next Sprint

- Do not use the LLM as a byte parser.
- Do not treat Ghidra as always correct; use it as a reference and
  diagnostic oracle while preserving independent evidence.
- Do not collapse labels and functions to make metrics look better.
- Do not promote static source/gate/sink packets to vulnerabilities
  without runtime validation evidence.
- Do not make a single monolithic "find bugs" agent before the
  low-level evidence tools and replay tests exist.

## Success Criteria

The next quality jump is achieved when a human can ask:

- "Why is this VA a function?"
- "What does Ghidra find here that Glaurung misses?"
- "Which starts are real functions, labels, candidates, or rejects?"
- "What changed between these two Windows builds?"
- "What evidence supports this sink/gate/source packet?"
- "What would I do next in IDA or Ghidra?"

and receive a bounded, deterministic, Pydantic-backed answer that an
agent can cite in a review packet and a test can replay.

## Current Completion Audit

Current status: the roadmap has initial deterministic implementations
for all ten low-level primitives and all ten high-level agent
workflows. The Windows high-level agents are package-visible through
`glaurung.llm.agents`, return Pydantic models, use bounded
deterministic tools, keep non-finding claim levels, and have focused
replay tests.

Validated high-level replay scope:

- Functionization review, triage worklist, sink-to-gate review,
  patch-diff review, validation planning, analyst notebook review,
  rule authoring, corpus curation, evidence review, interactive
  analyst, and package exports.
- Focused checks:
  `uv run pytest python/tests/test_windows_agent_exports.py
  python/tests/test_windows_functionization_review_agent.py
  python/tests/test_windows_triage_worklist_agent.py
  python/tests/test_windows_sink_to_gate_review_agent.py
  python/tests/test_windows_patch_diff_review_agent.py
  python/tests/test_windows_validation_planning_agent.py
  python/tests/test_windows_analyst_notebook_review_agent.py
  python/tests/test_windows_rule_authoring_agent.py
  python/tests/test_windows_functionization_rule_replay_tool.py
  python/tests/test_windows_corpus_curator_agent.py
  python/tests/test_windows_evidence_review_agent.py
  python/tests/test_windows_interactive_analyst_agent.py
  python/tests/test_windows_cli_analyst.py -q`
  passed with 61 tests.
- `windows_functionization_rule_replay` was also run against the
  current 30-file dashboard defaults and passed 5 fixture groups / 11
  cases with 0 failures and 0 unsupported cases.
- Latest replay-tool validation: scoped `uvx ruff check` passed for
  `windows_functionization_rule_replay.py`,
  `test_windows_functionization_rule_replay_tool.py`, and
  `memory_agent.py`; scoped `uvx ty check` passed for the tool and
  test; focused `uv run pytest
  python/tests/test_windows_functionization_rule_replay_tool.py -q`
  passed with 5 tests, covering checked-in dashboard fixtures,
  unsupported-rule accounting, memory-agent registration, concrete byte
  replay, and checked-in native analyzer replay over vendored PE
  positive/negative addresses.
- Latest scanner-rejection validation: scoped `uvx ruff check`, `uvx
  ty check`, `cargo fmt --check`, `cargo test -q tiny_stub_scan --lib`,
  and focused `uv run pytest` passed for the native stats binding,
  Windows structured-fact helper, and functionization replay paths.
  Tests cover per-address `scan_rejections` records for data-reference
  weak pointers and body-overlap tiny stubs, and a native replay fixture
  that reports `scan_rejection_at_address:body_overlap:tiny_stub` for a
  specific rejected VA.
- Latest function-start/worklist rejection validation: scoped `uvx ruff
  check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows_function_start_explain.py`,
  `windows_candidate_start_worklist.py`,
  `test_windows_function_start_explain_tool.py`, and
  `test_windows_candidate_start_worklist_tool.py`; tests cover
  function-start explanations surfacing typed scan-rejection records and
  candidate worklist rows preserving scanner rejection reasons.
- Latest scan-rejection dashboard validation: scoped `uvx ruff check`,
  `uvx ty check`, and focused `uv run pytest` passed for
  `windows_scan_rejection_dashboard.py`, `memory_agent.py`, and
  `test_windows_scan_rejection_dashboard_tool.py`; tests cover
  synthetic per-address rejected-start/Ghidra-missing correlation,
  precision-guard ratio calculation, evidence-bundle coverage, native
  replay over the vendored SurfacePen driver, concrete
  `body_overlap:tiny_stub` samples, native `.pdata` chained-unwind
  rejection records over `win10-vwififlt.sys`, and memory-agent
  registration. The Rust/Python bridge was rebuilt with
  `uv run maturin develop`, and targeted `cargo test -q tiny_stub_scan
  --lib` plus `cargo test -q body_overlap_gate_tests --lib` passed.
- Latest corpus-curator validation: scoped `uvx ruff check`, `uvx ty
  check`, and `uv run pytest` passed for
  `windows_corpus_curator.py` and
  `test_windows_corpus_curator_agent.py`; the current corpus reports 0
  manifest drift items, and the focused stale-manifest fixture fails
  under `fail_on_drift=true`.
- Latest corpus-guard CI validation: local
  `glaurung windows corpus-guard --format json` returned success with
  30 fixtures, 0 manifest drift items, and `drift_guard_passed=true`;
  the new `.github/workflows/windows-corpus-guard.yml` parses as YAML
  and wires that command into pull-request/manual CI.
- Latest Windows CLI validation: scoped `uvx ruff check`, `uvx ty
  check`, and `uv run pytest` passed for `windows.py` and
  `test_windows_cli_analyst.py`; `glaurung windows corpus-guard`
  returns success for the current corpus and returns nonzero with a JSON
  drift report for a stale manifest fixture, and `glaurung windows
  analyst` can read/write bounded session state for address carry-over.
- Latest Windows function-start JSON validation: scoped `uvx ruff
  check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows_analysis.py` and `test_windows_analysis_helpers.py`; tests
  cover `diff_ghidra` emitting `function_start_classification` on a
  Ghidra-only row that Glaurung knows as a code label, with the expected
  `code_label` state, reason code, and function-entry/label booleans.
- Latest notebook-to-packet validation: scoped `uvx ruff check`, `uvx
  ty check` on the implementation, and focused `uv run pytest` passed
  for `windows_emit_review_packet.py`,
  `test_windows_emit_review_packet_tool.py`,
  `test_windows_analyst_notebook_tool.py`, and
  `test_windows_analyst_notebook_review_agent.py`; tests cover carrying
  notebook comments and suppressions inside a review packet, adding
  `windows_analyst_notebook` provenance and evidence refs, recording
  `analyst_notebook_decisions` coverage, and blocking promotion when an
  attached suppression contradicts the candidate.
- Latest notebook type-override validation: scoped `uvx ruff check`,
  scoped `uvx ty check`, and focused `uv run pytest` passed for
  `windows_analyst_notebook`, `test_windows_analyst_notebook_tool.py`,
  `test_function_prototypes.py`, `test_stack_frame_vars.py`, and
  `test_undo_redo.py`; tests cover exporting and importing
  `function_prototype` and `stack_var` notebook decisions, IDA/Ghidra
  script handoff content, CLI JSON export, and manual prototype undo
  participation.
- Latest functionization notebook-attachment validation: scoped `uvx
  ruff check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows_functionization_review.py`,
  `test_windows_functionization_review_agent.py`,
  `test_windows_emit_review_packet_tool.py`, and
  `test_windows_analyst_notebook_review_agent.py`; tests cover matching
  a notebook suppression to an existing NETwtw padding-run worklist row,
  returning a typed attachment, adding notebook evidence refs and
  `analyst_notebook_decisions` coverage, and blocking functionization
  promotion with `notebook_promotion_blocker`.
- Latest evidence-review validation: scoped `uvx ruff check`, `uvx ty
  check`, and `uv run pytest` passed for `windows_evidence_review.py`
  and `test_windows_evidence_review_agent.py`; the markdown report
  includes stale artifact details, runtime blockers, project coverage
  gaps, and next actions in focused tests, and optional output paths
  persist both operator-review and candidate-validation markdown.
- Latest evidence-export/import validation: scoped `uvx ruff check`,
  `uvx ty check`, and `uv run pytest` passed for
  `windows_evidence_review.py`, `test_windows_evidence_review_agent.py`,
  lazy LLM package exports, package-visible Windows agents, and pytest
  configuration. Tests cover writing the export manifest and preserving
  generated artifact paths in both the manifest and evidence-bundle
  attributes. Direct import checks now complete for
  `glaurung.llm` and
  `glaurung.llm.agents.windows_evidence_review` without importing
  `pydantic_ai`/`logfire` through the package-export path, and
  `pytest.ini` disables third-party plugin autoload while explicitly
  enabling the suite's needed anyio, asyncio, and benchmark plugins.
  The full `python/tests/test_windows_*.py` surface passed under that
  configuration with one skipped test.
- Latest interactive-analyst validation: scoped `uvx ruff check`, `uvx
  ty check`, and `uv run pytest` passed for
  `windows_interactive_analyst.py`,
  `test_windows_interactive_analyst_agent.py`, `windows.py`, and
  `test_windows_cli_analyst.py`; tests cover session-state file/address
  defaults, updated result state, CLI state JSON persistence, and JSON
  review-packet handoff writes through both the agent and CLI.
- Latest interactive evidence-handoff validation: scoped `uvx ruff
  check`, `uvx ty check`, and `uv run pytest` passed for
  `windows_interactive_analyst.py`, `windows.py`,
  `test_windows_interactive_analyst_agent.py`, and
  `test_windows_cli_analyst.py`; tests cover loading an
  evidence-review export manifest, following its candidate-packet
  artifact, selecting a candidate id, preserving loader tool sequence,
  and exposing the same flow through the CLI.
- Latest interactive memory-agent validation: scoped `uvx ruff check`,
  `uvx ty check`, and focused `uv run pytest` passed for
  `windows_interactive_analyst.py`, `memory_agent.py`, and
  `test_windows_interactive_analyst_agent.py`; tests cover the
  `windows_interactive_analyst` MemoryTool wrapping the deterministic
  candidate-handoff workflow and registration with `create_memory_agent`.
- Latest interactive pipeline-blocker validation: scoped `uvx ruff
  check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows_interactive_analyst.py`, `windows_analyst_command_loop.py`,
  `windows.py`, `test_windows_interactive_analyst_agent.py`, and
  `test_windows_cli_analyst.py`; tests cover reading
  `blocker-worklist.json`, summarizing the highest-ranked blockers,
  reading compact persisted `blocker-task-plan.json` artifacts,
  summarizing the highest-priority remediation task, emitting
  deterministic next tools such as `windows_bootstrap_project_facts`,
  preserving the worklist/task-plan path in the evidence bundle, and
  exposing both artifact paths through the CLI.
- Latest triage-worklist validation: scoped `uvx ruff check`, `uvx ty
  check`, and `uv run pytest` passed for
  `windows_triage_worklist.py` and
  `test_windows_triage_worklist_agent.py`; tests cover loading a
  persisted project fact manifest directly into an `untyped_global`
  queue item, deriving changed-function work from a direct binary diff,
  and deriving a gate/source blocker from a synthetic `.glaurung`
  project operation-risk summary, plus resolving project paths and
  binary diff pairs from a build-corpus manifest, and auto-selecting
  high-volume corpus targets into ranked queue items without a
  target-id filter, plus fanning a selected target out to a
  `windows_validation_planning_batch` handoff with resolved project,
  binary, metadata paths, and packet bounds.
- Latest sink-to-gate validation: scoped `uvx ruff check`, `uvx ty
  check`, and `uv run pytest` passed for
  `windows_sink_to_gate_review.py` and
  `test_windows_sink_to_gate_review_agent.py`; tests cover automatic
  project CFG, branch-condition, and call-argument tool invocation from
  supplied project and binary paths, plus project-path resolution from
  manifest-joined review packet project facts, and binary/project path
  resolution from a build-corpus manifest, plus a batch review over
  multiple sink callsites with aggregated blockers, tool sequence,
  candidate ids, and evidence refs, and loading a persisted candidate
  packet artifact into the same batch path.
- Latest validation-planning validation: scoped `uvx ruff check`, `uvx
  ty check`, and `uv run pytest` passed for
  `windows_validation_planning.py`, package exports, and
  `test_windows_validation_planning_agent.py`; tests cover a mixed
  grounded/manual candidate batch with aggregated blockers and grounding
  coverage, loading batch packets from a persisted project-tool packet
  artifact, and invoking `windows_project_sink_call_packets` directly
  from batch config over a synthetic `.glaurung` project, plus
  resolving project/binary paths from a build-corpus manifest before
  emitting validation candidate packets, and executing multiple
  build-corpus-backed target packet scans in one validation-planning
  batch, plus writing loaded/emitted candidate packets to a durable JSON
  handoff artifact. The focused vulnerability-seed extension test also
  covers invoking `windows_vulnerability_seed_packets` from validation
  batch config and preserving emitted seed-packet counts, manifest path,
  diff context, inferred source status, and ASB grounding.
- Latest operation-backlog packet validation: scoped `uvx ruff check`,
  `uvx ty check`, and focused `uv run pytest` passed for
  `windows_operation_backlog_packets.py`,
  `windows_validation_planning.py`, `memory_agent.py`,
  `test_windows_operation_backlog_packets_tool.py`, and
  `test_windows_validation_planning_agent.py`; tests cover converting
  operation-classification backlog metadata into non-finding review
  packets, registering the tool with `memory_agent`, and invoking the
  packet source from validation-planning batch config.
- Latest target-pipeline operation-backlog validation: scoped `uvx ruff
  check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows_validation_planning.py`, `windows_target_pipeline.py`,
  `windows.py`, `test_windows_validation_planning_agent.py`, and
  `test_windows_target_pipeline_agent.py`; tests cover per-target
  operation-backlog packet batches in the target pipeline and CLI,
  preserving the packet counts and `windows_operation_backlog_packets`
  tool sequence.
- Latest target-pipeline patch-diff packet validation: scoped `uvx ruff
  check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows_target_pipeline.py`, `windows.py`, and
  `test_windows_target_pipeline_agent.py`; tests cover threading
  `patch_diff_binary_a`/`patch_diff_binary_b` through
  `WindowsTargetPipelineConfig`, exposing the same path through
  `glaurung windows target-pipeline --patch-diff-binary-a
  --patch-diff-binary-b`, preserving `patch_diff_packet_count`, and
  carrying `windows_patch_diff_packets` in the pipeline tool sequence.
  The high-volume workflow YAML parses with manual patch-diff inputs
  and conditional command wiring.
- Latest target-pipeline blocker-worklist validation: scoped `uvx ruff
  check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows_target_pipeline.py`, `windows.py`,
  `test_windows_target_pipeline_agent.py`, and package exports. Tests
  cover writing `blocker-worklist.json`, preserving the worklist path
  and item count in the pipeline export manifest and evidence bundle,
  surfacing project-cache, source/gate metadata, validation-inventory,
  and harness blockers, and exposing the same output through
  `glaurung windows target-pipeline --blocker-worklist-path`.
- Latest pipeline blocker task-plan validation: scoped `uvx ruff
  check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows_pipeline_blocker_task_plan.py`, `windows.py`,
  `memory_agent.py`, `test_windows_pipeline_blocker_task_plan_tool.py`,
  and adjacent high-volume preflight/target-pipeline/analyst CLI tests.
  Tests cover converting a blocked high-volume preflight artifact into
  a concrete `windows_bootstrap_project_facts` project-cache task,
  converting a symbol/similarity blocker work item into a
  `windows_symbol_similarity_extraction_plan` task, exposing the same
  output through `glaurung windows blocker-task-plan --format json`,
  and registering `windows_pipeline_blocker_task_plan` with
  `memory_agent`. The high-volume workflow now YAML-parses with
  preflight and post-pipeline task-plan artifact generation wired in.
- Latest project-cache remediation CLI validation: scoped `uvx ruff
  check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows.py`, `test_windows_bootstrap_project_facts_tool.py`, and
  `test_windows_project_fact_manifest_tool.py`. Tests cover
  `glaurung windows bootstrap-project-facts --format json` with all
  indexing disabled for a deterministic no-native-work smoke path, and
  `glaurung windows project-fact-manifest --format json` filtering a
  project-fact manifest by available `call_xrefs` and minimum call-xref
  count.
- Latest project-fact manifest write validation: scoped `uvx ruff
  check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows_bootstrap_project_facts.py`, `windows.py`,
  `test_windows_bootstrap_project_facts_tool.py`, and
  `test_windows_project_fact_manifest_tool.py`. Tests cover writing a
  generated `pe-project-facts.yaml` record with target/build/binary
  metadata, project SHA256, project size, fact sources, counts, missing
  facts, and CLI JSON fields for `project_facts_output_path` and
  `project_fact_record_id`; adjacent task-plan tests cover forwarding
  `project_facts_output_path`, `project_fact_id`, binary filename, and
  architecture into `project_cache_refresh` tasks and emitting a
  copy-pasteable `glaurung windows bootstrap-project-facts` command.
- Latest symbol/similarity extraction-plan validation: scoped `uvx ruff
  check`, `uvx ty check`, and focused `uv run pytest` passed for
  `windows_symbol_similarity_extraction_plan.py`,
  `windows_pipeline_blocker_task_plan.py`, `windows.py`,
  `memory_agent.py`,
  `test_windows_symbol_similarity_extraction_plan_tool.py`,
  `test_windows_pipeline_blocker_task_plan_tool.py`, and
  `test_windows_patch_function_identity_extract_tool.py`. Tests cover
  generating a runner script with `analyzeHeadless` and BSim commands,
  preserving the external similarity manifest and identity-output
  paths, creating review-compatible
  `windows_patch_function_identity_extract` args with optional PDB
  identity manifest context, exposing the plan through
  `glaurung windows symbol-similarity-plan --format json`, registering
  the tool with `memory_agent`, and routing symbol/similarity blocker
  work items to this extraction-plan tool.
- Latest runner artifact review validation: scoped `uvx ruff check`,
  `uvx ty check`, and focused `uv run pytest` passed for
  `windows_runner_artifact_review.py`, `windows.py`,
  `memory_agent.py`, `test_windows_runner_artifact_review_tool.py`,
  `test_windows_pipeline_blocker_task_plan_tool.py`, and
  `test_windows_symbol_similarity_extraction_plan_tool.py`. Tests cover
  a clean high-volume artifact directory that is artifact-promotion
  ready, a blocked preflight directory that preserves task-plan next
  actions and warns that `target-pipeline.json` is absent because
  preflight failed, a clean Ghidra parity refresh artifact directory
  with promotable refreshed JSON/Markdown outputs, CLI JSON output through
  `glaurung windows runner-artifact-review`, and memory-agent
  registration. The high-volume workflow now emits
  `preflight-artifact-review.json` and `runner-artifact-review.json` as
  uploaded review verdicts, and the Ghidra parity refresh workflow emits
  `runner-artifact-review.json` beside refreshed parity artifacts.
- Latest runner artifact promotion-plan validation: focused tests cover
  a clean Ghidra parity runner review mapping refreshed parity JSON and
  Markdown to the docs baseline, refusal when the runner review is not
  promotion-ready, CLI JSON output through
  `glaurung windows runner-artifact-promotion-plan`, SHA256 recording
  for source artifacts, target-pipeline artifact mapping under
  `docs/windows-port/runner-artifacts/`, and memory-agent
  registration. The Ghidra parity refresh workflow now emits
  `runner-artifact-promotion-plan.json` and a stdout copy of the same
  plan as uploaded artifacts, and the high-volume target-pipeline
  workflow now emits the same promotion-plan artifacts after the final
  runner artifact review.
- Latest runner artifact promotion-apply validation: scoped `uvx ruff
  check`, `uvx ty check`, focused `uv run pytest`, and workflow YAML
  parsing passed for `windows_runner_artifact_promotion_apply.py`,
  `windows.py`, `memory_agent.py`,
  `test_windows_runner_artifact_promotion_apply_tool.py`, and
  `.github/workflows/windows-ghidra-parity-refresh.yml` plus
  `.github/workflows/windows-target-pipeline.yml`. Tests cover
  dry-run hash verification without copying, persisted apply-result
  JSON with changed-destination counts, persisted maintainer-facing
  Markdown with `baseline_commit_ready`, explicit copy-and-verify mode,
  hash-mismatch refusal, CLI JSON output through
  `glaurung windows runner-artifact-promotion-apply`, and memory-agent
  registration. The Ghidra parity refresh workflow now dry-runs the
  apply step and uploads `runner-artifact-promotion-apply.json`,
  `runner-artifact-promotion-apply.md`, and a stdout copy beside the
  reviewed promotion plan. The high-volume target-pipeline workflow now
  does the same dry-run apply only when the target-pipeline promotion
  plan is clean.
- Latest target-pipeline validation: scoped `uvx ruff check`, `uvx ty
  check`, and `uv run pytest` passed for
  `windows_target_pipeline.py`, package exports, and
  `test_windows_target_pipeline_agent.py`; tests cover a build-corpus
  target resolving to a synthetic `.glaurung` driver project, emitting
  candidate packets, writing the validation handoff artifact, running
  sink-to-gate batch review, running evidence review over the same
  candidate id, and invoking the same workflow through
  `glaurung windows target-pipeline --format json`, plus writing and
  validating the top-level target-pipeline export manifest. The current
  test also covers merging a vulnerability-seed packet into the same
  target run through both the agent config and CLI path.
- Latest target-pipeline CI validation: `.github/workflows/windows-target-pipeline.yml`
  was added and locally YAML-parsed; it runs the target-pipeline smoke
  pytest on relevant pull requests and manual dispatch.
- Latest evidence-handoff validation: scoped `uvx ruff check`, `uvx ty
  check`, and `uv run pytest` passed for
  `windows_evidence_review.py`, `windows_validation_planning.py`,
  `test_windows_evidence_review_agent.py`, and
  `test_windows_validation_planning_agent.py`; tests cover writing a
  candidate-packet JSON handoff artifact from evidence review,
  recording it in the export manifest, preserving the path in the
  evidence bundle, loading candidate-packet artifacts and evidence
  export manifests back into evidence review, and loading that export
  manifest in batch validation planning before producing VM/harness
  plans.
- Latest patch-diff validation: scoped `uvx ruff check`, `uvx ty
  check`, and `uv run pytest` passed for
  `windows_patch_diff_review.py` and
  `test_windows_patch_diff_review_agent.py`; tests cover loading a
  persisted PDB/BSim-style function identity manifest and preserving
  similarity-backed match basis, algorithm provenance, identity reason
  codes, manifest tool sequencing, and identity count, plus invoking a
  cached PDB identity manifest directly to synthesize PDB-backed
  function identity evidence for changed diff rows.
- Latest patch-diff packet validation: scoped `uvx ruff check`, `uvx
  ty check`, and focused `uv run pytest` passed for
  `windows_patch_diff_packets.py`, `windows_validation_planning.py`,
  `memory_agent.py`, `test_windows_patch_diff_packets_tool.py`, and
  `test_windows_validation_planning_agent.py`; tests cover converting
  patch-diff review items into non-finding review packets, registering
  the tool with `memory_agent`, and invoking the packet source from
  validation-planning batch config.
- Latest patch-identity extraction validation: scoped `uvx ruff check`,
  `uvx ty check`, and `uv run pytest` passed for
  `windows_patch_function_identity_extract.py` and
  `test_windows_patch_function_identity_extract_tool.py`; tests cover
  extracting function identities from a real binary diff pair, joining a
  cached PDB identity record, writing the review-compatible YAML
  manifest, registering the tool with `memory_agent`, and feeding the
  emitted manifest back into patch-diff review.
- Latest project-prototype diff validation: scoped `uvx ruff check`,
  `uvx ty check`, and focused `uv run pytest` passed for
  `windows_project_prototype_diff.py`, the Windows CLI registration,
  `memory_agent.py`, `test_windows_project_prototype_diff_tool.py`,
  `test_windows_patch_diff_review_agent.py`, and
  `test_windows_patch_diff_packets_tool.py`; tests cover added,
  removed, and changed prototype rows, security-relevant buffer/length
  and role deltas, KB evidence-node creation, CLI JSON output, and
  `memory_agent` registration.
- Latest patch-diff prototype integration validation: scoped `uvx ruff
  check`, `uvx ty check`, `git diff --check`, and focused
  `uv run pytest` passed for `windows_patch_diff_review.py`,
  `windows_patch_diff_packets.py`,
  `test_windows_patch_diff_review_agent.py`,
  `test_windows_patch_diff_packets_tool.py`, and
  `test_windows_project_prototype_diff_tool.py`; the full
  `uv run pytest python/tests/test_windows_*.py -q` sweep also passed
  with one skip. Tests cover project-prototype deltas becoming
  `prototype_delta` review items, evidence-bundle prototype-delta
  coverage, sink/gate routing for security-relevant signature changes,
  and preservation into emitted patch-diff validation packets.
- Latest project function-start explanation validation: scoped
  `uvx ruff check`, `uvx ty check`, `git diff --check`, and focused
  `uv run pytest` passed for
  `windows_project_function_start_explain.py`, Windows CLI registration,
  `memory_agent.py`, `test_windows_project_function_start_explain_tool.py`,
  `test_windows_function_start_explain_tool.py`,
  `test_windows_function_chunks.py`, and
  `test_windows_project_xref_query_tool.py`; the full
  `uv run pytest python/tests/test_windows_*.py -q` sweep also passed
  with one skip. Tests cover strict `.pdata` functions, import thunks,
  exception funclet chunks, incoming call xrefs, comments, CLI JSON
  output, KB evidence-node creation, and `memory_agent` registration.

Not A+ yet:

- Triage worklist now accepts caller-provided facts, persisted project
  fact manifests, direct binary-diff paths, direct `.glaurung`
  operation-risk extraction, and build-corpus manifest resolution for
  project paths, binary paths, and diff pairs; it can also auto-select
  high-volume targets from a whole build-corpus manifest and fan those
  selected targets into per-target validation-planning batch handoffs.
  Validation planning can execute multiple of those target packet scans
  in one batch and write the produced packets to a durable handoff
  artifact for sink-to-gate batch review. The target pipeline now runs
  triage fanout, validation packet emission, sink-to-gate batch review,
  and evidence review in one deterministic agent, is exposed through
  the Windows CLI, writes a resumable pipeline manifest, and has a CI
  smoke workflow. It can also add ASB vulnerability invariant seed
  packets and per-target operation-backlog packets to the validation
  batch. The next step is scheduled/high-volume execution with cached
  corpus/project artifacts and seed/backlog metadata. Project-cache
  refresh tasks are now directly runnable through
  `glaurung windows bootstrap-project-facts`, and project-fact
  availability can be inspected through
  `glaurung windows project-fact-manifest`; the open work is running
  those commands against real high-volume targets and refreshing the
  manifest.
- Sink-to-gate review now attaches provided project facts, invokes
  project CFG/branch/call-argument tools automatically, resolves project
  paths from manifest-joined review packets, and resolves project/binary
  paths from build-corpus metadata, and batch-runs multiple concrete
  callsite reviews or pre-emitted candidate packets into one aggregate
  evidence bundle; target-pipeline fanout now feeds produced packets
  ASB vulnerability invariant seed packets, and per-target
  operation-backlog packets through sink-to-gate batch review and
  evidence review. The next step is running these packet sources
  together over the real high-volume corpus/project cache.
- Patch-diff review now models per-function PDB-backed and
  similarity-backed identity, can ingest persisted identity YAML, and
  can invoke cached PDB identity manifests directly. A new patch
  identity extractor writes review-compatible YAML from binary diff
  rows, PDB identity metadata, deterministic size/hash similarity, and
  optional external BSim-style similarity manifests. A new
  symbol/similarity extraction-plan tool now emits the runner commands,
  output paths, and identity-extractor handoff needed to produce those
  manifests from real Windows patch pairs on a prepared Ghidra/BSim
  runner. The next step is executing that plan on the real runner and
  promoting successful BSim/symbol-cache outputs back into patch-diff
  review artifacts.
- Validation planning now records candidate grounding, batch-runs
  multiple packets, can load persisted packet artifacts emitted by
  project candidate-packet tools, can invoke project sink-call packet
  extraction directly from batch config, can resolve project/binary
  paths from build-corpus metadata before packet emission, can execute
  multiple build-corpus-backed target scans, can consume evidence-review
  export manifests as durable packet handoffs, and can write its own
  candidate-packet handoff artifact for sink-to-gate/evidence review.
  It can also invoke `windows_vulnerability_seed_packets` and merge
  public invariant seed packets into the same batch, and can invoke
  `windows_operation_backlog_packets` for classifier-work-item packets,
  and can invoke `windows_patch_diff_packets` for changed-function
  review packets. Target pipeline can now compose those packet sources
  into the same high-volume path. The next step is running that combined
  source mix on the real runner and promoting repeated blockers into
  project cache, metadata, and symbol/similarity extraction tasks.
- Rule authoring now materializes proposed fixtures into checked-in
  functionization replay YAML, and
  `windows_functionization_rule_replay` consumes those fixtures against
  cached comparison evidence. Replay fixtures can now also carry
  concrete `bytes_hex` and `address` cases, which are checked directly
  against deterministic rule-level byte classifiers for tiny stubs,
  import thunks, data-ref padding, and body-split candidates; fixtures
  can also carry `binary_path` plus `address` to replay native Glaurung
  function-start output on vendored PE files, including expected seed
  kind and structured native provenance reason codes. Native replay now
  includes both emitted positive and non-emitted SIMD negative real-PE
  fixtures in the checked-in replay YAML, with byte-head reason codes
  for SIMD/padding/tiny-helper/thunk-shape cases,
  Rust-emitted `scan_rejection_counts` for scanner gate accounting, and
  per-address `scan_rejections` records for rejected VAs. Function-start
  explanations, candidate worklists, and the new scan-rejection
  dashboard now surface those records from single-address review through
  corpus-level precision/recall telemetry. `.pdata` zero-begin,
  zero-size, chained-unwind, and non-executable rejection gates now also
  produce address-specific records. The next step is using dashboard
  hits to decide which remaining scanner gates need fixture or scanner
  work.
- Corpus curation now writes an updated manifest after explicit
  approval and exposes a `fail_on_drift` guard for
  manifest/dashboard/local corpus coverage drift through
  `glaurung windows corpus-guard`; a dedicated GitHub Actions workflow
  now invokes the guard for Windows corpus/doc/tooling changes, and the
  guard can consume an accepted-drift policy that keeps intentional
  fixture refresh drift visible while excluding it from CI failures. The
  guard can also write corpus review markdown that attaches dashboard
  refresh commands, accepted-drift reasons, and unaccepted blockers to
  release/review notes. The workflow now runs on a weekly schedule and
  uploads corpus guard JSON plus the markdown review note. A separate
  Ghidra-equipped scheduled/manual workflow now regenerates and uploads
  fresh parity dashboard JSON/Markdown plus a runner artifact review
  verdict, promotion plan, and dry-run promotion-apply verification.
  The next step is proving that workflow on the actual self-hosted
  Ghidra runner and applying accepted promotion actions in a reviewed
  docs-baseline commit. Clean promotion artifacts now include the
  maintainer-facing apply Markdown needed for that commit review, but
  the real self-hosted runner proof and reviewed baseline commit are
  still open.
- Evidence review now checks local runtime artifact freshness,
  persisted project fact coverage, emits operator-facing validation
  markdown, can persist both operator and validation markdown, and can
  write a JSON export manifest plus structured candidate-packet handoff
  artifacts that validation planning, evidence review, and interactive
  analyst handoff consume directly; the target-pipeline CI smoke now
  uploads those generated handoff artifacts from its pytest temp
  directory. Runner artifact review now gives scheduled high-volume
  runs a deterministic promotion/readiness verdict over those uploaded
  files. The next step is applying that review to real runner outputs
  and promoting clean artifacts back into the docs and metadata
  baselines.
- Interactive analyst is now exposed through `glaurung windows analyst`
  with bounded session-state read/write, named auto-resuming sessions,
  persisted review-packet handoff files, and `glaurung windows
  analyst-loop` for bounded script transcripts over the same deterministic
  session store. It is also registered as a `windows_interactive_analyst`
  memory-agent tool, so the user-facing agent/chat surface can invoke
  the same deterministic workflow directly. The workflow can now read
  target-pipeline blocker worklists and blocker task plans as
  first-class analyst intents, which connects high-volume artifacts
  back to chat navigation and concrete remediation commands. Review
  packets can now also carry analyst notebook decisions, including
  promotion-blocking suppressions and demotions, and functionization
  review now attaches notebook decisions to candidate-start,
  body-split, and import-thunk review rows. The next step is adding
  UI/session plumbing around that bounded tool rather than a separate
  unbounded chat loop.
- Target pipeline now composes triage fanout, validation packet
  emission, sink-to-gate batch review, and evidence review over a
  build-corpus target manifest and is exposed through
  `glaurung windows target-pipeline`; it also writes a resumable
  pipeline export manifest, has a scheduled CI smoke workflow, uploads
  the generated smoke handoff artifacts, and has a self-hosted scheduled
  high-volume job for cached corpus/project artifacts. It can include
  ASB vulnerability invariant seeds, operation-classification backlog
  packets, and patch-diff changed-function packets in that high-volume
  run, and now writes a ranked
  blocker worklist plus a typed remediation task plan for cache,
  corpus, metadata, harness, inventory, functionization, runtime, and
  symbol/similarity follow-up. It also writes runner artifact reviews
  before a blocked preflight exits and after a full high-volume run,
  followed by a reviewed promotion plan and clean-plan dry-run apply
  artifact with a maintainer-facing readiness Markdown report.
  The next step is validating the high-volume job on the real runner
  and using the emitted task plan plus artifact review to drive actual
  project-cache generation, manifest metadata updates,
  symbol/similarity extraction, and baseline promotion.
