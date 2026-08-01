# Work breakdown and dependencies

Status legend: `TODO`, `ACTIVE`, `BLOCKED`, `DONE`. Initial implementation
status is intentionally `TODO`; writing this plan does not complete code work.

## Milestone dependency graph

```text
F foundation
  -> V validators
  -> T deterministic tools
  -> A autonomous agent
  -> R runner/resume
  -> Q quality/security gates
  -> E frozen evaluation
  -> H owner handoff
```

## Foundation and identity

| ID | Status | Task | Depends | Acceptance |
|---|---|---|---|---|
| F01 | TODO | Rename fixed pipeline identity and docs | none | No autonomous claim remains for fixed runner/artifact |
| F02 | TODO | Define schema v1 models | F01 | Schema tests and JSON round trips pass |
| F03 | TODO | Define prompt v1 | F01 | Prompt contains scope/policy/output rules and no source cues |
| F04 | TODO | Define tool-policy v1 | F01 | Exact allowlist and policy hash are deterministic |
| F05 | TODO | Define run profiles | F01 | Resolved config serializes before requests |
| F06 | TODO | Retain immutable raw/pipeline baselines | none | Artifacts, hashes, revisions, and evidence limits recorded |

## Target, evidence, and validation

| ID | Status | Task | Depends | Acceptance |
|---|---|---|---|---|
| V01 | TODO | Target/address canonicalization | F02 | x86, PE image base, ARM Thumb tests pass |
| V02 | TODO | Evidence ledger and IDs | F02,F04 | Append-only records hash and scope correctly |
| V03 | TODO | Output schema/size validator | F02 | Required negative cases rejected |
| V04 | TODO | Identifier/definition validator | V01,V03 | Wrong target and extra definitions rejected |
| V05 | TODO | Static policy validator | V03 | Escape/include/inline-asm cases classified |
| V06 | TODO | Parser/compiler syntax validator | V03 | Typed compiler diagnostics; never links/runs |
| V07 | TODO | Evidence-consistency validator | V02,V04 | High-confidence contradiction fixtures fail |
| V08 | TODO | Package-contract validator | V04 | Multi-function grouping and collisions tested |
| V09 | TODO | Repair classification | V03-V08 | Repairable vs terminal table enforced |

## Deterministic source-recovery tools

| ID | Status | Task | Depends | Acceptance |
|---|---|---|---|---|
| T01 | TODO | Common request/result envelopes | F02,V01,V02 | All tool paths use common typed contract |
| T02 | TODO | `target_overview` | T01 | Real x86/ARM/PE orientation facts |
| T03 | TODO | `view_disassembly` | T01 | Bytes/instructions bounded and scoped |
| T04 | TODO | `view_basic_blocks` | T01 | Edge kinds and target blocks tested |
| T05 | TODO | `decompile_native` | T01 | Raw-only hypothesis, no nested LLM |
| T06 | TODO | `view_stack_frame` | T01 | Offset/width/use facts on real fixture |
| T07 | TODO | `view_call_sites` | T01 | Calls, args, results, authority tested |
| T08 | TODO | `view_callee`/`view_callers` | T07 | Depth/count/scope enforced |
| T09 | TODO | `view_xrefs` | T01 | Code/data direction and bounds tested |
| T10 | TODO | Strings/imports/constants tools | T01 | Directly referenced evidence only |
| T11 | TODO | `view_data_object` | T01 | Byte/read/address limits enforced |
| T12 | TODO | Candidate C feedback tools | V04-V06,T01 | Generated text only; exact diagnostics |
| T13 | TODO | Exact tool registration | T02-T12,F04 | Registered names equal policy or fail closed |

## Autonomous agent kernel

| ID | Status | Task | Depends | Acceptance |
|---|---|---|---|---|
| A01 | TODO | Source-recovery context builder | V01,V02,T02 | No private metadata/keys exposed |
| A02 | TODO | Dedicated PydanticAI agent factory | F03-F05,T13 | Correct model, settings, tools, limits |
| A03 | TODO | Per-function controller | A01,A02 | One terminal outcome for every start |
| A04 | TODO | Structured result handling | A03,V03-V08 | Controller validates before acceptance |
| A05 | TODO | Validator feedback/repair | A04,V09 | Bounded live repair proven |
| A06 | TODO | Loop/repeat/progress guard | A03 | Repeated calls and no-progress terminate |
| A07 | TODO | Usage/termination normalization | A03 | Every outcome has usage/reason |
| A08 | TODO | Live vertical slice | A04-A07 | Real model chooses >=2 tools and emits accepted C |

## Tracing, security, and operations

| ID | Status | Task | Depends | Acceptance |
|---|---|---|---|---|
| O01 | TODO | Event JSONL and trace writer | F02 | Atomic ordered complete trace |
| O02 | TODO | Prompt/message/evidence retention | O01,V02 | Hash-linked redacted artifacts |
| O03 | TODO | Usage/cost aggregator | O01,A07 | Function/binary/run summaries |
| O04 | TODO | Secret redaction and scans | O01 | Sentinel failures leak nothing |
| O05 | TODO | Prompt-injection fixture | A08,O02 | Embedded instructions remain data |
| O06 | TODO | Static-only process policy | T01 | Negative execution/path/network tests pass |
| O07 | TODO | Compiler sandbox | V06,O06 | stdin, syntax-only, bounded environment |
| O08 | TODO | Container/runtime policy | O04,O06,O07 | Read-only target, controlled egress, no secrets in image |

## Runner, checkpointing, and packaging

| ID | Status | Task | Depends | Acceptance |
|---|---|---|---|---|
| R01 | TODO | Single-function CLI/API | A08,O01 | JSON outcome and exit codes documented |
| R02 | TODO | Manifest loader and target accounting | F02,V01 | Exact 250 set; no private metadata in context |
| R03 | TODO | Run/target identities | F03-F05,R02 | Config changes invalidate resume |
| R04 | TODO | Atomic per-target checkpoints | R03,O01 | Crash states recover safely |
| R05 | TODO | Scheduler and concurrency limits | R04,A03 | Global/provider limits enforced |
| R06 | TODO | Transient retry policy | R04 | Attempts retained; no silent duplicate credit |
| R07 | TODO | Package assembler | V08,R04 | Deterministic C/results mapping |
| R08 | TODO | Syntax/package/hash audit | R07,O04 | Official package validator and secret scans pass |
| R09 | TODO | Audit archive and Markdown summary | O02,O03,R08 | Reviewable, hash-complete, separate from ZIP |
| R10 | TODO | Interruption/resume drills | R04-R09 | No lost/duplicated terminal targets |

## Evaluation and delivery

| ID | Status | Task | Depends | Acceptance |
|---|---|---|---|---|
| E01 | TODO | Raw same-revision baseline | F06,R07 | Complete immutable scorecard or explicit scorer blocker |
| E02 | TODO | Fixed-pipeline baseline | F01,F06 | Honest identity and complete artifact |
| E03 | TODO | Source-backed live fixture matrix | A08,O05 | Raw/pipeline/agent compared on real binaries |
| E04 | TODO | Behavioral round-trip gate | E03 | Pass/fail/structural-only retained separately |
| E05 | TODO | Ten-function frozen pilot | R10,E03 | Cost/failure/tool/syntax report |
| E06 | TODO | Fifty-function freeze gate | E05 | Config frozen; promotion criteria pass |
| E07 | TODO | Official 250 run | E06,R08,R09 | Every target terminal; artifacts hashed |
| E08 | TODO | Owner package review | E07 | ZIP/audit inspected; no secrets/private traces |
| H01 | TODO | Owner submits package | E08 | Explicitly outside automation |
| H02 | TODO | Preserve and analyze returned scores | H01 | Complete B0-B3 scorecards and per-function deltas |

## Critical path

The fastest safe path is:

`F02-F05 -> V01-V06 -> T01-T05/T07/T10/T12/T13 -> A01-A05/A08 -> O01/O04/O06/O07 -> R01-R04/R07/R08 -> E03/E05/E06/E07`

Stack, cross-function, and data-object tools can follow the first live vertical
slice if the minimal set cannot recover the target. Do not block the kernel on
all 15 tools, but do not start the official run before policy v1 is complete.
