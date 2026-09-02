# Agentic Glaurung execution plan

> **Kind:** design · **Status:** proposed

This is the canonical ordered implementation checklist for the autonomous
source-recovery agent. Read [`STATUS.md`](STATUS.md) first when resuming work,
then take the first unchecked task whose dependencies are satisfied.

The detailed design remains in [`README.md`](README.md). Task dependencies and
acceptance criteria are defined in
[`implementation/02-work-breakdown.md`](implementation/02-work-breakdown.md),
and executable gates are defined in
[`implementation/04-acceptance-gates.md`](implementation/04-acceptance-gates.md).

## Status synchronization contract

- This file is the authoritative ordered checklist.
- [`STATUS.md`](STATUS.md) is the authoritative current-state and resume record.
- Check a task only after its linked acceptance evidence has a terminal result.
- Update this file and `STATUS.md` in the same commit whenever the active task,
  completed set, blocker, evidence, or next action changes.
- Keep raw Glaurung, the fixed LLM pipeline, and the autonomous agent as separate
  identities and evidence lanes.
- Record focused tests, full suites, behavioral round trips, DecBench scoring,
  local commits, remote integration, and remote CI separately.
- Never begin the official run while implementation, prompt, policy, budget, or
  runner configuration is still changing.

## Resume procedure

1. Read [`STATUS.md`](STATUS.md), including the exact next action and blockers.
2. Verify the current worktree, branch, `HEAD`, and `origin/master` rather than
   trusting a moving-ref statement in prose.
3. Use an isolated clean worktree; do not touch the concurrent decompiler lane.
4. Select the first unchecked task below whose dependencies are complete.
5. Read that task's acceptance row in the
   [work breakdown](implementation/02-work-breakdown.md) and the relevant design
   document linked by the phase.
6. Follow RED, GREEN, REFACTOR, VERIFY for implementation changes. Tests must use
   real repository binaries or fixtures where binary behavior is involved.
7. Run the phase's focused gates and retain their exact commands, results, and
   immutable Git identities.
8. Commit and push the bounded increment, integrate it into `master` when safe,
   verify the remote ref, then update both control documents.

## Control-plane documentation

- [x] P00 — Separate the durable identities `glaurung-raw`,
  `glaurung-llm-pipeline`, and `glaurung-agent`.
- [x] P01 — Record runtime, evidence, tool, validator, and repair architecture.
- [x] P02 — Record security, model, budget, trace, cost, concurrency, and resume
  policies.
- [x] P03 — Record real-binary, behavioral, DecBench, baseline, and ablation
  evaluation plans.
- [x] P04 — Record the phased roadmap, dependency catalog, file/API map, risks,
  decisions, and executable acceptance gates.
- [x] P05 — Add canonical `PLAN.md` and `STATUS.md` entrypoints and link them from
  the package README and repository documentation index.

Control-plane completion means the implementation can start; it does not mean
that any autonomous-agent code exists.

## Phase 0: Identity, policies, and immutable baselines

Primary references:

- [Current state and scope](00-current-state-and-scope.md)
- [Model configuration and budgets](operations/01-model-configuration-and-budgets.md)
- [Security and data policy](operations/02-security-sandbox-and-data-policy.md)
- [DecBench experiment design](evaluation/02-decbench-experiment-design.md)
- [Phase 0 roadmap](implementation/01-phased-roadmap.md#phase-0-freeze-names-baselines-and-policies)

Ordered checklist:

- [ ] F01 — Rename/deprecate the misleading fixed-pipeline runner identity and
  update its tests and diagnostics without relabeling historical artifacts.
- [ ] F06 — Inventory and hash the immutable raw and fixed-pipeline baselines,
  recording any unavailable scorer or artifact as an explicit evidence gap.
- [ ] F02 — Define and test schema-v1 target, evidence, result, outcome,
  validation, usage, and serialization models.
- [ ] F03 — Define prompt v1 with target, scope, evidence, output, injection, and
  termination rules; retain its deterministic hash.
- [ ] F04 — Define the exact deterministic tool-policy-v1 allowlist and fail if
  registration differs from it.
- [ ] F05 — Define quick, development, pilot, and official run profiles with
  serializable resolved configuration and hard budgets.
- [ ] Run Gate G0 and the changed-path portion of G4.
- [ ] Record Phase 0 evidence and update `STATUS.md` before Phase 1.

Phase exit: names, schemas, prompt, policy, profiles, and baseline evidence are
distinct, immutable, and reviewable. Stop if historical artifacts would need to
be overwritten or the three product lanes cannot be separated.

## Phase 1: Typed context and deterministic validation

Primary references:

- [Context, evidence, and memory](architecture/02-context-evidence-and-memory.md)
- [Output validation and repair](architecture/04-output-validation-and-repair.md)
- [File and API map](implementation/03-file-and-api-change-map.md)

Ordered checklist:

- [ ] V01 — Implement target/address canonicalization with x86, PE image-base,
  and ARM Thumb tests.
- [ ] V02 — Implement the append-only, hash-linked, address-scoped evidence
  ledger.
- [ ] V03 — Implement output schema and size validation.
- [ ] V04 — Implement target identifier and single-definition validation.
- [ ] V05 — Implement static policy validation for forbidden constructs.
- [ ] V06 — Implement bounded syntax-only compiler validation that never links
  or executes generated code.
- [ ] V07 — Implement high-confidence evidence-consistency checks.
- [ ] V08 — Implement package-level function mapping and collision checks.
- [ ] V09 — Implement stable repairable-versus-terminal classification.
- [ ] Run Gates G1 and G4.
- [ ] Record Phase 1 evidence and update `STATUS.md` before Phase 2.

Phase exit: the validator accepts valid real-fixture C and rejects every
required negative without model or network access.

## Phase 2: Bounded deterministic tool surface

Primary reference:
[tool surface and contracts](architecture/03-tool-surface-and-contracts.md).

Every tool task begins with a real-binary failing contract test and ends with
typed bounded output, trace/evidence recording, scope failures, truncation, and
unsupported/error coverage.

- [ ] T01 — Common typed request/result envelopes.
- [ ] T02 — `target_overview`.
- [ ] T03 — `view_disassembly`.
- [ ] T04 — `view_basic_blocks`.
- [ ] T05 — `decompile_native`, returning deterministic raw output only.
- [ ] T06 — `view_stack_frame`.
- [ ] T07 — `view_call_sites`.
- [ ] T08 — Bounded `view_callee` and `view_callers`.
- [ ] T09 — `view_xrefs`.
- [ ] T10 — Directly referenced strings, imports, and constants.
- [ ] T11 — Bounded `view_data_object`.
- [ ] T12 — Candidate-C feedback tools using V04-V06.
- [ ] T13 — Exact fail-closed tool registration against policy v1.
- [ ] Run Gates G2 and G4.
- [ ] Record Phase 2 evidence and update `STATUS.md` before Phase 3.

Phase exit: the registered set exactly matches policy, uses no nested LLM,
shell, arbitrary path, network, target execution, emulation, or mutation.

## Phase 3: Autonomous agent kernel and trace

Primary references:

- [Runtime and control loop](architecture/01-runtime-and-control-loop.md)
- [Observability, provenance, and cost](operations/03-observability-provenance-and-cost.md)

Ordered checklist:

- [ ] A01 — Build the source-recovery context without exposing keys or private
  benchmark metadata.
- [ ] A02 — Build the dedicated PydanticAI agent factory with the exact model,
  settings, tools, output type, and usage limits.
- [ ] A03 — Build the per-function controller with one terminal outcome per
  start.
- [ ] A04 — Validate structured output before acceptance.
- [ ] A06 — Add repeat/no-progress guards and bounded termination.
- [ ] A07 — Normalize usage and termination evidence.
- [ ] O01 — Add atomic ordered event JSONL and trace writing.
- [ ] O02 — Retain hash-linked, redacted prompts, messages, and evidence.
- [ ] O03 — Aggregate per-function, binary, and run usage/cost.
- [ ] O04 — Add secret redaction and sentinel scans.
- [ ] A05 — Feed only repairable validator diagnostics back into the bounded
  agent run.
- [ ] A08 — Pass the authorized live vertical slice with at least two
  model-selected evidence tools and accepted structured C.
- [ ] Run Gates G1-G5 as applicable and record each result separately.
- [ ] Record Phase 3 evidence and update `STATUS.md` before Phase 4.

Phase exit: the trace proves autonomous tool selection, bounded validation and
repair, complete usage, and no credited raw/fixed-pipeline fallback.

## Phase 4: Security and containment

Primary reference:
[security sandbox and data policy](operations/02-security-sandbox-and-data-policy.md).

- [ ] O06 — Enforce and test static-only path, process, execution, emulation,
  mutation, and network policy.
- [ ] O07 — Isolate syntax-only compiler validation with stdin, environment,
  output, CPU, memory, and time limits.
- [ ] O05 — Pass the real hostile-string prompt-injection fixture.
- [ ] O08 — Define and validate the official read-only target/container/egress
  policy.
- [ ] Run Gates G5 and G6, retaining provider, trace, and secret-scan evidence.
- [ ] Record Phase 4 evidence and update `STATUS.md` before Phase 5.

Any source leakage, target execution/emulation, policy escape, or credential
leak invalidates the affected run and blocks promotion.

## Phase 5: CLI, checkpointing, resume, and packaging

Primary references:

- [Concurrency, checkpointing, and recovery](operations/04-concurrency-checkpointing-and-recovery.md)
- [File and API map](implementation/03-file-and-api-change-map.md)

- [ ] R01 — Add a single-function `agent-decompile` CLI/API with stable JSON and
  exit codes and no hidden fallback.
- [ ] R02 — Load and account for the exact public manifest without exposing
  private metadata.
- [ ] R03 — Derive stable run/target identities that invalidate incompatible
  resume attempts.
- [ ] R04 — Persist atomic per-target checkpoints.
- [ ] R05 — Add bounded scheduling and provider/native concurrency controls.
- [ ] R06 — Add retained transient retries without duplicate credit.
- [ ] R07 — Assemble deterministic C/results mappings.
- [ ] R08 — Add syntax, official-package, hash, and secret audits.
- [ ] R09 — Produce a separate reviewable audit archive and Markdown summary.
- [ ] R10 — Pass interruption and resume drills with no lost or duplicated
  terminal target.
- [ ] Run Gates G3 and G4.
- [ ] Record Phase 5 evidence and update `STATUS.md` before Phase 6.

## Phase 6: Internal behavioral safety net

Primary references:

- [Test strategy](evaluation/01-test-strategy.md)
- [Curriculum corpus](../../development/decompiler-curriculum-corpus.md)
- [Decompiler test hierarchy](../../development/decompiler-testing.md)
- [Baselines and scorecards](evaluation/03-baselines-ablations-and-scorecards.md)

- [ ] E01 — Rebuild and retain the same-revision raw baseline or its explicit
  scorer blocker.
- [ ] E02 — Retain the honestly labeled fixed-pipeline baseline.
- [ ] E03 — Run the real source-backed multi-architecture fixture matrix across
  raw, fixed pipeline, disassembly-only agent, and full agent.
- [ ] E04 — Run recompilation and behavioral round trips, retaining pass, fail,
  and structural-only outcomes separately.
- [ ] Run Gates G6-G8 to terminal results.
- [ ] Classify every failure and regression by responsible layer.
- [ ] Record Phase 6 evidence and update `STATUS.md` before Phase 7.

Metric-only gains do not satisfy this phase.

## Phase 7: Frozen pilots and experiment freeze

Primary references:

- [DecBench experiment design](evaluation/02-decbench-experiment-design.md)
- [Baselines, ablations, and scorecards](evaluation/03-baselines-ablations-and-scorecards.md)

- [ ] Resolve or explicitly accept Q1-Q10 in
  [risks and decisions](implementation/05-risks-and-decisions.md#open-questions-requiring-a-decision-before-phase-7).
- [ ] E05 — Run the predeclared ten-function frozen pilot and retain cost,
  failure, tool, validation, and syntax reports.
- [ ] E06 — Run the fifty-function freeze gate and meet promotion criteria.
- [ ] Freeze code, runner, model/settings, prompt, tool policy, budgets,
  concurrency, container digest, and target lists.
- [ ] Run Gate G9 and re-run all applicable earlier gates.
- [ ] Obtain explicit owner authorization for official-run cost.
- [ ] Record the frozen experiment tuple in `STATUS.md`.

No implementation or configuration change after freeze may retain the same
experiment identity.

## Phase 8: Official 250-function run

- [ ] E07 — Run the official 250-function experiment under the frozen tuple.
- [ ] Verify exact target accounting and terminal outcome for every target.
- [ ] Run Gate G10 to a terminal package result.
- [ ] Retain ZIP, audit archive, manifest, diagnostic, secret-scan, and hash
  evidence.
- [ ] Inspect representative and worst outputs manually.
- [ ] E08 — Complete owner review of the package and private audit material.
- [ ] Record Phase 8 evidence and update `STATUS.md`.

No score is claimed until scored output is returned.

## Phase 9: Owner submission and scored interpretation

- [ ] H01 — Owner submits the reviewed package. Automation must not contact the
  maintainer, upload, comment, email, or open an issue.
- [ ] H02 — Preserve returned scorer artifacts and populate complete B0-B3
  scorecards with per-function deltas.
- [ ] Separate completion, syntax, GED, type, byte match, behavior, time, token,
  cost, and failure results.
- [ ] Decide whether the agent is experimental, publishable, or requires
  another architecture iteration.
- [ ] Run Gate G11 for the final bounded integration and verify remote state.
- [ ] Mark the project complete only when the definition of done in
  [`README.md`](README.md#definition-of-done) is satisfied.

## Global release blockers

Stop and update `STATUS.md` immediately if any of the following occurs:

- The fixed pipeline, raw engine, or fallback is credited as autonomous output.
- Source/private metadata leaks into agent context or results.
- A target binary executes, is emulated, is loaded, or is mutated.
- A tool can escape its target/address/path/network/resource scope.
- A trace, usage record, termination reason, or target outcome is missing.
- Generated C is linked or executed by a syntax-only validator.
- A checkpoint is reused across incompatible code, policy, prompt, model, or
  configuration identities.
- Cost, time, requests, tokens, tool calls, or output can become unbounded.
- Improvements exist only on tuned public fixtures or behavioral correctness
  regresses.
- The owner has not reviewed the package or authorized the next paid stage.
