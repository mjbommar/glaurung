# Phased implementation roadmap

> **Kind:** design · **Status:** proposed

## Delivery rule

Each phase begins with a failing test or evidence gap, ends with an immutable
checkpoint, and has an explicit stop condition. Do not begin the official
250-function run while implementation is still changing.

## Phase 0: Freeze names, baselines, and policies

### Phase 0 work

- Adopt `glaurung-raw`, `glaurung-llm-pipeline`, and `glaurung-agent` identities.
- Preserve the existing 250-function fixed-pipeline archive and diagnostics.
- Rebuild a same-revision raw package if the scoring environment is available.
- Pin the initial source-recovery tool policy and prompt.
- Define run/artifact schema v1 and configuration profiles.
- Record the no-execution, no-source, no-contact boundaries.

### Phase 0 exit criteria

- Baseline artifacts and hashes are retained.
- No document or CLI calls the fixed pipeline autonomous.
- Tool-policy and prompt design have reviewable hashes.
- Open questions that could invalidate implementation are decided or explicitly
  deferred.

### Phase 0 stop condition

Stop if the official kit, raw baseline, or naming cannot be distinguished
without overwriting existing artifacts.

## Phase 1: Data contracts and deterministic validators

### Phase 1 RED

Add failing tests for target identity, output schema, extra definitions, wrong
addresses, unknown evidence, syntax diagnostics, policy violations, and resume
compatibility.

### Phase 1 GREEN

- Implement `RecoveryTarget`, `SourceRecoveryContext`, `EvidenceRecord`,
  `RecoveredFunction`, `FunctionOutcome`, validation records, and usage records.
- Implement stable run/target/policy identities.
- Implement validator chain V1-V7 without model integration.
- Implement atomic outcome/checkpoint storage.

### Phase 1 REFACTOR

- Centralize address canonicalization and diagnostic codes.
- Remove duplicated payload validation from the external runner where the new
  contracts supersede it.

### Phase 1 exit criteria

- Deterministic contract tests are green.
- Validator accepts valid real-fixture C and rejects every required negative.
- No network or API key is needed for the phase gate.

## Phase 2: Source-recovery tool set

Implement tools one vertical slice at a time:

1. `target_overview`
2. `view_disassembly`
3. `view_basic_blocks`
4. `decompile_native`
5. call/import tools
6. stack/data/string/xref tools
7. generated-C checks

For each tool, write the real-binary test first, implement typed bounded output,
then add trace/evidence recording.

### Phase 2 exit criteria

- Registered names exactly equal tool-policy v1.
- Every tool has real x86-64 coverage; architecture-specific tools cover ARM
  Thumb and PE where applicable.
- Out-of-scope, truncation, timeout, unsupported, and no-result paths are tested.
- No tool uses an LLM, arbitrary path, shell, target execution, or mutation.

### Phase 2 stop condition

Stop adding tools if model-facing output exceeds budget, registration depends on
private PydanticAI internals, or a tool cannot enforce target scope.

## Phase 3: Minimal autonomous agent

### Phase 3 RED

Add an authorized live-model test expecting one fixture recovery with at least
two model-selected tool calls and structured output.

### Phase 3 GREEN

- Create the dedicated PydanticAI agent.
- Register only source-recovery tools.
- Build the system/user prompt from immutable context.
- Apply project `UsageLimits` and model settings.
- Return one `FunctionOutcome` with trace and usage.

### Phase 3 REFACTOR

- Separate provider setup, prompt construction, controller, and persistence.
- Ensure the generic memory agent remains unchanged.

### Phase 3 exit criteria

- One real function is recovered by a true tool-using agent.
- The trace proves model-selected tools rather than a fixed sequence.
- No fixed-pipeline or raw fallback is credited on failure.

## Phase 4: Validation feedback and repair

### Phase 4 work

- Wire the validator chain to PydanticAI output validation.
- Return stable actionable feedback with `ModelRetry` or the supported PydanticAI
  v2.9 equivalent.
- Cap repair attempts separately from general tool requests.
- Retain every proposed source and validation result.
- Make policy/scope violations terminal.

### Phase 4 exit criteria

- A real live-agent fixture repairs a deliberately induced syntax/shape error.
- An unrecoverable policy violation terminates without retry.
- Budget exhaustion during repair produces a complete terminal outcome.

## Phase 5: CLI and resumable external runner

### Phase 5 work

- Add a single-function CLI/API entry point.
- Add a new external runner for `glaurung-agent`; retain the fixed-pipeline runner
  under its honest name.
- Implement manifest loading, concurrency, checkpointing, resume, package
  assembly, syntax audit, hashing, and secret scan.
- Emit run summary and audit archive.

### Phase 5 exit criteria

- Interrupted real-fixture batch resumes without losing or duplicating accepted
  work.
- Partial and complete artifacts cannot overwrite each other.
- Official `package.py` accepts the generated package shape.

## Phase 6: Internal fixture and curriculum gate

### Phase 6 work

- Run raw, fixed pipeline, disasm-only agent, and full agent on the frozen
  multi-architecture pilot.
- Recompile and behaviorally test repository-owned fixtures.
- Classify every failure by architecture, tool, validator, agent, or native
  decompiler root cause.
- Tune only general contracts and prompts; do not encode function-specific
  answers.

### Phase 6 exit criteria

- Promotion criteria in the scorecard document pass.
- No raw behavioral regression from shared code.
- Prompt-injection, secret, and static-only gates pass.
- Cost and p95 wall time fit the selected profile.

### Phase 6 stop condition

Stop if gains exist only on known public fixtures, if agent repairs reduce
behavioral correctness, or if tool use cannot be attributed.

## Phase 7: Frozen pilots

Run E0 through E3 from the DecBench experiment plan. After the 50-function
pilot:

- Freeze Glaurung and runner commits.
- Freeze model/settings, prompt, tool policy, budgets, and concurrency.
- Rebuild container and record digest.
- Re-run all acceptance gates.
- Authorize cost before E4.

No implementation change after freeze enters the same experiment identity.

## Phase 8: Official 250-function run

- Create a fresh run root.
- Verify manifest/binary/container identities.
- Run static-only with configured credentials.
- Persist each target atomically.
- Validate 250-target accounting.
- Produce result ZIP, audit archive, hashes, and summary.
- Inspect representative and worst outputs manually.
- Confirm original kit unchanged and secrets absent.

### Phase 8 exit criteria

- Every target has a terminal state.
- Package validation has a terminal result.
- Artifacts are immutable and reproducible from recorded inputs.
- No official score is claimed before external ingestion.

## Phase 9: Scoring, interpretation, and handoff

After the owner submits and receives scored output:

- Preserve returned score artifacts and scorer revision.
- Populate the complete B0-B3 scorecards.
- Analyze per-function improvements and regressions.
- Separate text metrics, compile, behavior, cost, and completion.
- Decide whether the agent is experimental, publishable, or requires another
  architecture iteration.
- Update DecBench integration docs without contacting maintainers automatically.
