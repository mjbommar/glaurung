# Runtime and control-loop architecture

## Design objective

One invocation recovers one requested function. The model decides what static
evidence to inspect, but deterministic code owns scope, budgets, validation,
termination, persistence, and package assembly.

The agent is neither a free-form shell nor an outer loop that repeatedly calls
three LLM tools. It is a typed PydanticAI agent with a small, explicit tool set.

## Component boundary

```text
official manifest
      |
      v
run coordinator ---- checkpoint/artifact store
      |
      +-- source-recovery controller (one target)
              |
              +-- immutable SourceRecoveryContext
              +-- pydantic_ai.Agent
              |       |
              |       +-- approved static tools
              |       +-- structured RecoveredFunction output
              |
              +-- deterministic validator chain
                      |
                      +-- accept
                      +-- bounded repair feedback -> same agent run
                      +-- explicit failure
```

## Responsibility split

### Run coordinator

The coordinator owns work across binaries and functions:

- Load and hash `functions.json`.
- Verify every binary identity and requested address.
- Construct stable target IDs.
- Schedule bounded concurrency.
- Resume only compatible checkpoints.
- Persist each terminal function before scheduling more work.
- Assemble C files and `results.json` from accepted functions.
- Run package-wide static audits.

It does not choose analysis tools or rewrite C.

### Source-recovery controller

The controller owns one target:

- Build the context and initial prompt.
- Instantiate the correct model, tool set, settings, and usage limits.
- Execute the PydanticAI run.
- Route tool events to the trace recorder.
- Apply deterministic output validators.
- Return validator failures as bounded model-retry feedback when repairable.
- Produce one terminal `FunctionOutcome`.

It does not decide what evidence is semantically important; that is the agent's
job.

### PydanticAI agent

The agent owns the investigation:

- Orient on architecture and target bounds.
- Form hypotheses about signature, data flow, control flow, and calls.
- Select evidence tools.
- Revisit hypotheses when evidence conflicts.
- Emit one structured `RecoveredFunction`.
- Repair an output after actionable deterministic feedback if budget remains.

The agent may not change its tool policy, target, model, or budget.

### Deterministic validators

Validators decide whether an output is admissible. Model confidence is retained
as a diagnostic only and never substitutes for a validator.

## Per-function state machine

| State | Meaning | Allowed successors |
|---|---|---|
| `pending` | Manifest target has no compatible checkpoint | `starting` |
| `starting` | Context, policy, and trace are being created | `investigating`, `failed` |
| `investigating` | Agent may call approved tools | `synthesizing`, `failed`, `budget_exhausted` |
| `synthesizing` | Agent is producing structured C | `validating`, `failed` |
| `validating` | Deterministic checks are running | `accepted`, `repairing`, `rejected` |
| `repairing` | Validator feedback is returned to the agent | `investigating`, `synthesizing`, `budget_exhausted` |
| `accepted` | Final output satisfies every required check | terminal |
| `rejected` | Output is present but violates a non-repairable contract | terminal |
| `budget_exhausted` | A request/token/time/tool budget ended the run | terminal |
| `failed` | Provider, tool, controller, or persistence failure | terminal |

Every transition is an event in the trace. No target may disappear between
`starting` and a terminal state.

## Proposed core types

```python
class RecoveryTarget(BaseModel):
    binary_name: str
    binary_sha256: str
    requested_va: int
    canonical_va: int
    architecture: str
    manifest_sha256: str


class RecoveredFunction(BaseModel):
    identifier: str
    c_source: str
    c_prototype: str
    evidence_ids: list[str]
    assumptions: list[str]
    unresolved: list[str]
    confidence: float


class FunctionOutcome(BaseModel):
    target: RecoveryTarget
    status: Literal[
        "accepted", "rejected", "budget_exhausted", "failed"
    ]
    result: RecoveredFunction | None
    termination_reason: str
    validation: list[ValidationRecord]
    usage: UsageRecord
    artifact_paths: ArtifactPaths
```

The persisted schema receives an explicit version. Additive fields are allowed;
semantic changes require a new schema version and invalidate incompatible
resume checkpoints.

## Run shape

The first implementation should use a single PydanticAI `Agent.run()` with:

- `deps_type=SourceRecoveryContext`
- `output_type=RecoveredFunction`
- an explicit source-recovery tool set
- `UsageLimits`
- a result/output validator that may raise `ModelRetry`
- model settings from the official configuration profile

Do not begin with `pydantic_graph`. The vertical slice must prove the normal
agent/tool/output-validation path first. A graph becomes justified only if the
single run cannot express a measured control requirement.

## Initial prompt contract

The system prompt must establish:

- Role: expert reverse engineer recovering one function.
- Exact target binary identity and address scope.
- Static-only and no-source policy.
- Tool-output-as-untrusted-data rule.
- Requirement to investigate before answering.
- Requirement to preserve observed behavior rather than optimize readability.
- Exact structured output contract.
- Instruction to state unresolved facts instead of inventing them.
- Instruction to use validator feedback for repair without changing target.

The user prompt should contain only the target identity, requested address,
architecture facts, available tool summary, and a neutral task. Do not seed a
function name, source package, or project identity that can cue memorization.

## Termination rules

Accept only when all mandatory validators pass. Otherwise terminate explicitly
on the first applicable hard boundary:

1. Wall-clock deadline.
2. PydanticAI request limit.
3. Total/input/output token limit.
4. Tool-call or tool-output-byte limit.
5. Repeated identical tool call beyond policy.
6. Maximum validation-repair attempts.
7. Provider refusal or non-retryable provider error.
8. Non-repairable policy violation.
9. Persistence failure.

The official runner must not switch models, insert the fixed-pipeline result, or
fall back to raw output after a terminal agent failure. Those may be useful
separate baselines, never hidden recovery paths.

## Vertical-slice acceptance

Before adding more tools or parallelism, one real fixture must demonstrate:

- At least two different evidence tools chosen by the model.
- An evidence ledger linking tool results to the final output.
- A deliberately induced recoverable validation error.
- One repair turn producing accepted C.
- A complete replayable trace with model and tool schema identities.
- No binary execution and no out-of-scope file access.
