# File and API change map

## Design principle

Keep generic source-recovery agent code inside `python/glaurung`; keep blinded
manifest scheduling and package assembly in `tools/`. Do not bury the agent
inside the DecBench fork or the existing `explain` command.

## Proposed new Python modules

### `python/glaurung/llm/agents/source_recovery_models.py`

Owns versioned Pydantic models:

- `RecoveryTarget`
- `SourceRecoveryPolicy`
- `EvidenceRecord`
- `RecoveredFunction`
- `ValidationRecord`
- `UsageRecord`
- `FunctionOutcome`
- `RunManifest`

No native calls, provider calls, or filesystem side effects.

### `python/glaurung/llm/agents/source_recovery_context.py`

Owns `SourceRecoveryContext`, binary session/cache handles, evidence append API,
target scoping, and scratch-path policy.

Proposed API:

```python
def build_source_recovery_context(
    binary_path: Path,
    requested_va: int,
    *,
    policy: SourceRecoveryPolicy,
    trace: TraceSink,
) -> SourceRecoveryContext:
    ...
```

### `python/glaurung/llm/agents/source_recovery_tools.py`

Owns the explicit tool wrappers and registration:

```python
SOURCE_RECOVERY_TOOL_NAMES: tuple[str, ...]

def register_source_recovery_tools(
    agent: Agent[SourceRecoveryContext, RecoveredFunction],
    *,
    policy: SourceRecoveryPolicy,
) -> Agent[SourceRecoveryContext, RecoveredFunction]:
    ...
```

Registration fails if actual names differ from policy.

### `python/glaurung/llm/agents/source_recovery_validation.py`

Owns V1-V7, stable diagnostic codes, repair classification, compiler/parser
adapter, and package-level source checks.

```python
def validate_recovered_function(
    result: RecoveredFunction,
    context: SourceRecoveryContext,
) -> ValidationReport:
    ...
```

### `python/glaurung/llm/agents/source_recovery_prompt.py`

Owns prompt v1 and deterministic rendering. Exposes prompt hashes and keeps
binary-derived data out of the system-policy section.

### `python/glaurung/llm/agents/source_recovery_trace.py`

Owns JSONL events, redaction, hashes, per-function layout, usage normalization,
and atomic writes.

### `python/glaurung/llm/agents/source_recovery.py`

Owns agent factory and one-function controller:

```python
def create_source_recovery_agent(
    config: SourceRecoveryRunConfig,
) -> Agent[SourceRecoveryContext, RecoveredFunction]:
    ...


async def recover_function(
    target: RecoveryTarget,
    config: SourceRecoveryRunConfig,
    artifacts: FunctionArtifactStore,
) -> FunctionOutcome:
    ...
```

This is the only module that coordinates provider calls, tools, validation
feedback, and terminal outcomes.

## Proposed CLI

### `python/glaurung/cli/commands/agent_decompile.py`

One target per invocation:

```text
glaurung agent-decompile BINARY --func 0xADDR \
  --model openai:gpt-5.4-mini \
  --profile official \
  --artifact-dir DIR \
  --format json
```

Required behavior:

- Static-only by construction.
- Structured JSON outcome on stdout.
- Logs on stderr with secrets redacted.
- Stable exit codes for accepted, rejected, exhausted, and infrastructure
  failure.
- No raw or fixed-pipeline fallback.

Do not overload `glaurung explain`; that command remains the fixed pipeline.

## Proposed external tools

### `tools/decbench_external_agent.py`

New official-kit coordinator using the source-recovery API/CLI. Reuse manifest,
resume, atomic write, source aggregation, and syntax-audit concepts from the
existing runner, but write schema v1 artifacts and full traces.

### Rename/deprecate existing runner

Rename `tools/decbench_external_agentic.py` to an honest fixed-pipeline identity,
for example `tools/decbench_external_llm_pipeline.py`. Keep a compatibility shim
for one release if users already invoke the old path. The shim must print a
clear deprecation message without changing artifact identity.

## Existing modules to extend carefully

| File | Change | Constraint |
|---|---|---|
| `python/glaurung/llm/config.py` | Resolve source-recovery profiles/settings | Preserve project model defaults |
| `python/glaurung/llm/context.py` | Reuse budgets or add shared primitives | Do not weaken general-agent compatibility |
| `python/glaurung/llm/usage_limits.py` | Build official `UsageLimits` | Exact limits recorded per run |
| `python/glaurung/llm/tools/base.py` | Shared typed envelope helpers if justified | Avoid global behavior changes without tests |
| `python/glaurung/cli/main.py` | Register command | Keep non-LLM startup lazy |
| `python/glaurung/llm/agents/__init__.py` | Export stable public API | Avoid importing full tool registry eagerly |

Do not add DecBench-specific behavior to the Rust decompiler unless a real raw
fixture and raw regression test require it.

## Proposed tests

| Test file | Coverage |
|---|---|
| `python/tests/test_source_recovery_models.py` | Schema, identity, serialization |
| `python/tests/test_source_recovery_context.py` | Scope, cache, evidence ledger |
| `python/tests/test_source_recovery_tools.py` | Real-binary tool contracts |
| `python/tests/test_source_recovery_validation.py` | V1-V7 and repair classes |
| `python/tests/test_source_recovery_trace.py` | Events, atomic writes, redaction |
| `python/tests/test_source_recovery_agent_live.py` | Explicit opt-in real-model vertical slice |
| `python/tests/test_cli_agent_decompile.py` | CLI JSON/exit codes and static policy |
| `python/tests/test_decbench_external_agent.py` | Manifest, resume, package, hashes |
| `python/tests/test_source_recovery_prompt_injection_live.py` | Real hostile-string fixture |

Reuse current fixture builders and compiled assets. Do not create mock binaries
or claim live-agent behavior from simulated provider responses.

## DecBench fork changes

The DecBench fork should ultimately expose three separate registrations and
documentation rows if upstream accepts them:

- `glaurung-raw`
- `glaurung-llm-pipeline`
- `glaurung-agent`

The agent row is sample-set-only and external-results-capable. Its installation
documentation must state model credentials, tool policy, cost, trace handling,
and the hybrid comparison caveat.

Do not edit or push DecBench integration until Glaurung's local agent contract is
green and the owner authorizes that repository work.

## Import and startup discipline

PydanticAI and the large tool surface materially increase import cost. Keep all
new agent imports lazy behind the command or API call. `import glaurung` and
ordinary native decompilation must not import the agent registry or provider
clients.

Add an import-time/RSS comparison before and after CLI registration. A new
agent command must not slow raw decompilation startup through eager imports.
