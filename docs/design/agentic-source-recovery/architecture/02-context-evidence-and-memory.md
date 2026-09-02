# Context, evidence, and memory

> **Kind:** design · **Status:** proposed

## Principle

The model may reason freely, but every durable claim must trace to bounded,
typed evidence. Context is not a bag of strings; it is an immutable target plus
an append-only evidence ledger.

## `SourceRecoveryContext`

The source-recovery context should be separate from the general mutable
`MemoryContext`, while reusing its artifact and budget primitives where safe.

Required fields:

| Field | Purpose |
|---|---|
| `target` | Immutable binary/address/architecture identity |
| `binary_path` | Controller-resolved path; tools never accept arbitrary replacements |
| `artifact` | One triage result reused across tools |
| `analysis_session` | Cached native analysis for the binary |
| `budgets` | Read, instruction, block, result, time, and tool limits |
| `evidence` | Append-only typed evidence ledger |
| `trace` | Event sink for prompts, calls, validation, and usage |
| `policy` | Static-only tool and path policy |
| `scratch` | Ephemeral controller-owned directory for generated C only |

The context must not expose API keys, source paths, the private scorer, project
names, or the package metadata in `functions.json.private` to the model or
tools.

## Evidence record

Every successful tool call emits one or more records:

```python
class EvidenceRecord(BaseModel):
    evidence_id: str
    tool_name: str
    tool_schema_version: int
    target_id: str
    request: dict[str, JsonValue]
    result_sha256: str
    result_summary: str
    payload: JsonValue
    address_ranges: list[AddressRange]
    truncated: bool
    warnings: list[str]
    created_monotonic_ns: int
```

`evidence_id` is stable within a run and is what the final result cites. The
full payload stays in diagnostics; the model may receive a bounded rendering.

## Evidence classes

Tag records so validation and ablation can distinguish their authority:

- `binary_fact`: format, architecture, image base, section ranges.
- `instruction_fact`: disassembly and decoded operand evidence.
- `cfg_fact`: blocks, edges, branch kinds, dominance, loop facts.
- `call_fact`: call target, import identity, prototype, argument/result facts.
- `data_fact`: strings, constants, global references, stack slots.
- `decompiler_hypothesis`: native pseudocode or recovered types; useful but not
  equivalent to machine-code fact.
- `validator_fact`: parser/compiler diagnostics about generated C.
- `agent_assertion`: model conclusion not independently proven.

The system prompt must explain that `decompiler_hypothesis` and
`agent_assertion` have lower authority than instruction/call/CFG facts when
they conflict.

## Scope enforcement

All address-bearing tool requests pass through one controller function:

```text
requested VA
  -> canonicalize architecture state (including ARM Thumb bit)
  -> verify mapped section
  -> verify target or permitted neighborhood
  -> clamp window/result budget
  -> invoke native API
  -> record exact covered range
```

Permitted scopes:

- Target function body.
- Bounded predecessor/successor blocks needed to explain entry/tail behavior.
- Direct callers and callees up to configured depth and count.
- Imported symbol/prototype records reached by a target call.
- Strings/globals directly referenced by the target or an allowed callee.

Whole-binary enumeration is allowed only for compact orientation metadata such
as imports, sections, and function-address indexes. Large bodies remain
address-scoped.

## Memory lifetime

### Per binary

Cache deterministic expensive work across target functions:

- Triage and format parsing.
- Function discovery and CFG index.
- Symbol/import maps.
- Read-only native analysis session.

Key by binary SHA-256, Glaurung revision, native schema version, and analysis
configuration. Never reuse across a key mismatch.

### Per function

Keep agent evidence and conversation isolated. Cross-function facts may be
served from the binary cache, but one target's model assertions or generated C
must not enter another target's prompt.

### Across runs

Only deterministic binary analysis caches may persist. Model responses and
agent evidence are run artifacts, not an implicit cache. An optional response
cache must be opt-in and keyed by every prompt, model, tool, binary, target, and
configuration identity; it is disabled for the official first run.

## Context compaction

Tool output can dominate tokens. Each tool therefore supplies:

- A small model-facing representation.
- The complete retained payload.
- A hash linking the two.
- A truncation marker and query for narrower follow-up.

Do not use an LLM summarizer inside the initial agent run. Deterministic
summaries preserve attribution, reduce cost, and avoid nested model provenance.

Suggested model-facing ceilings:

| Evidence | Default ceiling |
|---|---:|
| Disassembly | 160 instructions per call |
| CFG blocks | 64 blocks |
| Callers/callees | 32 records |
| Strings/xrefs | 64 records |
| Native pseudocode | 24 KiB |
| Individual tool payload | 32 KiB rendered text |
| Total tool payload per target | 256 KiB rendered text |

These are initial values to benchmark, not permission to exceed provider or
project usage limits.

## Prompt-injection boundary

Binary content can contain text such as "ignore previous instructions". The
tool layer must wrap all content in typed data fields and label it untrusted.
The system prompt must prohibit treating binary-derived text as commands.

Tests must include a real compiled fixture embedding adversarial instruction
strings and prove that:

- The string is returned as evidence.
- No extra tool or path becomes available.
- The output trace records the string as data.
- The agent still obeys the static-only and output policies.

## Evidence sufficiency

The first release requires the final output to cite:

- At least one instruction or CFG fact.
- At least one signature/call/data fact when the function contains such
  behavior.
- Every evidence record used to justify a nontrivial struct, external call, or
  constant interpretation.

Missing citations are repairable validation failures. Self-reported confidence
is not evidence sufficiency.
