# Observability, provenance, and cost

> **Kind:** design · **Status:** proposed

## Objective

An agent result without a tool and usage trail cannot be debugged, reproduced,
priced, or compared fairly. Observability is part of the result contract, not an
optional debug mode.

## Artifact layout

```text
run-root/
├── run-manifest.json
├── progress.json
├── functions/
│   └── <target-id>/
│       ├── outcome.json
│       ├── events.jsonl
│       ├── messages.json
│       ├── evidence.json
│       ├── validation.json
│       └── recovered.c
├── results/
│   ├── <binary>.c
│   └── results.json
├── diagnostics.json
└── submission.zip
```

Write per-function artifacts atomically before updating `progress.json`.

## Event schema

Every line in `events.jsonl` includes:

```json
{
  "schema_version": 1,
  "run_id": "...",
  "target_id": "...",
  "sequence": 17,
  "monotonic_ns": 123,
  "event": "tool_result",
  "payload": {}
}
```

Required events:

- `target_started`
- `model_request_started`
- `model_request_finished`
- `tool_call_requested`
- `tool_call_started`
- `tool_call_finished`
- `evidence_recorded`
- `output_proposed`
- `validation_started`
- `validation_failed`
- `repair_requested`
- `target_accepted`
- `target_terminated`
- `checkpoint_written`

Use monotonic time for durations and UTC timestamps only for human correlation.

## Message capture

Retain the exact redacted system/user messages and the provider message history
needed to replay the run. Record hashes before and after redaction. Never place
full transcripts in the external submission ZIP.

## Tool provenance

For every call record:

- Tool name and schema version.
- Canonical arguments after controller clamping.
- Tool-policy hash.
- Target and address ranges.
- Status, duration, truncation, warnings, and result hash.
- Evidence IDs exposed to the model.
- Native Glaurung revision and relevant renderer/analysis configuration.

## Validation provenance

Each validator emits:

- Validator name/version.
- Required/advisory severity.
- Pass/fail.
- Stable diagnostic codes.
- Input source hash.
- Compiler/parser identity when applicable.
- Whether feedback was returned to the model.

## Usage and cost

Normalize provider usage into:

```python
class UsageRecord(BaseModel):
    requests: int
    input_tokens: int
    cached_input_tokens: int | None
    output_tokens: int
    reasoning_tokens: int | None
    tool_calls: int
    estimated_cost_usd: Decimal | None
    pricing_revision: str | None
```

Store raw provider usage alongside normalized fields. Estimated cost must name
the pricing table and date; it is not a billed amount.

Aggregate at function, binary, and run levels:

- Mean/median/p50/p90/p95 wall time.
- Mean/median/p95 tokens and tool calls.
- Total estimated cost.
- Cost per accepted function.
- Cost by termination class.
- Tool-call distribution and empty/truncated/error rate.
- Validation failures and repairs by code.

## Failure taxonomy

Use stable categories:

- `provider_auth`
- `provider_rate_limit`
- `provider_timeout`
- `provider_refusal`
- `usage_limit`
- `wall_timeout`
- `tool_policy`
- `tool_timeout`
- `tool_native_error`
- `invalid_structured_output`
- `validation_rejected`
- `repair_exhausted`
- `checkpoint_error`
- `package_error`

The human error string supplements the category and must be redacted.

## Required dashboards/reports

The runner should produce one Markdown summary generated from diagnostics:

- Completion and termination table.
- Tool use and validation table.
- Time/token/cost distributions.
- Syntax and package results.
- Exact identities and hashes.
- Links to worst/slowest traces.
- Explicit statement that no DecBench score is present until ingestion.

After scoring, join results by exact function key to produce correlations such
as tool calls vs GED, validation repairs vs compile success, and cost vs perfect
Union. Do not infer causality from those correlations.

## Redaction tests

Before any official run:

- Seed process environment with sentinel secret values.
- Cause provider, tool, compiler, and checkpoint errors.
- Verify no sentinel enters logs, traces, JSON, C, or ZIP.
- Verify redaction does not destroy model/tool/version provenance.

This test may use sentinels; it must not expose a real key.
