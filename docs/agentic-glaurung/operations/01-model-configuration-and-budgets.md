# Model configuration and budgets

## Configuration objective

Every result must identify the exact model, provider settings, budgets, prompt,
tool policy, Glaurung revision, and runner revision that produced it. A model
alias without those facts is not a reproducible version.

## Default model policy

Follow `CLAUDE.md` and `python/glaurung/llm/config.py`:

- Model: `openai:gpt-5.4-mini`
- Service tier: `flex`
- Temperature: `0.3` unless the experiment records another value
- Fallback model available to interactive users: `anthropic:claude-haiku-4-5`

For official evaluation, fallback is disabled. A provider failure is a recorded
failure or an explicitly resumed attempt with the same model; it never changes
the decompiler identity mid-run.

## Configuration precedence

Highest to lowest:

1. Explicit CLI arguments.
2. A checked-in named run profile.
3. Environment variables.
4. Project defaults.

The controller writes the resolved configuration, not merely the user inputs,
to `run-manifest.json` before the first model request.

## Proposed profiles

Initial values must be benchmarked and may change through a documented decision.

| Limit | `quick` | `development` | `official` |
|---|---:|---:|---:|
| PydanticAI requests | 4 | 8 | 12 |
| Validation repairs | 1 | 2 | 2 |
| Per-target wall time | 60 s | 300 s | 900 s |
| Input-token limit | 80,000 | 200,000 | 400,000 |
| Total-token limit | 100,000 | 260,000 | 500,000 |
| Max output tokens/request | 8,192 | 16,384 | 32,768 |
| Tool calls | 8 | 16 | 24 |
| Rendered tool bytes | 96 KiB | 192 KiB | 256 KiB |
| Identical tool+args repeats | 0 | 1 | 1 |
| Functions in flight | 1 | 1-2 | 1 by default |

The official request and token ceilings align with current project defaults.
The separate tool and rendered-byte limits protect against a small number of
very large tool calls.

## Model settings

Resolve settings through one function that is covered by tests:

```python
class SourceRecoveryModelConfig(BaseModel):
    model: str
    service_tier: Literal["flex", "default", "priority"]
    temperature: float
    max_output_tokens: int
    seed: int | None
    fallback_enabled: bool
```

Provider-specific settings are normalized but retained verbatim in diagnostics.
If a provider does not support a requested setting, fail before the run or
record the negotiated setting; do not silently ignore it.

## Run identity

The decompiler version should be machine-readable and stable, for example:

```text
glaurung-agent/
  glaurung=8a51f6ddd18f
  runner=<commit>
  model=openai:gpt-5.4-mini
  profile=official-v1
  prompt=<sha256-prefix>
  tools=<sha256-prefix>
  schema=1
```

The human-facing compact version may shorten hashes, while `run-manifest.json`
retains full values.

## Cost controls

- Estimate price from recorded provider usage, not prompt length guesses.
- Record cached input, uncached input, output, and reasoning tokens separately
  when the provider exposes them.
- Persist usage after every function.
- Stop scheduling new functions at the configured run-level request, token, or
  dollar ceiling.
- Let active functions reach a safe checkpoint unless the hard operator ceiling
  requires termination.
- Never log or infer billing from API key identity.

## Concurrency calibration

Increase concurrency only with measured provider and host evidence. For each
candidate setting record:

- Wall time and summed function time.
- Requests and tokens per minute.
- Provider throttles/retries.
- Host CPU, RSS, and native-analysis contention.
- Cost and output differences.

Start official runs at one worker. A move to two or more requires a controlled
A/B showing no policy, completion, or determinism regression. More workers can
slow native analysis and increase rate-limit backoff.

## Reproducibility limits

LLM output may remain nondeterministic even with a seed. Reproducibility means:

- Exact inputs and configuration are retained.
- The run can be replayed.
- Each artifact is immutable and hashed.
- A replay's differences are measured rather than denied.

Do not promise byte-identical model output unless repeated evidence proves it.
