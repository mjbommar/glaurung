---
id: tech-llm-model-defaults
name: LLM Model Defaults (binary-analysis tasks)
priority: 60
active: true
---

# LLM Model Defaults

## REQUIRED default for Glaurung LLM calls

**Model:** `openai:gpt-5.4-mini`
**OpenAI service tier:** `flex`

This applies to every code path that calls an LLM in this repo:
`glaurung ask`, `glaurung name-func`, `glaurung windows analyst`,
the L2 critic, the L3 CWE sweep, and the L1 structured-output runner.

Wired into `python/glaurung/llm/config.py`:

```python
LLMConfig.default_model       = "openai:gpt-5.4-mini"
LLMConfig.fallback_model      = "anthropic:claude-haiku-4-5"
LLMConfig.summarizer_model    = "openai:gpt-5.4-mini"
LLMConfig.risk_scorer_model   = "openai:gpt-5.4-mini"
LLMConfig.ioc_model           = "openai:gpt-5.4-mini"
LLMConfig.openai_service_tier = "flex"
```

`ModelHyperparameters.to_model_kwargs(model_name=...)` adds
`extra_body={"service_tier": "<tier>"}` automatically when the model
name starts with `openai:` and the tier is not `"default"`. The
critic and findings runner both pass `model_name=` through.

Environment overrides:

```
GLAURUNG_LLM_MODEL=openai:gpt-5.4-mini      # also set automatically by config
GLAURUNG_OPENAI_SERVICE_TIER=flex           # 'flex' | 'default' | 'priority'
```

## When NOT to swap models

If a sweep hits OpenAI's 128-tool cap (`Invalid 'tools': array too
long. Expected an array with maximum length 128, but got an array
with length 218 instead.`), **DO NOT** fall back to Anthropic.
That cap is exactly what L5 routing exists to solve.

Use one of:

* Pass `--route` on the CLI (deterministic intent router picks <=30
  tools per question).
* Pass `tool_filter={'name1', ...}` to `register_analysis_tools`
  programmatically.
* Set `GLAURUNG_AGENT_ROUTE=1` in the environment as a global default.

If a sweep hits Anthropic's 4M-tokens-per-minute IPM ceiling, the
right answer is to lower `max_parallel` in `sweep_binary` (default
is 1; raising it in distributed runs is on you to coordinate),
**not** to swap to a different model family.

## When explicit overrides are appropriate

Users can pass `--model anthropic:claude-opus-4-7` (or any other
provider:model string) for one-off interactive runs where the
heavier model is justified. The default stays at gpt-5.4-mini for
batched / automated work.
