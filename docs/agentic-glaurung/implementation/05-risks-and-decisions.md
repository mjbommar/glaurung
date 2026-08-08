# Risks, decisions, and open questions

> **Status: active design risk register.** Accepted design choices constrain
> future implementation; unresolved questions remain blockers at the phases
> named here.

## Risk register

| ID | Risk | Likelihood | Impact | Mitigation | Trigger/owner action |
|---|---|---:|---:|---|---|
| R1 | Model invents plausible but false C | high | high | Evidence citations, deterministic contradiction checks, behavioral fixtures | Stop promotion on systematic uncited inventions |
| R2 | Fixed pipeline is mislabeled agentic | existing | high | Three durable identities and separate artifacts | Rename before new evaluation |
| R3 | Nested LLM tools obscure provenance/cost | high | medium | Deterministic-only v1 tool policy | Allow only as explicit later ablation |
| R4 | Embedded string prompt injection | medium | high | Typed untrusted data boundary and live adversarial fixture | Any policy deviation is release blocker |
| R5 | Agent accesses source/private metadata | low-medium | critical | Minimal context, neutral naming, no web/path tools, leakage audit | Invalidate affected run |
| R6 | Binary executes or is emulated | low | critical | Static-only process/tool/container policy and negative tests | Invalidate run and investigate |
| R7 | API key leaks to trace/package | low-medium | critical | Redaction, sentinel tests, artifact secret scans | Rotate key; invalidate artifact |
| R8 | Tool registry exceeds model/provider limits | medium | high | Explicit <20-tool registration and startup assertion | Fail before first request |
| R9 | Tool output overwhelms context | high | medium | Per-call/total byte ceilings and deterministic compaction | Tune ceilings from trace data |
| R10 | Cost or rate limits run away | medium | high | Request/token/tool/dollar limits and one-worker default | Stop scheduling at run ceiling |
| R11 | Resume duplicates paid work | medium | high | Stable IDs, atomic terminal markers, recovery drills | Reconcile attempts before continuing |
| R12 | Shared caches cross-contaminate targets | low-medium | high | Deterministic binary cache only; isolated agent evidence | Invalidate contaminated run |
| R13 | PydanticAI private API changes | medium | medium | Dedicated public registration path; fail-closed assertions | Pin/update with compatibility tests |
| R14 | Provider/model alias drifts | medium | high | Record resolved model/settings and provider metadata | New experiment identity |
| R15 | Compiler validation becomes execution surface | low | high | stdin, syntax-only, sandbox, include policy, limits | Disable compiler gate until contained |
| R16 | Agent optimizes DecBench text metrics but behavior worsens | high | high | Separate behavioral round-trip gate and per-cell regressions | Do not promote aggregate-only gain |
| R17 | Public fixture overfitting | high | high | Frozen holdout and predeclared pilots | Revert target-specific prompt/tool logic |
| R18 | Raw architecture caps agent quality | high | high | Lower-level evidence tools and raw architecture roadmap | Attribute rather than hide bottleneck |
| R19 | Full 250 run succeeds but cannot be reproduced | medium | high | Immutable identities, manifests, traces, hashes, clean rebuild | Do not submit unlabeled artifact |
| R20 | Hybrid results compared as agent-alone | medium | high | Tool-policy disclosure and disasm-only ablation | Correct publication/scorecard wording |

## Accepted decisions

### D1: Three products, three identities

Native raw, fixed LLM pipeline, and autonomous agent remain separate. No hidden
fallback crosses lanes.

### D2: One target per agent run

Isolation simplifies cost, traces, failure accounting, and DecBench mapping.
Cross-function evidence is available only through bounded tools.

### D3: Deterministic tools only in v1

The primary agent is the only model decision-maker. LLM-backed analysis tools
remain fixed-pipeline or later ablation components.

### D4: Explicit source-recovery tool registry

Do not reuse the broad memory-agent registry or private-attribute best-effort
filtering. Registration mismatch fails closed.

### D5: Static-only blinded policy

No execution or emulation. Generated C may receive syntax-only validation.

### D6: Controller owns trust and resources

The model chooses investigation actions. Deterministic code owns target scope,
tool availability, budgets, validation, persistence, and acceptance.

### D7: Structured output plus evidence

C alone is insufficient for audit. The external package strips diagnostics only
after a structured result and complete trace are retained.

### D8: Bounded validator feedback

Repair is useful but limited to two official attempts. Policy/scope failures are
terminal.

### D9: Official fallback disabled

Provider failure does not silently switch models or substitute raw/pipeline
output.

### D10: No automated maintainer contact

The workflow ends with owner-reviewed artifacts. Submission and communication
remain manual owner actions.

### D11: Behavioral and DecBench evidence stay separate

GED/type/byte metrics, compile rate, and generated syntax do not prove runtime
equivalence.

### D12: Start with normal PydanticAI agent flow

Use `Agent.run`, typed tools, usage limits, structured output, and output
validation first. Introduce `pydantic_graph` only for a measured missing control
requirement.

## Open questions requiring a decision before Phase 7

### Q1: Official hybrid tool disclosure

What exact public description distinguishes the full Glaurung agent from
Codex/Claude Code's disassembly-only policy? Proposed answer: publish both the
full tool list and a disasm-only ablation.

### Q2: Native pseudocode in the default policy

Does `decompile_native` belong in v1 default or only in the full hybrid lane?
Proposed answer: include it in B3, exclude it in B2.

### Q3: Model size and comparison

Is `gpt-5.4-mini` the product target or merely a cost baseline before a larger
model? Proposed answer: keep project default for v1, then run a predeclared model
ablation if budget permits.

### Q4: Temperature and seed

Should official v1 favor low variance (`0.0-0.3`) or exploration? Proposed
answer: retain `0.3`, measure repeat variance on the pilot, and freeze.

### Q5: Evidence validator strictness

How much CFG/source structural comparison is safe without rejecting valid C
rewrites? Proposed answer: only high-confidence contradictions block v1; softer
checks are warnings until calibrated.

### Q6: Trace disclosure

Which traces, if any, can accompany public results without revealing benchmark
or credential-sensitive material? Proposed answer: retain full private audit,
publish only redacted aggregate tool/usage metadata unless reviewed.

### Q7: Response caching

Can identical official targets reuse a prior model response? Proposed answer:
no for the first official run; evaluate cache mechanics separately.

### Q8: Concurrency

Can two workers improve wall clock without rate-limit or native contention?
Proposed answer: begin at one and approve two only after controlled pilot data.

### Q9: Promotion target

What metric threshold makes the agent worth submitting? Proposed answer: do not
predeclare one Union number before a same-revision baseline; require improvement
in at least two official axes, no material third-axis/behavior regression, and
acceptable cost.

### Q10: DecBench naming/upstream shape

Will upstream prefer one Glaurung PR with multiple rows or raw integration plus
an external-only agent result? This requires owner/maintainer coordination after
local completion; automation does not decide or communicate it.

## Decision-log template

Append future decisions to this file:

```markdown
### DNN: Short title

- Date:
- Status: proposed | accepted | superseded
- Context:
- Decision:
- Alternatives:
- Consequences:
- Evidence:
- Supersedes:
```

Do not silently revise an accepted decision. Mark it superseded and link the new
decision so old artifacts remain interpretable.
