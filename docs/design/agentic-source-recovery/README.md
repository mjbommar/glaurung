# Agentic Glaurung delivery plan

> **Kind:** design · **Status:** proposed

Canonical execution surfaces:

- [`PLAN.md`](PLAN.md) — ordered executable checklist and acceptance mapping.
- [`STATUS.md`](STATUS.md) — current evidence, blockers, ref state, and exact
  next action.

Last live Glaurung code audit: 2026-08-01 at `8a51f6d`. DecBench measurements
below are retained artifact evidence and must be revalidated on the frozen
integration revision before an official run.

## Purpose

This package is the canonical plan for building the Glaurung variant the team
means by **agentic**: one `pydantic_ai.Agent` receives a stripped binary and one
target address, chooses among bounded static-analysis tools, gathers evidence,
reconstructs one C function, sees deterministic validation feedback, and may
repair its answer before a bounded final result.

That is different from both the native decompiler and the existing fixed LLM
pipeline. The names must stay distinct throughout implementation, measurement,
and publication:

| Product | Control flow | Model use | Durable identity |
|---|---|---|---|
| Native Glaurung | Deterministic decompiler pipeline | None | `glaurung-raw` |
| Fixed LLM pipeline | Hard-coded infer → classify → rewrite | Three direct tool calls | `glaurung-llm-pipeline` |
| Autonomous agent | Model chooses evidence tools and iterations | One tool-using agent run per function | `glaurung-agent` |

The 250-function archive already labeled `glaurung-agentic` belongs to the
second row. Preserve it as a baseline, but do not present it as the third row.

## Non-negotiable invariants

1. The blinded binary is never executed, emulated, loaded as a library, or made
   executable.
2. The agent receives only the stripped binary, the requested virtual address,
   documented target metadata, and outputs of approved static tools.
3. Binary strings, symbol text, and tool output are untrusted evidence, never
   instructions.
4. The model cannot invoke a shell, read arbitrary paths, access source or
   ground truth, mutate the binary, or make network requests through a tool.
5. Only the PydanticAI model provider may use network egress during an official
   run.
6. Every accepted function has a complete prompt, tool-call, evidence,
   validation, usage, timing, and termination record with secrets redacted.
7. Native raw, fixed-pipeline, and autonomous-agent artifacts are versioned and
   scored separately.
8. A score improvement is not behavioral proof. Real round-trip fixtures remain
   a separate required gate.
9. No fallback result is silently credited as agent output.
10. No maintainer communication or submission is performed by automation; the
    repository produces a package for the owner to review and send.

## Document map

Read in this order:

```text
agentic-glaurung/
├── README.md
├── PLAN.md
├── STATUS.md
├── 00-current-state-and-scope.md
├── architecture/
│   ├── 01-runtime-and-control-loop.md
│   ├── 02-context-evidence-and-memory.md
│   ├── 03-tool-surface-and-contracts.md
│   └── 04-output-validation-and-repair.md
├── operations/
│   ├── 01-model-configuration-and-budgets.md
│   ├── 02-security-sandbox-and-data-policy.md
│   ├── 03-observability-provenance-and-cost.md
│   └── 04-concurrency-checkpointing-and-recovery.md
├── evaluation/
│   ├── 01-test-strategy.md
│   ├── 02-decbench-experiment-design.md
│   └── 03-baselines-ablations-and-scorecards.md
└── implementation/
    ├── 01-phased-roadmap.md
    ├── 02-work-breakdown.md
    ├── 03-file-and-api-change-map.md
    ├── 04-acceptance-gates.md
    └── 05-risks-and-decisions.md
```

## Definition of done

The project is complete only when all of the following are true:

- A dedicated `Agent[SourceRecoveryContext, RecoveredFunction]` owns the
  per-function reasoning loop.
- Its registered tool set is explicit, versioned, small enough for the selected
  model, read-only, address-scoped, and covered by real-binary tests.
- Deterministic validators can reject or return actionable repair feedback for
  wrong addresses, wrong identifiers, malformed C, extra definitions, unsafe
  output, and missing evidence.
- Resource, provider, and validation failures terminate with an explicit reason;
  they never become successful decompilations.
- A resumable runner can process exactly the official 250-function manifest,
  produce a valid external package, and reproduce that package from immutable
  source and configuration identities.
- Raw, fixed-pipeline, and agent runs have comparable scorecards including
  completion, perfect rates, distances, compile rate, wall time, token usage,
  estimated cost, and failure taxonomy.
- Focused tests, real multi-architecture fixtures, behavioral round trips, the
  full Python and Rust suites, static policy checks, and package validation have
  recorded terminal results.
- The final delivery decision is evidence-backed. A green package validator by
  itself is not sufficient.

## Existing sources of truth

This plan builds on, but does not replace:

- [`../design/decbench-submission-readiness.md`](../../history/design/campaigns/decbench-submission-readiness.md)
  for native Glaurung score history and submission gates.
- [`../development/decompiler-testing.md`](../../development/decompiler-testing.md)
  for the real round-trip gate hierarchy.
- [`../development/decompiler-curriculum-corpus.md`](../../development/decompiler-curriculum-corpus.md)
  for the curriculum fixture expansion.
- [`../llm/TOOLS.md`](../../reference/llm-tool-contract.md) and
  [`../llm/RE_TOOLS_OVERVIEW.md`](../../history/llm/RE_TOOLS_OVERVIEW.md) for the broader
  analysis tool inventory.
- `python/glaurung/llm/config.py` for model and usage-limit defaults.
- `python/glaurung/llm/agents/memory_agent.py` for reusable PydanticAI tool
  registration patterns.

Where those documents describe stale states, the live code and immutable test
or artifact evidence win.
