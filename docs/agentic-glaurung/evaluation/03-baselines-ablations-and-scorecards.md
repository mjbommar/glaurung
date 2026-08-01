# Baselines, ablations, and scorecards

## Why ablations matter

An autonomous agent can improve because of its model, raw pseudocode, CFG tools,
validation repair, extra tokens, or simple luck. The experiment must isolate
which capability buys quality and what it costs.

## Required baselines

### B0: Raw native

Deterministic Glaurung at the exact experiment revision. This is the reference
for whether the agent adds value over the decompiler.

### B1: Fixed LLM pipeline

The existing infer/classify/rewrite path. This isolates autonomous tool choice
from ordinary LLM post-processing.

### B2: Agent, disassembly-only

The same agent runtime and budgets with only simple binary facts and
disassembly-style tools. This is the closest internal policy analogue to Codex
and Claude Code on DecBench.

### B3: Agent, full Glaurung tools

The intended hybrid product with native pseudocode, CFG, call, type, xref,
string, and validation tools.

## Prior score anchors

Retained raw evidence, not a current same-revision comparison:

| Measure | Glaurung | angr | Ghidra |
|---|---:|---:|---:|
| GED mean, lower better | `41.335` | `21.774` | `20.281` |
| Compile rate | `97/250` | `120/250` | `125/250` |
| Type match mean | `0.127` | `0.280` | `0.231` |

The later raw checkpoint reports 250/250 compile coverage and byte-match mean
`0.15612902766757247`, but lacks a fresh full GED/type replacement score in the
retained document. The experiment must generate a new same-revision baseline.

The completed fixed-pipeline external run provides completion and syntax data,
not official DecBench scores:

- 250/250 functions accepted.
- 0 runner failures.
- 165/224 whole-binary C files syntax-check standalone.

## Primary ablation matrix

Run only after B0-B3 infrastructure is stable:

| ID | Change from B3 | Question |
|---|---|---|
| A1 | Remove native pseudocode | Does the decompiler hypothesis help beyond lower-level facts? |
| A2 | Remove CFG tool | Does explicit graph evidence improve GED-perfect results? |
| A3 | Remove call/prototype tools | Do call contracts improve types/compile/byte match? |
| A4 | Remove validation repair | Does repair improve admissibility or merely cost? |
| A5 | One request only | Is iterative tool use better than one-shot synthesis? |
| A6 | Half token/tool budget | What is the quality/cost frontier? |
| A7 | No cross-function tools | Do callers/callees justify their latency and leakage risk? |
| A8 | Deterministic tools only vs nested LLM tools | Reserved post-v1 provenance experiment |

Do not run all 250 functions for every ablation initially. Use a frozen public or
internally source-backed subset, promote only decisions with stable evidence,
and perform one final frozen B0-B3 comparison on the blind set.

## Predeclared hypotheses

- B1 should improve readability and some GED cases but may damage byte match by
  rewriting expressions.
- B2 should test model reasoning without native high-level hypotheses.
- B3 should improve completion, structural recovery, and types over B2 if tool
  contracts are useful.
- CFG removal should disproportionately reduce GED-perfect results.
- Call/prototype removal should disproportionately reduce type and compile
  results.
- Validation repair should improve compile/admissibility but may not improve
  semantic metrics.

Recording hypotheses before scoring reduces post-hoc storytelling.

## Scorecard template

### Identity

| Field | Value |
|---|---|
| Lane | |
| Glaurung commit | |
| Runner commit | |
| DecBench commit | |
| Kit manifest | |
| Model/settings | |
| Prompt/tool policy | |
| Budget/concurrency | |
| Artifact SHA-256 | |

### Completion and official metrics

| Measure | Value | Denominator | Baseline delta |
|---|---:|---:|---:|
| Accepted functions | | 250 | |
| Union perfect | | 250 | |
| GED perfect | | measured | |
| GED mean / median | | measured | |
| Type perfect | | measured | |
| Type mean / median | | measured | |
| Byte perfect | | measured | |
| Byte mean / median | | measured | |
| Official compile | | measurable | |
| Scorer/pipeline failures | | 250 | |

### Agent operations

| Measure | Mean | Median | p95 | Total |
|---|---:|---:|---:|---:|
| Wall seconds | | | | |
| Requests | | | | |
| Tool calls | | | | |
| Input tokens | | | | |
| Output tokens | | | | |
| Estimated USD | | | | |

### Validation and failures

| Category | Count | Repaired | Terminal |
|---|---:|---:|---:|
| Syntax | | | |
| Identifier/shape | | | |
| Evidence contradiction | | | |
| Policy | | | |
| Provider | | | |
| Tool/native | | | |
| Budget | | | |

### Behavioral safety net

Record behavioral passes, failures, structural-only cases, exact changed cells,
and whether raw behavior regressed. Do not combine this table with DecBench.

## Promotion gates

Promote an agent configuration to official evaluation only if:

- It has no policy or leakage failures.
- Completion is at least 98% on the frozen pilot, with all failures classified.
- It improves at least two targeted dimensions over B0/B1 on source-backed
  evaluation without a material regression in the third.
- Behavioral fixtures do not regress due to shared deterministic code changes.
- Median cost and p95 wall time remain inside the declared profile.
- The result is reproducible as an immutable artifact.

## Interpretation rules

- A higher Union score can hide worse types or byte match; always show all axes.
- A lower mean distance can coexist with fewer perfect functions; show both.
- Whole-file syntax rate is stricter and differently denominated than official
  per-function compile rate.
- A validator repair correlated with a better score is not proof the repair
  caused it.
- Public-fixture wins do not establish blinded generalization.
- Generated C quality does not establish behavioral equivalence.
