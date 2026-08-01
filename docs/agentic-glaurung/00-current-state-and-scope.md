# Current state and scope boundary

## Executive verdict

Glaurung has the pieces needed to build a genuine source-recovery agent, but
they are not yet assembled into that product.

- Native Glaurung exists and has retained DecBench measurements.
- A fixed LLM-assisted pipeline exists and has completed the 250-function
  external kit.
- A generic PydanticAI agent and a large analysis-tool surface exist.
- No DecBench runner currently gives a PydanticAI agent autonomous control over
  a curated tool set and a repair loop.

The implementation project therefore starts with integration and contract work,
not with inventing another decompiler or another generic agent framework.

## Three evidence lanes

### 1. Native raw Glaurung

The retained blinded score checkpoint in
[`../design/decbench-submission-readiness.md`](../design/decbench-submission-readiness.md)
records the following at Glaurung `f02ecb9` with harness `4f80682`:

| Measure | Retained value | Meaning |
|---|---:|---|
| GED distance | `41.3347280335` | Mean structural edit distance; lower is better |
| Type match | `0.1271417040` | Mean type-recovery score |
| Byte match | `0.0423607691` | Mean recompilation similarity |
| Compile coverage | `97/250` | Official fixup/recompile coverage at that checkpoint |
| Adapter completion | `250/250` | All requested functions emitted |

A later documented raw checkpoint, `d6882dc`, reports 250/250 official
byte-match compilations and mean byte match `0.15612902766757247`, but it does
not have a fresh complete GED/type result in the retained document. Treat it as
a later output checkpoint, not as a complete replacement scoreboard.

Before any agent-vs-raw claim, rebuild raw output from the exact comparison
revision and score all metrics on the same DecBench revision. Do not splice
moving evaluator results without immutable function-key accounting.

### 2. Fixed LLM pipeline

`glaurung explain` executes a predetermined sequence:

1. `infer_function_signature`
2. `classify_function_role`
3. `rewrite_function_idiomatic`

`tools/decbench_external_agentic.py` launches that command once per target and
rejects output unless the signature and rewrite stages report LLM provenance.
Its completed artifact records:

| Measure | Value |
|---|---:|
| Binaries | `224/224` |
| Functions | `250/250` |
| Runner failures | `0` |
| Whole-file standalone syntax | `165/224` |
| Model identity | `openai:gpt-5.4-mini` |
| Glaurung identity | `8a51f6d` |

This is a valuable baseline. It is not autonomous: the model cannot decide to
inspect disassembly, CFG shape, callees, strings, or xrefs, and it cannot react
to validation errors by choosing new evidence.

### 3. Autonomous source-recovery agent

This lane is missing. Its minimum distinguishing properties are:

- One PydanticAI agent run owns one requested function.
- The model selects tools from an approved, purpose-built subset.
- Tool results enter a typed evidence ledger.
- The agent may perform multiple tool and reasoning turns within hard budgets.
- Deterministic validation can return repair feedback into the same bounded run.
- The final structured result cites the evidence used and records unresolved
  assumptions.

## Reusable implementation assets

| Existing asset | Reuse | Required correction |
|---|---|---|
| `LLMConfig.create_agent()` | Provider/model construction | Add source-recovery-specific settings and fail-closed fallback policy |
| `build_usage_limits()` and config defaults | Request/token ceilings | Add per-profile wall-clock and tool-result byte ceilings |
| `MemoryContext` and `Budgets` | Binary context and read limits | Introduce target-address scope and immutable evidence ledger |
| `register_analysis_tools()` | Wrapper conventions | Do not register the full 164-tool surface; use an explicit source-recovery set |
| `tool_routing.py` | Curated-set precedent | Add a fixed DecBench route, not question-keyword routing |
| `decompile_function`, disassembly, CFG, xref, string, import tools | Deterministic evidence | Normalize schemas, bounds, and errors for one-function recovery |
| `IterativeRefinementAgent` | Loop and termination ideas | Remove debug output, audit semantics, and avoid using self-reported confidence as the accept oracle |
| External runner | Manifest loading, resume, packaging | Replace fixed `glaurung explain` invocation with the agent CLI/API |

## In scope

- ELF, PE, ARM/Thumb, and x86/x86-64 targets present in the DecBench sample set.
- One target function per independent agent run.
- Static evidence available from Glaurung's deterministic analysis APIs.
- Structured C recovery, validation, bounded repair, trace capture, resume, and
  package production.
- Raw/pipeline/agent comparisons and controlled ablations.
- Internal real-binary and behavioral regression coverage.

## Out of scope for the first release

- Executing or emulating a benchmark binary.
- Fetching source code, debug source paths, package sources, or internet search
  results that reveal ground truth.
- A general unrestricted coding shell.
- Whole-program source-tree recovery.
- Persistent mutation of analyst KB names or types during a blinded run.
- Nested LLM-backed tools inside the primary agent. The agent should reason over
  deterministic evidence first; nested-model ablations may come later.
- Automatic publication, emailing, issue creation, or maintainer contact.

## Fair-comparison statement

Codex and Claude Code on DecBench are general coding agents constrained to
manual recovery from simple binary-inspection tools. A Glaurung agent is a
hybrid agent using a real decompiler and richer analysis tools. Its results are
still useful, but they must be labeled accordingly. Never imply that the tool
policies are identical.

The evaluation must retain at least these separate rows:

- `glaurung-raw`: native decompiler only.
- `glaurung-llm-pipeline`: fixed three-stage post-processing.
- `glaurung-agent`: autonomous agent using the declared Glaurung tool policy.
- Optional `glaurung-agent-disasm-only`: fairer tool-policy ablation against
  general coding agents.

## Immediate project objective

Deliver the smallest true agent that can recover one real fixture function with
an auditable sequence of deterministic tool calls, fail a wrong-address or
malformed-C attempt, repair it using validator feedback, and reproduce the final
result under pinned configuration. Expand only after that vertical slice is
green.
