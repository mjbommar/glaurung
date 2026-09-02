# LLM subsystem

> **Kind:** architecture · **Status:** maintained

`python/glaurung/llm/` is 313 files and 133,858 lines — 84% of the Python
package — and almost none of it calls a model. It is a large catalogue of
**deterministic tools** with a small agent layer on top, a knowledge base
underneath, and two schemes of cost control between them. Understanding it
starts with separating those three things.

Measured at commit `13faa6f7`, with the command that produced each number
beside it.

| part | files | lines | what it is |
|---|---:|---:|---|
| `llm/tools/` | 242 | 99,701 | deterministic analysis functions exposed as agent tools |
| `llm/agents/` | 29 | 15,916 | agent constructors, personas, structured output types |
| `llm/kb/` | 27 | 14,835 | the `.glaurung` knowledge base — see [`python-package-map.md`](python-package-map.md) |
| `llm/*.py` | 15 | 3,406 | config, context, routing, findings, critique, verification, budgets |

## Configuration

`LLMConfig` (`python/glaurung/llm/config.py`, a `@dataclass`) is the single
place model policy lives. `.env` is auto-loaded at import via
`dotenv.find_dotenv(usecwd=True)`; a missing `python-dotenv` degrades to
environment-only.

| field | default | env override |
|---|---|---|
| `default_model` | `openai:gpt-5.4-mini` | `GLAURUNG_LLM_MODEL` |
| `fallback_model` | `anthropic:claude-haiku-4-5` | — |
| `summarizer_model`, `risk_scorer_model`, `ioc_model` | `openai:gpt-5.4-mini` | — |
| `openai_service_tier` | `flex` | `GLAURUNG_OPENAI_SERVICE_TIER` (`flex` \| `default` \| `priority`) |
| `temperature` | `0.3` | `GLAURUNG_LLM_TEMPERATURE` |
| `default_request_limit` | `12` | `GLAURUNG_REQUEST_LIMIT` |
| `default_input_tokens_limit` | `400_000` | `GLAURUNG_INPUT_TOKENS_LIMIT` |
| `default_total_tokens_limit` | `500_000` | `GLAURUNG_TOTAL_TOKENS_LIMIT` |
| `default_max_output_tokens` | `32_768` | `GLAURUNG_MAX_OUTPUT_TOKENS` |
| provider keys | `None` | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `GEMINI_API_KEY` |

`preferred_model()` is the de-facto resolver — ten call sites, and what the
tools and the Java/Windows agents use. `create_agent()` writes the resolved key
back into `os.environ` before constructing a `pydantic_ai.Agent`, and is not on
the memory-agent path.

Four fields are declared and read nowhere in `python/`: `risk_scorer_model`,
`fallback_on_error`, `cache_responses`, and `fallback_model` (used only inside
`preferred_model()` itself).

**`ModelHyperparameters` is not in `config.py`.** It is a `pydantic.BaseModel`
in `python/glaurung/llm/agents/base.py`, with `temperature`, `top_p`, `top_k`,
`max_tokens`, `presence_penalty`, `frequency_penalty` and `seed`.
`to_model_kwargs(*, model_name=…)` emits only the non-`None` fields, and for an
`openai:` or `openai-responses:` model appends
`extra_body={"service_tier": …}` when the configured tier is not `default`.
`to_model_settings` is the same minus `top_k`, which is not in pydantic-ai's
portable `ModelSettings`. Three call sites build `extra_body` by hand instead
of going through it (`finding_critic.py`, `tools/_llm_helpers.py`,
`tools/suggest_function_name.py`), and two of those check only the `openai:`
prefix.

## Agents

Everything routes through one constructor:
`create_foundation_agent(model=None, *, output_type=str, system_prompt=None)`
in `agents/memory_foundation.py`. Its default persona is three lines, plus a
dynamic `@agent.system_prompt` that injects
`Context: file={path}, kb_nodes={n}, kb_edges={m}`. When no provider key is
available it constructs with `model="test"` rather than failing.
`deps_type=MemoryContext` throughout; there is no `Toolset`, no MCP server, and
no `pydantic_graph` usage anywhere in the tree.

`create_memory_agent(model=None, *, tool_filter=None)` is the foundation agent
plus `register_analysis_tools`.

**Strategies** (`agents/factory.py`): `AgentStrategy` is
`{SINGLE_PASS, ITERATIVE, AUTO}`, and `AnalysisAgentFactory` exposes
`create_fast_single_pass_agent`, `create_safe_iterative_agent` and
`analyze_with_best_strategy`. `SinglePassConfig` defaults to a 60-second
timeout; `IterativeConfig` to five iterations, 0.7 minimum confidence, 120
seconds, 100,000 tokens, and loop guards (`allow_repeated_tools=1`,
`detect_state_loops`, `pattern_detection_length=3`).

**Structured output** is where most of the agent layer lives.
`agents/specialized.py` builds seven agents through one `_make_agent`, each
with its own persona and Pydantic output type: `FunctionExplanation`,
`BinaryTriageReport`, `VulnerabilityHuntReport`, `SecurityPostureReport`,
`CallPathFinding`, `RenameSweepReport`, `StringClusterReport`,
`TaintTraceReport`. Elsewhere: `SuggestedFunctionName`, `BinarySummary`,
`IOCValidationResult` / `IOCValidationOutput`, `FindingsReport`, and the
critic's private verdict type.

**Java agents** (`agents/java.py`) are the one place a *profile-scoped* toolset
is used instead of the full catalogue:
`register_java_agent_tools(agent, *, profile=…)` with
`JavaAgentToolProfile ∈ {triage, security, recovery, deobfuscation}` and
toolsets of 16 / 18 / 19 / 17 tools. Unlike the memory agent's filter, this one
**raises** on an unknown tool name.

**The thirteen `windows_*` agent modules are deterministic workflows**, not model
calls. Only `agents/windows_pretty_lift_agent.py` imports `pydantic_ai`, and
its constructor has no caller in `python/glaurung/` — only a test builds it,
with `model="test"`. The Windows CLI reaches none of them through a model:

```bash
rg -c pydantic_ai python/glaurung/cli/commands/windows.py \
                  python/glaurung/cli/commands/windows_risk.py   # 0
```

## Tools, and how many there really are

```bash
ls python/glaurung/llm/tools/*.py | wc -l          # 242
ls python/glaurung/llm/tools/windows_*.py | wc -l  # 113
ls python/glaurung/llm/tools/java_*.py | wc -l     # 57
rg -c 'tool_to_pyd_ai\(' python/glaurung/llm/agents/memory_agent.py   # 164
rg -c 'tool_agent\.tool\(' python/glaurung/llm/agents/memory_agent.py # 55
```

`register_analysis_tools(agent, *, model_name=None, tool_filter=None)`
(`agents/memory_agent.py`) registers **219 tools** on a memory agent: 55 thin
`RunContext`-taking wrappers registered by name, and 164 direct
`add_tool(tool_to_pyd_ai(build_X()))` calls. The 164 are entirely
prefix-grouped — 112 `windows_*`, 46 `java_*`, 3 `pe_*`, 3 `minecraft_*` —
with no per-group registration function, so `tool_filter` is the only way to
opt a group out.

Three comments in the tree still say "~163 tools"
(`tool_routing.py`, `tools/base.py`, and `memory_agent.py`'s own docstring).
The count that is true today is 219, and it is reproducible:

```python
from glaurung.llm.agents.memory_agent import create_memory_agent
agent = create_memory_agent()
len(agent._function_toolset._tools)     # 219
```

`register_analysis_tools` first resolves strictness —
`default_tool_strict_for_model` returns `False` for `anthropic:` and `True`
otherwise, falling back to `GLAURUNG_TOOL_STRICT` when no model name is given —
then registers everything, then applies the filter.

**`_apply_tool_filter` is a post-hoc prune, not a pre-filter.** It registers
all 219 tools and then `pop()`s every key not in the filter out of
`agent._function_toolset._tools` (a private pydantic-ai attribute, with a
`.tools` fallback). Two consequences follow, and both matter: any failure is a
`log.warning` and the agent then runs with the *full* surface, and **unmatched
names are dropped silently**.

## L1–L5: the routing and analysis ladder

`L1`…`L5` are comment and docstring tags in the code, not identifiers. Four of
the five are real:

| tag | what it names | where |
|---|---|---|
| **L1** | a structured-output side pass over one question | one comment, `cli/commands/ask.py:323`. There is no L1-named module, class or function; the thing meant is `llm/findings_runner.py`, whose own docstring never says L1 |
| **L2** | self-critique of a `VulnerabilityFinding` | `finding_critic.py` (module docstring), `findings.py`, `findings_runner.py`, `finding_verifier.py`, `cwe_sweep.py`, `ask.py` |
| **L3** | CWE-class-driven discovery sweep | `cwe_sweep.py` (module docstring), `findings.py`, `findings_runner.py`, `ask.py` |
| **L4** | cite-or-discard finding verification | `finding_verifier.py` (module docstring), `finding_critic.py`, `findings.py`, `findings_runner.py`, `cwe_sweep.py`, `ask.py` |
| **L5** | per-question tool routing | `tool_routing.py` (module docstring), `memory_agent.py`, `agents/factory.py`, `findings_runner.py`, `ask.py` |

```bash
rg -o '\bL[1-5]\b' python/glaurung/llm/ python/glaurung/cli/
```

L3 sweeps a binary per CWE class. `DEFAULT_CWE_CLASSES` holds seven
`CWEClassSpec` entries — **CWE-121, CWE-134, CWE-190, CWE-416, CWE-401,
CWE-476, CWE-787** — each filterable by `applies_to ∈ {any, userland, kernel}`.

### L5 in detail: the router, and where it leaks

`llm/tool_routing.py` is a **deterministic** router: substring and regex
matching over the question, no model call. `Intent(name, tools, keywords,
keyword_re)` instances are tried in priority order — `vuln_discovery` (25
keywords), `triage_summary` (13), `function_walk` (7), `import_audit` (6),
`string_audit` (6), and `broad_discovery` (no keywords, the fallback, last by
construction). Public API: `route_for_question`, `select_tools_for_question`,
`list_intents`, `intent_summary`.

**The router's tool names do not all match the registry, and the mismatch is
silent.** Because `_apply_tool_filter` drops unmatched names without
complaining, an intent that lists fifteen tools can hand the model seven.
Measured against a real agent:

```python
registered = set(create_memory_agent()._function_toolset._tools)
[(i.name, len(i.tools), sum(t in registered for t in i.tools))
 for i in list_intents()]
```

| intent | names declared | tools that survive |
|---|---:|---:|
| `vuln_discovery` | 15 | **7** |
| `broad_discovery` | 15 | **7** |
| `function_walk` | 12 | **5** |
| `triage_summary` | 7 | **3** |
| `import_audit` | 4 | **2** |
| `string_audit` | 2 | **1** |

The names that match nothing in the repository are `extract_strings`,
`list_imports`, `list_exports`, `detect_packer`, `list_basic_blocks`,
`list_callers`, `list_callees`; `describe_call_site` exists as a tool but is
not registered on the memory agent. Two tool groups, `_GRAPH_TOOLS` and
`_VULN_FACT_TOOLS`, are defined and referenced by no `Intent` at all.
`findings_runner.py`'s own comment estimates "the broad-discovery subset (~17
tools)"; it is seven.

`python/tests/test_tool_routing.py` does not catch this: it asserts the
survivors are a *subset* of an expected set plus a non-empty check, which
passes with one tool present.

### Where routing is applied

Two places, and only one of them is opt-in.

1. `cli/commands/ask.py` — opt-in with `--route`, inspectable with
   `--show-routing`, escaped with `--all-tools`.
2. `llm/findings_runner.py` — the same flags, **plus an unconditional
   fallback**: if no filter was set and the model name starts with `openai:`
   or `openai-responses:`, routing is forced on to stay under OpenAI's
   128-tool cap. Since the project default *is* `openai:gpt-5.4-mini`, the
   findings pass is always routed and therefore always runs with at most seven
   tools.

The 128-tool cap is why routing exists at all; `tool_routing.py` names it
alongside Anthropic's 20-strict-tool limit. The alternative levers are
`tool_filter={…}` passed to `register_analysis_tools` directly, and the Java
profile toolsets. There is **no `--tools t1 t2` flag** despite
`tool_routing.py`'s docstring describing one, and no environment variable
enables routing.

## F1–F7: the cost guards

Also comment tags, all seven present.

| tag | what it is | where |
|---|---|---|
| **F1** | per-run budget defaults on `LLMConfig` and their env parsing | `config.py` |
| **F2** | per-call `request_limit` / `tool_calls_limit` caps | `findings_runner.py` (`request_limit=8`), `finding_critic.py` (`request_limit=2, tool_calls_limit=0, total_tokens_limit=50_000`), `agents/iterative.py`, `kb/binary_diff.py` |
| **F3** | `max_tokens` sizing | `findings_runner.py`, `finding_critic.py`, `usage_limits.py` |
| **F4** | session-wide cost telemetry | `usage_tracker.py`, called from `findings_runner.py`, `finding_critic.py`, `agents/single_pass.py`, `agents/iterative_refinement.py` |
| **F5** | cost-budget circuit breaker — `CostBudgetExceeded(RuntimeError)` | `usage_tracker.py`, `cwe_sweep.py`, `kb/binary_diff.py` |
| **F6** | skip the critic when L4 already demoted the finding | `finding_critic.py`, `kb/binary_diff.py` |
| **F7** | incremental partial-result writes, so a killed sweep leaves recoverable state | `cwe_sweep.py` |

`usage_limits.build_usage_limits(...)` turns the config into a pydantic-ai
`UsageLimits`; its `model_name` argument is documented as informational only,
with no per-provider branching. `usage_tracker.py` carries
`PRICE_PER_MILLION_USD` in USD per million `(input, output)` tokens —
`openai:gpt-5.4-mini` `(0.15, 0.60)`, `openai:gpt-5.5` `(5.00, 15.00)`,
`openai:gpt-5.5-mini` `(0.25, 1.00)`, `anthropic:claude-haiku-4-5`
`(1.00, 5.00)`, `anthropic:claude-sonnet-4-6` `(3.00, 15.00)`,
`anthropic:claude-opus-4-7` `(15.00, 75.00)`, `test` zero — and a prefix match
for dated model ids. Tracking is **opt-in**: a call site has to call
`.record(...)`.

A second, non-token budget sits in `llm/context.py`: `Budgets` bounds what a
tool may *read and compute* — `max_functions=5`, `max_blocks=2048`,
`max_instructions=50_000`, `timeout_ms=200`, `max_read_bytes=10 MiB`,
`max_file_size=100 MiB`, `max_disasm_window=4096`, `max_results=200`. Those are
the numbers `ask`'s `--max-read-bytes`, `--max-functions`, `--max-instructions`
and `--disasm-window` move.

`cwe_sweep.sweep_binary` takes `max_parallel=1`, implemented as an
`asyncio.Semaphore`. No CLI flag exposes it.

## Which commands actually call a model

Five of the forty subcommands, and one shared helper.

| command | file | what it reaches |
|---|---|---|
| `ask` | `cli/commands/ask.py` | `AnalysisAgentFactory`, `cwe_sweep.sweep_binary`, `findings_runner.run_findings_pass`, `tool_routing.route_for_question`, `usage_tracker` |
| `explain` | `cli/commands/explain.py` | `infer_function_signature`, `classify_function_role`, `rewrite_function_idiomatic`, plus `commands/_layer0_prepass.py` (`name_local_variable`, `name_string_literal`, `classify_constant`) |
| `name-func` | `cli/commands/name_func.py` | `SuggestFunctionNameTool.run(use_llm=True)`; exits 2 with no provider key |
| `java` | `cli/commands/java.py` | `agents.java_runner.run_java_agent_analysis` |
| `repl` | `cli/commands/repl.py` | only the interactive `ask` verb: `create_memory_agent()` + `run_sync` |

`ask`'s LLM and guard flags: `--agent`, `--strategy`, `--max-iterations`,
`--min-confidence`, `--timeout`, `--show-tools`, `--show-plan`, `--model`,
`--max-read-bytes`, `--max-file-size`, `--quick`, `--max-functions`,
`--max-instructions`, `--disasm-window`, `--findings-json`, `--skip-critique`,
`--cwe-sweep`, `--cwe-sweep-applies`, `--route`, `--show-routing`,
`--all-tools`, `--max-cost-usd` (F5), `--usage-log` (F4, JSONL).

`explain` has `--with-layer0` / `--no-layer0`, whose own help states the cost:
"10-30 LLM calls per function (~$0.20-$0.50)". It has no `--model`.

**`windows` and `windows-risk` make no model call**, despite 4,025 and 2,652
lines and imports of four `llm.agents.windows_*` modules — see the Agents
section above and [`windows-port.md`](windows-port.md).

## The knowledge base underneath

Every tool and agent writes through `llm/kb/`, and every write is ranked. That
is what makes the agent's output auditable rather than merely plausible: an
LLM-suggested name lands with a `set_by` the analyst can see and outrank. Read
[`../reference/provenance.md`](../reference/provenance.md) for the ladder and
[`persistent-project.md`](persistent-project.md) for the file it lives in.

`MemoryContext` (`llm/context.py`) is what a tool receives — the file path, the
triage artifact, the `Budgets` above, and the KB. `MemoryContext.open_persistent`
is how a tool gets all four at once against a real project file.

## Two source-recovery systems, one shipped

They are easy to confuse and are not the same thing.

- **Shipped:** `scripts/recover_source.py` (2,587 lines) walks a binary through
  a 25-tool Layer 0 → Layer 4 ladder and writes a recovered source tree. The
  ladder's tools are ordinary `llm/tools/` modules and the ordering is
  documented in
  [`../reference/llm-source-recovery-tools.md`](../reference/llm-source-recovery-tools.md).
- **Designed, not built:** the *agentic* variant in
  [`../design/agentic-source-recovery/`](../design/agentic-source-recovery/) —
  one `pydantic_ai.Agent` receives a stripped binary and one address, chooses
  among bounded tools, and iterates against deterministic validation feedback.
  That package is a live proposal, not a description of the tree.

## Names to be careful with

Several plausible-sounding names are not in the code, and every one of them has
appeared in a document at some point:

| name | reality |
|---|---|
| `GLAURUNG_AGENT_ROUTE` | no reader anywhere; routing is `--route` or `tool_filter=` |
| `--tools t1 t2` | no such flag, though `tool_routing.py:11` documents one |
| `--max-parallel` | `max_parallel` is a `sweep_binary` parameter with no CLI flag |
| an `L1` identifier | one comment; the module meant is `findings_runner.py` |
| "the `windows analyst` LLM code path" | `windows.py` calls no model |
| "~163 tools" | 219 registered |
| provider rate-limit handling | no rate-limit constant, retry-after handling, or ceiling literal exists |
