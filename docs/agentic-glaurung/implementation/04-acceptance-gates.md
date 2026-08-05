# Acceptance gates and commands

## Evidence reporting rule

Report focused tests, full suites, static policy, live model runs, behavioral
round trips, DecBench metrics, committed/pushed state, and remote CI as separate
states. A green item does not imply the others.

Commands below are the intended contract. Adjust exact filenames only when the
implementation lands, and update this document in the same change.

## Gate G0: Repository and artifact identity

```bash
git status --short --branch
git rev-parse HEAD
git diff --check
uv lock --check
```

Acceptance:

- Owned worktree has no unrelated changes.
- Baseline artifacts name immutable revisions and hashes.
- Raw, pipeline, and agent identities are distinct.

## Gate G1: Contract and validator tests

```bash
uv run pytest \
  python/tests/test_source_recovery_models.py \
  python/tests/test_source_recovery_context.py \
  python/tests/test_source_recovery_validation.py \
  -xvs
```

Acceptance: all pass, including wrong-address, extra-definition, policy,
evidence, syntax, and repair classification negatives.

## Gate G2: Deterministic tool tests

```bash
uv run pytest python/tests/test_source_recovery_tools.py -xvs
```

Acceptance:

- Real x86-64, ARM Thumb, and PE fixtures pass.
- Scope, limits, empty, unsupported, truncation, and native-error paths pass.
- Exact registered tool names match policy.
- No registered tool is network-, shell-, path-, mutation-, execution-, or
  emulation-capable.

## Gate G3: Controller, tracing, and resume

```bash
uv run pytest \
  python/tests/test_source_recovery_trace.py \
  python/tests/test_cli_agent_decompile.py \
  python/tests/test_decbench_external_agent.py \
  -xvs
```

Acceptance:

- One terminal outcome per started target.
- Atomic interruption/resume drills pass.
- Sentinel secret tests pass.
- Package mapping, partial labeling, and hash checks pass.

## Gate G4: Changed-path quality

```bash
uvx ruff format --check \
  python/glaurung/llm/agents/source_recovery*.py \
  python/glaurung/cli/commands/agent_decompile.py \
  python/tests/test_source_recovery*.py \
  python/tests/test_cli_agent_decompile.py \
  python/tests/test_decbench_external_agent.py \
  tools/decbench_external_agent.py

uvx ruff check \
  python/glaurung/llm/agents/source_recovery*.py \
  python/glaurung/cli/commands/agent_decompile.py \
  python/tests/test_source_recovery*.py \
  python/tests/test_cli_agent_decompile.py \
  python/tests/test_decbench_external_agent.py \
  tools/decbench_external_agent.py

uvx ty check \
  python/glaurung/llm/agents/source_recovery*.py \
  python/glaurung/cli/commands/agent_decompile.py \
  tools/decbench_external_agent.py
```

Acceptance: owned paths are green. Repository-wide existing debt is measured
and reported separately; do not mass-format unrelated code.

## Gate G5: Live-agent vertical slice

```bash
GLAURUNG_RUN_LIVE_AGENT_TESTS=1 \
GLAURUNG_LLM_MODEL=openai:gpt-5.4-mini \
GLAURUNG_OPENAI_SERVICE_TIER=flex \
uv run pytest python/tests/test_source_recovery_agent_live.py -xvs
```

Acceptance:

- Real provider and real analysis tools used.
- At least two model-selected evidence calls.
- Structured C accepted.
- One bounded validation-repair witness.
- Complete trace and usage.
- No fallback, policy violation, or secret leakage.

Record estimated maximum cost before running this opt-in gate.

## Gate G6: Prompt-injection and sandbox

```bash
GLAURUNG_RUN_LIVE_AGENT_TESTS=1 \
uv run pytest \
  python/tests/test_source_recovery_prompt_injection_live.py \
  python/tests/test_source_recovery_security.py \
  -xvs
```

Acceptance: embedded instructions remain evidence data, tools remain fixed, no
out-of-scope path/network/process occurs, and compiler validation remains
syntax-only.

## Gate G7: Internal round-trip matrix

```bash
tools/dectest.py @agent-core
scripts/decbench-local-gate.sh
```

The implementation must add an `@agent-core` set covering the frozen real-agent
fixtures. The broader local gate retains raw extraction, metric, and behavioral
lanes.

Acceptance:

- Raw/pipeline/agent results are labeled separately.
- Behavioral passes/failures/structural-only outcomes are retained.
- Shared deterministic changes do not regress the raw baseline.
- Metric improvements and regressions are listed per cell.

## Gate G8: Full repository tests

```bash
cargo test
uv run pytest python/tests/
```

Acceptance: terminal results recorded. Do not claim full green while a command
is still running or after only rerunning one failure.

## Gate G9: Pilot and freeze

```bash
uv run python tools/decbench_external_agent.py \
  --kit <kit> \
  --output-root <pilot-root> \
  --profile development \
  --only <frozen-target> \
  --resume
```

Run E0/E1/E2/E3 with predeclared target lists. At E3 acceptance:

- Completion >=98% with every failure classified.
- Static/security gates clean.
- Promotion criteria in the scorecard document pass.
- Cost and p95 time are within profile.
- Prompt, policy, configuration, and commits freeze.

## Gate G10: Official external run

```bash
uv run python tools/decbench_external_agent.py \
  --kit <official-kit> \
  --output-root <immutable-run-root> \
  --profile official \
  --jobs 1 \
  --resume
```

Acceptance:

- Exact manifest and 250 target accounting.
- Every target terminal; missing results explicit.
- Official `package.py` terminal result.
- Whole-file syntax audit retained separately.
- ZIP/audit/manifest/diagnostic hashes.
- Original kit unchanged.
- Secret scan clean.
- Representative and worst outputs inspected.
- No score claim until scored output returns.

## Gate G11: Git and remote integration

Only after code and gates are complete:

```bash
git diff --check
git status --short --branch
git log -1 --oneline
git ls-remote origin refs/heads/master
```

Acceptance:

- Owned commits are coherent and pushed.
- `master` and remote match when integration is authorized.
- Temporary worktrees are clean and pruned.
- DecBench integration remains a separate repository/ref with its own tests and
  upstream status.

## Release blockers

Any of these blocks an official run or submission-ready claim:

- Tool-policy or prompt-injection failure.
- Binary execution/emulation or source leakage.
- Missing trace/usage/termination evidence.
- Hidden model/raw/pipeline fallback.
- Validator accepts wrong target or extra function definition.
- Incompatible checkpoint reused.
- Package omits targets without declaring them.
- Unbounded cost, time, tool calls, or output.
- Improvements only on tuned public fixtures.
- Owner has not reviewed the final ZIP.
