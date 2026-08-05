# Agentic Glaurung status and resume record

Snapshot date: 2026-08-03

Overall state: **READY TO START PHASE 0; AUTONOMOUS AGENT NOT IMPLEMENTED**

Current phase: Phase 0 — identity, policies, and immutable baselines

Current task: F01 — correct the fixed-pipeline runner identity

Implementation progress: 0 of 64 work-breakdown tasks complete

Read [`PLAN.md`](PLAN.md) for the ordered checklist. This file records the
current evidence, blockers, and exact next action; update both files together.

## Executive state

The detailed architecture, operations, evaluation, roadmap, dependency, risk,
and acceptance-gate documents exist. The implementation has not started.

Live inspection on 2026-08-03 confirmed:

- `tools/decbench_external_agentic.py` exists and invokes the fixed
  `glaurung explain` pipeline.
- `python/tests/test_decbench_external_agentic.py` tests that fixed runner.
- `python/glaurung/llm/agents/source_recovery.py` does not exist.
- `tools/decbench_external_agent.py` does not exist.
- Therefore no DecBench runner currently gives a dedicated PydanticAI agent
  autonomous control of the source-recovery tool set.

The next work is identity and contract preparation, not a benchmark launch.

## Commit and ref snapshot

Moving refs must always be rechecked before work. This table is retained as the
exact state observed when these control documents were created.

| Item | Observed state |
|---|---|
| Detailed-plan commit | `a374669166288e53d451daefa39e891cc43b21aa` |
| `origin/master` at worktree creation | `a374669166288e53d451daefa39e891cc43b21aa` |
| Initial PLAN/STATUS integration | `db5cbe47eeafd444511b0db0c47bab7e32a5fb25`, pushed and verified on `origin/master` |
| Documentation lane | `docs/agentic-plan-status`, based on `origin/master` |
| Integration target | `master`, then `origin/master` after validation |
| Concurrent checkout | `decompiler-gap-phase1` at `a374669`, with extensive unrelated dirty work |
| Concurrent-work policy | Do not stage, edit, clean, reset, or rebase that checkout |

Resolve the current integrated state with:

```bash
git fetch origin --prune
git rev-parse HEAD
git rev-parse origin/master
git status --short --branch
git ls-remote origin refs/heads/master
```

## Completed work

- [x] The three product identities and fair-comparison boundary are documented.
- [x] Runtime, evidence, tool, validator, repair, and output contracts are
  designed.
- [x] Model, budget, security, trace, cost, concurrency, checkpoint, and resume
  policies are designed.
- [x] Real-binary, behavioral round-trip, DecBench, baseline, and ablation
  evaluation plans are documented.
- [x] Phases, 64 implementation tasks, dependencies, file/API changes,
  acceptance gates, risks, and decisions are documented.
- [x] Canonical `PLAN.md` and `STATUS.md` entrypoints exist and are linked from
  the agentic package README and repository docs index.

These are planning/control-plane completions only. All F/V/T/A/O/R/E/H code and
evaluation tasks remain unchecked in [`PLAN.md`](PLAN.md).

## Evidence ledger

| Evidence | State | Meaning |
|---|---|---|
| Detailed planning package | PASS at `a374669` | 18 design/operations/evaluation/implementation documents retained on `origin/master` before this status addition |
| Canonical PLAN/STATUS files | PRESENT in current documentation change | Resume and progress surfaces now exist |
| Agentic implementation | NOT STARTED | No dedicated source-recovery agent module or external agent runner exists |
| Raw DecBench evidence | RETAINED, MIXED REVISIONS | Historical score anchors exist; same-revision remeasurement remains F06/E01 |
| Fixed LLM pipeline | IMPLEMENTED, MISNAMED | Useful baseline, but not autonomous; F01 corrects the live identity |
| Live autonomous-agent fixture | NOT RUN | Blocked on F02-F05, V01-V09, T01-T13, and A01-A07 |
| Internal behavioral agent round trip | NOT RUN | Blocked on A08 and the Phase 6 fixture gate |
| Official 250-function agent run | NOT AUTHORIZED | Blocked on all earlier phases, frozen pilot, security gates, and cost authorization |

Documentation-only validation for the current change is recorded below. It is
not evidence for agent implementation or benchmark readiness.

## Acceptance-gate status

| Gate | State | Latest evidence |
|---|---|---|
| Documentation local-link validation | PASS, 2026-08-03 | 21 Markdown files checked; all local links resolve and heading separators pass |
| PLAN/work-breakdown consistency | PASS, 2026-08-03 | All 64 work IDs occur exactly once; F01 is the first unchecked implementation task |
| Documentation whitespace/diff validation | PASS, 2026-08-03 | `git diff --check` plus new-file checks reported no whitespace errors |
| G0 repository/artifact identity | NOT RUN for implementation | Required at the start of F01 in a clean isolated worktree |
| G1 contracts/validators | NOT RUN | Phase 1 implementation absent |
| G2 deterministic tools | NOT RUN | Phase 2 implementation absent |
| G3 controller/trace/resume | NOT RUN | Phases 3 and 5 implementation absent |
| G4 changed-path quality | NOT RUN for implementation | No agent code exists |
| G5 live vertical slice | NOT RUN / NOT AUTHORIZED | Requires implementation, provider credentials, and bounded cost review |
| G6 security/injection | NOT RUN | Requires the live agent and sandbox |
| G7 internal round-trip matrix | NOT RUN | Requires `@agent-core` fixtures and the agent |
| G8 full repository tests | NOT RUN for this docs-only change | No production code changed |
| G9 pilot/freeze | BLOCKED | Earlier gates incomplete |
| G10 official external run | BLOCKED | Freeze and owner cost authorization absent |
| G11 Git/remote integration | PASS for initial PLAN/STATUS addition | `db5cbe47eeafd444511b0db0c47bab7e32a5fb25` matched `refs/heads/master` on 2026-08-03 |

Do not infer one evidence state from another. In particular, documentation
validation is not an implementation, behavioral, benchmark, or full-suite gate.

## Current blockers and deferred requirements

There is no technical blocker to starting F01 in an isolated worktree.

The following do not block F01, but they block later promotion:

- F06 must locate and hash the completed fixed-pipeline archive and establish
  the exact available DecBench scorer/kit revisions.
- Q1-Q10 in
  [`implementation/05-risks-and-decisions.md`](implementation/05-risks-and-decisions.md#open-questions-requiring-a-decision-before-phase-7)
  must be resolved or explicitly accepted before Phase 7.
- Live model gates require valid provider credentials and a recorded maximum
  cost before execution.
- The official 250-function run requires a frozen experiment tuple, completed
  security/behavioral gates, and explicit owner cost authorization.
- Maintainer communication and submission remain owner-only actions.

The dirty `decompiler-gap-phase1` checkout is a concurrency constraint, not a
project blocker. Agentic work must use its own clean worktree and preserve that
lane exactly.

## Exact next action

Start F01 using TDD in a clean agentic implementation worktree based on the
then-current `origin/master`:

1. Re-audit all references to `decbench_external_agentic`,
   `glaurung-agentic-diagnostics`, and claims that the fixed three-stage runner
   is autonomous.
2. Add or rename the focused test to
   `python/tests/test_decbench_external_llm_pipeline.py` and make it fail until:
   - the fixed runner's canonical path is
     `tools/decbench_external_llm_pipeline.py`;
   - live diagnostics and version identity use `glaurung-llm-pipeline`;
   - the old path, if retained for one release, is only a clearly deprecated
     compatibility shim;
   - historical archives remain unchanged and honestly described.
3. Run the new focused test and retain the expected RED result.
4. Implement the minimal rename, compatibility, diagnostics, test, and docs
   changes needed for GREEN.
5. Run the focused runner tests, changed-path Ruff checks, `git diff --check`,
   and the relevant G0 identity checks.
6. Commit, integrate, push, verify `origin/master`, mark F01 complete in
   [`PLAN.md`](PLAN.md), and replace this next action with F06.

Expected focused command after the RED test exists:

```bash
uv run pytest python/tests/test_decbench_external_llm_pipeline.py -xvs
```

## Stop conditions for the next action

Stop F01 and update this file instead of improvising if:

- the existing fixed-pipeline artifact would need to be overwritten or
  relabeled;
- compatibility requires silently changing output identity;
- concurrent changes touch the same runner/test/docs paths;
- `origin/master` moves and the new base materially changes the runner contract;
- the focused test cannot distinguish fixed sequence control from autonomous
  model-selected tool use.

## Definition of the next checkpoint

The next checkpoint is complete only when F01 is checked in `PLAN.md`, the fixed
pipeline has an honest live identity, historical evidence remains intact,
focused tests and changed-path checks have terminal results, the bounded commit
is integrated and pushed, the remote ref is verified, and this file names F06
as the exact next action.
