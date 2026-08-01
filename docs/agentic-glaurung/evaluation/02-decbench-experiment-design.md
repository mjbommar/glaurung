# DecBench experiment design

## Objective

Produce a defensible three-way comparison on the exact same 250-function
sample-set manifest:

1. Native Glaurung.
2. Fixed LLM pipeline.
3. Autonomous Glaurung agent.

No lane may inherit another lane's output, failure fallback, or score.

## Dataset contract

- Use the official external sample-set kit and record its manifest SHA-256.
- Read only the public target mapping required for recovery.
- Do not expose private/project-identifying metadata to the model.
- Statistically analyze the blinded binary only; never execute or emulate it.
- Preserve exact requested addresses and ARM Thumb semantics.
- Retain the original kit unchanged and verify its identity after the run.

## Lane identities

| Lane | Allowed evidence | Model behavior | Required name |
|---|---|---|---|
| Raw | Native Glaurung only | none | `glaurung-raw` |
| Fixed pipeline | Native pseudocode + fixed infer/classify/rewrite | no autonomous tool choice | `glaurung-llm-pipeline` |
| Agent | Declared source-recovery tool policy | autonomous bounded tool choice | `glaurung-agent` |
| Disasm ablation | Simple binary facts/disassembly only | autonomous bounded tool choice | `glaurung-agent-disasm-only` |

The disassembly-only ablation is the closest comparison to DecBench's Codex and
Claude Code tool policy. The full Glaurung agent is a hybrid and must be labeled
as such.

## Frozen experiment tuple

Before starting a lane, write:

- Glaurung commit.
- Runner commit.
- DecBench commit.
- Eval-kit manifest and binary hashes.
- Container/image digest if used.
- Model and provider settings.
- Prompt hash.
- Tool-policy hash.
- Budget profile.
- Concurrency.
- Artifact schema.
- Start time and owner authorization.

Changing any member creates a new experiment, not an in-place continuation.

## Development sequence

### E0: Contract smoke

- 1 binary / 1 function.
- Verify policy, trace, output, validation, and package fragment.
- No score claim.

### E1: Architecture smoke

- At least one x86-64, ARM Thumb, and PE target.
- Include one multi-function binary.
- Compare raw/pipeline/agent output and failure paths.

### E2: Ten-function pilot

- Fixed target list declared before running.
- Measure completion, syntax, tool use, time, tokens, and cost.
- If local source-backed scoring is available, score all lanes on the same
  evaluator revision.

### E3: Fifty-function pilot

- Stratify only from public manifest facts such as format/architecture, not
  source or prior score difficulty.
- Freeze configuration after this gate.
- Investigate failures by category, not by hand-tuning hidden targets.

### E4: Official 250-function run

- Fresh run identity.
- Official profile and frozen configuration.
- Default one worker unless concurrency calibration approved another value.
- Resume only exact compatible checkpoints.
- Produce package, diagnostics, trace index, and hashes.

### E5: Score ingestion

- The owner submits the ZIP through the external workflow.
- After scored output is returned, preserve it immutably.
- Join results by exact function identity.
- Do not overwrite pre-submission diagnostics.

## Metrics

### Official headline

- Union perfect rate.
- GED-perfect rate.
- Type-perfect rate.
- Byte-match-perfect rate.

### Distance and fairness controls

- GED mean/median and measured denominator.
- Type edit-distance mean/median and denominator.
- Byte edit-distance mean/median and denominator.
- Official per-function fixup compile rate.
- Pipeline/parser failure counts.

### Operational

- Accepted/failed/rejected/exhausted targets.
- Wall-time distribution.
- Tool calls and requests per function.
- Input/output/reasoning tokens.
- Estimated cost and cost per accepted/perfect function.
- Validation repair count and outcome.

### Internal safety net

- Whole-file standalone syntax rate.
- Behavioral round-trip pass/fail/structural-only counts.
- Raw regression cells.

Never merge those different denominators into one ambiguous "score."

## Fair A/B rules

- Same target manifest and binaries.
- Same scoring revision.
- Same function-key mapping.
- No successful-subset means.
- Missing functions remain failures/absences according to scorer policy.
- Same C preamble/package behavior unless the lane explicitly owns a different
  required declaration.
- Compare immutable artifacts, not moving output directories.
- Retain per-function deltas, including regressions hidden by an aggregate gain.

## Leakage audit

Before scoring, prove:

- Prompt and tools contain no source or DWARF source identity.
- The model cannot access package/project names from private manifest metadata.
- No web/Git/package lookup tool exists.
- Neutral binary naming is used where practical.
- Trace search finds no source snippets or repository paths.
- Any model memorization risk is disclosed as a benchmark limitation.

## Delivery package

Retain two archives:

1. `glaurung-agent-results.zip`: only official C files and `results.json`.
2. `glaurung-agent-audit.tar.zst`: run manifest, diagnostics, traces, evidence,
   usage, validation, and hashes; never sent unless explicitly requested and
   reviewed for secrets/private material.

The submission ZIP must pass official `package.py`. The audit archive must pass
schema, hash, and secret checks.

## Submission boundary

Automation ends after producing and validating the archives. It does not email,
comment, open an issue, upload, or otherwise contact the maintainer. The owner
reviews and sends the result.
