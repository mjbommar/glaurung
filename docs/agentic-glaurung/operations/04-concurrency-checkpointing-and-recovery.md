# Concurrency, checkpointing, and recovery

## Objective

The 250-function run must survive interruption without duplicating paid work,
mixing configurations, losing diagnostics, or crediting partial output.

## Stable identities

```text
run_id = sha256(
  manifest hash + binary-set hash + Glaurung revision + runner revision +
  model settings + prompt hash + tool-policy hash + budget profile + schema
)

target_id = sha256(run_id + binary name + binary sha256 + requested VA)
```

Human labels may include binary stem and address, but resume decisions use full
identities.

## Checkpoint contract

A compatible terminal checkpoint contains:

- Target and run identities.
- Terminal status and reason.
- Final source hash when accepted.
- Complete usage and trace hashes.
- Validation results.
- Artifact schema version.
- Atomic completion marker written last.

Resume may reuse only a terminal checkpoint whose full `run_id` matches. A
different model, prompt, budget, tool set, source revision, manifest, or schema
starts a distinct run.

## Atomic writes

For each artifact:

1. Write to a temporary file in the destination directory.
2. Flush and close.
3. Validate parse/hash where applicable.
4. Atomically rename.
5. Update the target completion marker.
6. Atomically update global progress.

A crash before the marker leaves an incomplete target that is safe to retry.

## Retry policy

### In-run repair

Validator feedback handled inside the same bounded agent run is not an
infrastructure retry and counts against request/repair budgets.

### Infrastructure retry

Retry only explicitly transient classes:

- Provider 429/rate limit with bounded provider-aware backoff.
- Provider 5xx/transport error.
- Controller process interruption before any terminal checkpoint.

Do not automatically retry:

- Authentication failure.
- Tool-policy violation.
- Invalid target or manifest mismatch.
- Deterministic validator rejection.
- Usage or wall-clock exhaustion.
- Native crash on the same input more than the configured crash retry.

Every infrastructure retry increments an attempt number and retains the failed
attempt trace. Never merge two conversations into one credited result.

## Scheduler

The scheduler operates on independent target work items and must:

- Preserve the exact manifest set.
- Cap global and per-provider concurrency.
- Stop launching on run-level cost/token/request ceilings.
- Prefer one target per binary at a time until binary-cache thread safety is
  proven.
- Persist after every target.
- Handle SIGINT/SIGTERM by stopping new scheduling and checkpointing safe state.
- Report pending, active, accepted, rejected, failed, and exhausted counts.

## Concurrency safety

- PydanticAI agents and contexts are per target.
- Evidence ledgers and scratch directories are never shared.
- Read-only binary analysis caches may be shared only behind documented
  thread/process safety.
- SQLite KB use is read-only for official runs; if opened, use one connection
  per process and do not persist model mutations.
- Artifact assembly occurs after all target workers stop.

## Resume modes

| Mode | Behavior |
|---|---|
| `--resume` | Reuse matching terminal checkpoints, retry incomplete targets |
| `--retry-transient` | Reattempt prior transient infrastructure failures |
| `--retry-rejected` | Explicit experimental rerun; creates new run identity or attempt set |
| `--only <binary[:va]>` | Bounded development subset; never relabeled full |
| `--fresh` | New run root; retains old artifacts |

Default resume must not retry accepted, rejected, budget-exhausted, or
non-transient failed targets.

## Package assembly

Package only after scheduling is terminal. The assembler:

- Groups accepted functions by exact binary identity.
- Sorts functions by requested VA.
- Resolves declaration collisions deterministically.
- Records all missing functions in diagnostics.
- Refuses a complete label unless all 250 targets are accepted.
- Runs whole-file static syntax audit.
- Invokes the official `package.py` validator.
- Hashes ZIP, manifest, diagnostics, and each C payload.

Partial packages may be produced for debugging but must include `partial` in
their name and cannot overwrite the final path.

## Recovery drills

Automated tests must interrupt a real multi-function fixture run:

1. During a provider wait.
2. During a native tool call.
3. Between outcome write and completion marker.
4. During package assembly.

After resume, verify no accepted target is billed or executed twice, incomplete
targets rerun once, hashes remain consistent, and the final package matches a
clean uninterrupted run where model nondeterminism is not involved. For live
model runs, compare target accounting and contracts rather than requiring
byte-identical C.
