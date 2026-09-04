# Performance and determinism ratchet plan

> **Kind:** plan · **Status:** proposed

This plan turns roadmap R6 and the determinism half of M7 into a release-grade
contract. It starts from the performance tools already in the repository; it
does not replace them with another benchmark framework.

## Progress

Commit `a938d897` recorded a three-reference retired-instruction baseline with
three runs per reference and observed spreads of 0.1–0.2%. An injected 10%
regression was verified to fail.

P9 landed in `4f4f88e3`: the gate now fails closed and is scheduled. Three
states that previously returned 0 — including a baseline reference the run
never measured — exit 3, "not evidence"; the scheduling came second on
purpose, because scheduling a fail-open gate manufactures assurance. It runs
from `.github/workflows/perf-nightly.yml`.

P1's missing-file condition is resolved and P2/P3 are covered by the
fail-closed states. P4–P8 remain open: provenance, RSS, output identity, and
returned-body completeness are still absent from the baseline contract.

`ef24d729` also makes the P1/P3 and statically impossible P2 decisions true
preflight checks. They now return exit 3 before launching the gate's nine
large-binary decompilations. The focused fail-closed suite fell from an
effectively unbounded full-suite stall to 0.62 seconds; assertions pin that
these paths never reach the measurement marker. Runtime failure of a configured
reference remains a post-measurement P2 check.

## Why this gate counts instructions

Carried from the earlier estate phase this plan supersedes, because the
reasoning is what keeps the design small:

* **Wall-clock on this box is noisy under load**, and the arch gate has
  recorded false failures for exactly that reason. Retired-instruction counts
  are stable to well under 1% across load, which is what justifies a tight
  threshold; a wall-clock gate could not carry one.
* **`perf` works here** once the sysctl is set — `kernel.perf_event_paranoid`
  ships at `4` and passwordless sudo is available.
* **The number must be measured on a release build.** `maturin develop` builds
  debug, and the two profiles disagree completely (the allocator is 6.5% of a
  debug profile and 26.2% of a release one). `tools/build_guard.py` runs
  first, and the gate refuses a debug extension.
* **RSS is the cheap canary, not a headline.** Allocation churn was this
  codebase's largest real performance bug — 47.5% of a discovery profile in
  libc `malloc`/`free`, and effectively invisible to sampling self-time — so
  peak RSS per reference is recorded with a loose threshold rather than left
  out.
* **Criterion stays diagnostic.** Ten wall-clock targets across a multi-minute
  run is exactly the check that gets skipped; they answer *where* a regression
  lives once the shipped-entry gate has said *that* one exists.

## Evidence boundary

The pinned full DecBench decompile processed 803 binaries and returned 94,358
bodies in 213.1 seconds. That is strong throughput evidence for one release,
machine, corpus, invocation, and build. It is not a regression gate and does
not isolate instruction count, memory, tail latency, output volume, or
completeness changes.

Current local performance evidence consists of:

* ten Criterion targets, including discovery, lift, dataflow, structuring, and
  a partially recomposed decompile pipeline;
* `tools/perf_gate.py`, invoked by `scripts/decbench-local-gate.sh`, measuring
  three committed binaries three times through the shipped Python
  `decompile_all` entry point;
* `tools/decompiler_profile.py` and pipeline trace events, which already report
  cold/warm time, per-phase time, object parses, and `ru_maxrss`;
* a retained 2026-08-08 profiler snapshot under
  `tests/decompiler_profile/`; and
* default-suite decompile determinism tests over x86-64 ELF, ARM64 ELF, PE,
  sequential subprocesses, concurrent subprocesses, and known Rust render
  flippers.

This is useful substrate. It is not yet a fail-closed release ratchet.

## Proven gaps in the current gate

### P1 — baseline absence fails closed before measurement (closed)

`bench/perf_baseline.json` is present. If an overridden or production baseline
is missing, `tools/perf_gate.py` now returns exit 3 before measurement. The
developer bootstrap state is distinct from a passing gate without paying for a
measurement that cannot be compared.

### P2 — incomplete measurements fail closed (closed; typed detail remains)

A positive baseline reference outside the configured population or absent from
disk now returns exit 3 before measurement. A configured reference that fails
during measurement is detected afterward and also returns exit 3. Per-reference
typed failure detail remains part of the v2 schema work.

### P3 — incomparable units fail closed before measurement (closed)

The intended baseline uses retired instructions. On a host without usable
`perf`, the tool switches to seconds. If baseline and current units differ, it
now returns exit 3 before measurement. That remains a useful developer
diagnostic but is never a passing gate verdict.

### P4 — provenance is insufficient

The report currently records only unit, run count, and measures. It does not
pin the Glaurung commit, native-extension SHA-256, build profile, Python/Rust
toolchains, host/PMU identity, reference hashes, command contract, or budget
schema. The three inputs are committed but not hash-verified by the tool.

`tools/build_guard.py` proves only that the installed extension is newer than
Rust sources. It does not prove that it was built in release mode. The current
worktree also has concurrent Rust edits newer than the extension, so any fresh
measurement now would describe an older build and is deliberately rejected.

### P5 — exit status and completeness are not measured together

The wall-clock runner ignores the child return code. Neither path records
function count, returned-body count, structured refusals, output bytes, or an
output digest. A faster run caused by lost work, truncation, timeout, or empty
output could look like an improvement.

### P6 — memory and tail behavior are outside the gate

`tools/decompiler_profile.py` already captures peak RSS, but the performance
gate does not. Whole-process totals also cannot attribute one pathological
function. The large-function plan requires phase, timeout, RSS, MIR/SSA, and
output high-water marks, none of which the current three ordinary binaries
cover.

### P7 — Criterion is diagnostic, not authoritative

The ten targets have no stored baselines and no automated caller. Some skip
when gitignored fixture builds are absent. `decompile_pipeline` explicitly
recomposes only public stages and omits shipped context-sensitive analysis, so
its end-to-end number is a lower bound rather than the product entry point.
Criterion remains valuable for attribution after the shipped-entry gate turns
red.

### P8 — determinism is tested but not reported as a release artifact

`python/tests/test_decompile_determinism.py` is substantive. It does not yet
bind output identity, performance samples, build identity, and corpus hashes
into one retained report. Its ordinary sample rows may skip when files are
absent; the generated Rust flipper cells require toolchains. Determinism also
needs an explicit cold/warm and serial/concurrent distinction.

### P9 — the gate is never run automatically

P1–P8 are about a measurement that reports the wrong thing. P9 is about one
that never happens. `tools/perf_gate.py --check` appears in no workflow: the
suite CI added on 2026-08-31 runs `cargo test`, the Python suite and lint, and
nothing invokes the perf gate, the determinism lane, or the six behavioural
ratchets. All of them are `slow`-marked or manual, so the command a contributor
actually types cannot go red on a performance regression.

This is the same defect the estate has hit repeatedly, one level up: a gate
that exists, is correct, and is not wired to anything is indistinguishable from
one that does not exist. The fix is scheduling, not measurement — and it must
come with an "is it run" invariant, the way `fuzz-nightly.yml` asserts that its
targets execute rather than merely compile.

### P10 — a vacuous measurement is reported as a passing one

The Rust suite carries 20 sites shaped

```rust
Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
```

where a test that cannot find its compiler returns `ok` having asserted
nothing. The perf gate's `--characterize` path has the same exposure by
construction: a reference that fails to build is dropped (P2), and a host
without usable `perf` silently changes units (P3). Taken together, a perf run
on an under-provisioned machine can produce a green result from an empty
measurement.

The typed-result contract below is what closes this, but it must extend to the
*population*: not merely "each measurement is typed", but "the set of
measurements attempted is recorded, and a run that measured nothing is a
distinct result from a run that measured everything and found no regression".

## Contract: measurement is a typed result

Every reference produces exactly one of:

* `measured` — all required counters and completeness fields are valid;
* `unsupported_environment` — the required counter cannot run on this host;
* `missing_input` — a pinned asset is absent or has the wrong hash;
* `stale_or_wrong_build` — build identity is not the intended release build;
* `analysis_failed` — child exit, signal, timeout, malformed output, or no
  bodies;
* `incomplete` — expected functions/bodies/output contract changed; or
* `measurement_failed` — counter/report parsing failed.

Only `measured` participates in comparison. A required release lane passes
only when every required reference is `measured` and every ratchet passes.
Developer mode may report unsupported rows without pretending they passed.

## Baseline schema

Use a versioned, self-contained `bench/perf_baseline.json`:

```json
{
  "schema": "glaurung-perf-v2",
  "glaurung_commit": "full SHA",
  "native_sha256": "...",
  "build_profile": "release",
  "python": "...",
  "rustc": "...",
  "host": {"kernel": "...", "machine": "...", "cpu": "...", "pmu": "..."},
  "measurement": {"runs": 3, "primary": "instructions:u"},
  "references": {
    "stable-id": {
      "path": "...",
      "sha256": "...",
      "mode": "decompile_all/decbench",
      "expected_functions": 692,
      "expected_bodies": 692,
      "instructions": 84970000000,
      "max_rss_kib": 120000,
      "output_bytes": 1000000,
      "output_sha256": "..."
    }
  }
}
```

Raw per-run samples live in a retained result artifact. The baseline records
the accepted statistic and contract, not only the final pass/fail. Updating it
requires an explicit reason and a diff showing cost, completeness, and output
movement together.

## Reference ladder

The current Rust, Go, and small Clang examples cover language/size variation,
but the 16 KiB Clang input contradicts the tool's statement that all three are
large enough for startup to be negligible. Replace intuition with measured
startup share and use this minimum ladder:

| class | purpose | source |
|---|---|---|
| canary | startup and fixed overhead, not a tight instruction gate | committed source-built fixture |
| ordinary | normal analyst binary and full shipped orchestration | committed medium ELF |
| large/static | discovery and repeated function processing | committed Go or Rust binary |
| pathological function | region/dataflow/output scaling | first `@large` ladder tier |
| PE identity/import | distinct loader/discovery path | source-grounded PE family |
| hostile transform | bounded refusal or controlled body recovery | realistic-corpus subset |

Do not cross every compiler and architecture into the fast gate. Choose one
reference per distinct cost path. Run the broader size/shape/architecture
matrix in the scheduled characterization lane.

Each reference declares whether its tight counter is instructions, wall time,
RSS, or a phase-specific measure. The canary may have a loose wall threshold
while larger workloads use instructions.

## Metrics and ratchets

### Fast release gate

For every reference:

* child exits zero and is not signaled or timed out;
* input and native-extension hashes match the report;
* expected function/body/refusal counts match exactly;
* output digest is deterministic for the pinned build, or declared structural
  digest matches when benign rendering changes are accepted;
* retired instructions do not regress by more than 5%;
* peak RSS does not regress by more than 50%;
* output bytes do not grow by more than 25% without a reviewed quality reason;
* no faster result is accepted when completeness or output health declines.

Instruction counts use the minimum of three only after a calibration report
proves that choice stable on the release runner. Store all three samples and
their spread. Pin CPU affinity when supported and record whether affinity was
applied. Treat PMU multiplexing or `not counted` rows as measurement failure.

### Scheduled characterization

At least nightly or before a release candidate, record:

* wall-time median, p95, and maximum across repeated whole-binary runs;
* per-phase totals and worst-function phase times;
* cold versus warm session behavior;
* max RSS and output/MIR/SSA high-water marks;
* size-by-shape curves from the `@large` ladder;
* ELF x86-64/ARM64, PE32/PE32+, and controlled hostile families; and
* serial versus concurrent throughput without output divergence.

This lane characterizes tail behavior. Its acceptance budgets are pinned only
after a clean uncontended calibration, not invented in advance.

### Determinism matrix

For the fast subset, compare byte or canonical structural digests across:

1. repeated calls in one process;
2. fresh sequential processes with fixed environment and ASLR contract;
3. concurrent processes at the gate's supported job count;
4. cold and warm `ProgramSession` paths;
5. `decompile_at`, ordered `decompile_many`, and `decompile_all`; and
6. plain and DecBench render profiles where both are supported.

The same function identities, ordering, bodies/refusals, and output digests
must match. Timing is not required to match; the work and result are.

## Implementation sequence

### Increment A — make the existing tool fail closed

RED tests first for missing baseline, missing reference, hash mismatch, unit
mismatch, child failure, partial current results, malformed `perf` rows, and
zero bodies. GREEN changes make each a typed nonzero outcome in gate mode.
Keep an explicit `--characterize` mode for non-gating wall-clock fallback.

Acceptance: no execution path prints `passed` or exits zero without a complete
comparison, except deliberately selected characterization mode.

### Increment B — pin provenance and create the baseline

Add release-profile evidence rather than inferring it from timestamps. Hash
the extension and inputs, capture Git/toolchain/host/PMU data, and retain raw
samples. Wait for a clean, committed Rust tree; build the exact revision with
the documented release command; calibrate; then commit the first baseline.

Acceptance: rerunning the exact build/input tuple yields complete comparable
rows inside the calibrated spread. The present dirty/stale build is not valid
baseline material.

### Increment C — completeness, RSS, and output health

Use a structured worker response instead of discarding stdout. Record exit,
function/body/refusal counts, output bytes/digest, wall time, instructions, and
peak RSS. Reuse the profiler's Linux `ru_maxrss` implementation and schema
validation rather than creating a third memory collector.

Acceptance: deliberate early truncation, empty output, or one omitted body
fails even if instructions and wall time improve.

### Increment D — reference ladder and large-function bridge

Measure startup share and replace or reclassify the small Clang input. Add one
source-grounded PE reference and the smallest `@large` pathological tier once
those assets land. Every addition names its distinct cost path and runtime
cost.

Acceptance: the fast lane remains short enough to run locally while the
scheduled lane exposes size/shape curvature and worst-function phases.

### Increment E — unify determinism evidence

Keep the existing tests, add cold/warm session and ordered `decompile_many`
coverage, eliminate sample-absence skips for the committed fast subset, and
emit a retained determinism report using the same build/input identities as
performance.

Acceptance: a deliberate ordering perturbation or known hash-order leak turns
the gate red in at least one independent execution shape.

### Increment F — diagnostic Criterion workflow

Add a preflight listing missing fixture inputs and fail if a requested target
would benchmark zero cases. Document targeted Criterion baselines for the
phase named by the fast-gate regression. Do not put all ten noisy targets on
the mandatory fast path.

Acceptance: `cargo bench --bench decompile_pipeline` cannot appear successful
after silently running no fixture-backed cases, and its report remains labeled
as a partial pipeline lower bound.

### Increment G — run the gate, and prove that it ran

Nothing above matters if the gate is only ever invoked by hand. This increment
is about automation, and it is deliberately last because it should schedule a
gate that already fails closed rather than one that fails open.

* Add the perf gate and the determinism lane to a **scheduled** workflow, not
  per-push: performance measurement on a shared runner is noisy, and a
  ratchet that flaps gets disabled. Nightly, offset from the hour, alongside
  `fuzz-nightly.yml`.
* Emit a distinct non-pass status on a host that cannot measure instructions,
  so an unsupported runner is visibly *not evidence* rather than a pass (P3).
* Assert the invariant `fuzz-nightly.yml` already models: the job must prove
  its measurements ran. A run whose reference set is empty fails (P9/P10).
* Upload the typed result as an artifact, so a regression is diagnosable
  without re-running on the machine that saw it.
* Add the six behavioural ratchets — `baseline.json`,
  `arch_baseline.json`, `structural_baseline.json`, `defuse_baseline.json`,
  `stripped_divergences.json`, `tools/fitness_baseline.json` — to the same
  scheduled lane. They are all `slow`-marked, so no ordinary run reaches them,
  and on 2026-08-31 seven were red on pushed `master` for hours while every
  command anyone typed stayed green.

RED first: a test that asserts the workflow file names the gate, and a test
that a zero-reference result is a failure rather than a pass.

## TDD command sequence

Use focused pure tests for schema, comparison, `perf` parsing, and failure
states before invoking the expensive runner. Then, on a clean release build:

```bash
uv run pytest python/tests/test_perf_gate.py -xvs
uv run pytest python/tests/test_decompile_determinism.py -xvs
uv run python tools/build_guard.py
uv run python tools/perf_gate.py --characterize --json
uv run python tools/perf_gate.py --check --json
```

Coverage-side commands, for the R8 work this plan now depends on:

```bash
cargo test                      # the DEFAULT suite: 2,829 passing, 4 ignored
cargo test --features python-ext   # 2,951 — the 122 difference is python_bindings
uv run pytest python/tests/ -m "" -k census   # the slow ratchets, opt-in
```

After implementation, run the full project gates required by `CLAUDE.md`.
Baseline regeneration is a deliberate artifact change, never an automatic
side effect of an ordinary check.

## Completion evidence

R6 is complete only when:

1. the baseline exists with full build/input/host provenance;
2. all required references must be present, measured, complete, and comparable;
3. instructions, RSS, output size, body/refusal counts, and deterministic
   digests are jointly ratcheted;
4. the local release gate fails closed while unsupported CI environments emit
   a distinct non-pass result;
5. one deliberate performance regression and one deliberate completeness loss
   have each been shown to turn it red;
6. the scheduled lane records tail/phase/large-function evidence; and
7. the retained internal report binds performance and determinism to the exact
   Glaurung revision and asset hashes; and
8. the gate is **scheduled**, proves its own measurements ran, and a run that
   measured nothing is red rather than green (P9/P10).

Nothing in this plan publishes benchmark data, sends email, opens an issue, or
submits a result.
