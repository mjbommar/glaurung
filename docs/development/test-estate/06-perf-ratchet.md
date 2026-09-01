# Phase 6 — A performance number something compares against

## The problem

Ten criterion targets exist (built this session), **no baseline is recorded
for any of them, and nothing anywhere invokes `cargo bench`** — `CLAUDE.md`
already says a change that doubles decompile time ships green, and the
inventory confirmed it. `bench/harness.py` records `decompile_ms` and never
compares it. This phase adds the missing half: a recorded number and a gate
that reads it.

## 6.1 Instructions, not seconds

The primary ratchet counts **instructions retired**, not wall-clock.
Rationale, all learned on this box:

* Wall-clock on this machine is noisy under load — the arch gate has recorded
  false failures for exactly that reason (memory: baseline regen needs a
  quiet machine). Instruction counts are stable to well under 1% across load.
* `perf` works here once the sysctl is set (passwordless sudo:
  `sudo sysctl -w kernel.perf_event_paranoid=1`).
* The number must be measured on a **release** build; the debug/release
  profiles disagree completely (allocator 6.5% vs 26.2%). `tools/build_guard.py`
  runs first, and the gate refuses a debug `.so`.

## 6.2 `tools/perf_gate.py`

* Reference set: 5 binaries spanning the size ladder — one small fixture
  object, one mid (`bash`-class), one large — chosen once and pinned by
  hash. Not DecBench material (held out), not host binaries that differ per
  machine: use committed/canary fixtures plus `samples/` binaries.
* Measure `perf stat -e instructions:u -x,` over
  `glaurung <decompile-entrypoint>` per reference binary, median of 3.
* Baseline: `bench/perf_baseline.json` — instructions per reference binary,
  plus the commit and `.so` hash it was recorded at.
* Compare: fail at >5% instructions regression on any reference (instruction
  counts justify a tight threshold; wall-clock could not), with the same
  `--accept-regression` escape hatch and required-reason field the def-use
  census uses. Improvements auto-tighten (ratchet), same as fitness.
* Fallback when `perf` is unavailable (CI runners): wall-clock with a slack
  threshold (25%) and a warning that it is the weak form.

## 6.3 Wire it

* `scripts/decbench-local-gate.sh` gains the perf gate as a lane — seconds of
  runtime, so it goes in lanes 1–3, not behind `--decbench`.
* Document in `CLAUDE.md`'s gate list once it exists (one line; the bullet
  about benches gating nothing gets updated rather than deleted, per the
  correction style used there).

## 6.4 Criterion baselines (second tier, optional)

The criterion targets stay what they are — diagnosis tools for *where* a
regression lives once 6.2 says *that* one exists. Record
`cargo bench -- --save-baseline main` on a quiet machine and document
`critcmp` usage in `docs/development/decompiler-testing.md`; do **not** gate
on them (criterion wall-clock across 10 targets is exactly the noisy
multi-minute check that gets skipped, and 6.2 already covers the
gate role).

## 6.5 Memory ceiling (cheap add-on)

While in `perf_gate.py`: record `max_rss` per reference binary
(`/usr/bin/time -v` or `getrusage`) with a loose threshold (50%). Allocation
churn was this codebase's biggest real perf bug (47.5% of a profile in
libc malloc, invisible to self-time), and RSS is the cheap canary for its
return.

## Acceptance

* `bench/perf_baseline.json` exists with pinned references and recorded
  instruction counts.
* Deliberately pessimizing one pass (e.g. re-enabling a known-quadratic
  path) turns the gate red. Verify once, by doing it.
* The gate runs inside `decbench-local-gate.sh` lanes 1–3.

## Effort

One day. The design is small on purpose — the entire failure mode being
fixed is that the previous, larger design (10 criterion targets) produced no
gate.
