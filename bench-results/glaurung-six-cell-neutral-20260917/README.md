# Glaurung four-cell rerun at the 2026-09-16 Axeyum pin

This directory began as a **zero-result-row registration** (`registration.json`,
committed before any timing row existed). The protocol is ADR-0272's (Axeyum
`docs/research/09-decisions/adr-0272-preregister-six-cell-neutral-warm-regime.md`),
executed by `run-glaurung-four-cell-20260917.py` — the July runner with exactly
the producer revision, the executable hash, the validator path, and the
docstring changed. The pins that differ from July and why are in
[`docs/development/six-cell-rerun-2026-09-17.md`](../../docs/development/six-cell-rerun-2026-09-17.md);
the decision this feeds is
[`solver-033`](../../docs/decisions/solver-033-six-cell-rerun-at-the-2026-09-16-pin.md).

- Producer: Glaurung `b1f420ab1e406ec2479509f65143211191428be0` (master
  `11b68faf` + the preflight alias fix), Axeyum pin `8df853252`,
  `default-features = false, features = ["qfbv"]`.
- Cells: four — `{Z3, Axeyum} × {cold, warm}`. No Bitwuzla (see the note).
- Executable SHA-256
  `4f3e5c376ef2da45ec0fc904b94874931ba3d5ff717da1e4482ca46c3a055f3f`; runner
  SHA-256 `1a85b88ad7c78884291b35765191b08bcf5f0e5305dd930a14bf37c41c8ffbb7`.
- Host s4, i5-12600K (July's CPU model), logical CPU 2, 2026-09-17
  05:37–06:26 UTC. One-minute load sampled every 30 s during the run: min 2.4,
  median 8.2, max 16.3 — other lanes were building. See `logs/load-samples.tsv`.

## What happened

All 20 fresh processes exited 0 and each published one trace that
`tools/axeyum/validate_ordered_trace.py` accepted. Over the five repetitions
there are 208,359 ordered check occurrences and 833,436 measured solver cells.
**Operational errors: 0. Decided disagreements: 0.** Unknowns: 52 cells — 51
warm-Axeyum cells on DptfDevGen that hit the frozen 250 ms warm safety cap
(`GLAURUNG_CHECK_TIMEOUT_MS`), and 1 cold-Z3 cell on SurfacePen. Every other
cell decided, and every decided cell agreed with every other on the same check.

**The preregistered analyzer refused all four drivers** with
`fixed-work check identity drift` (its stderr and exit status are kept per
driver as `preregistered-analyzer.stderr` / `.exit`). The cause is in every
process's `[exploration-limits]` line: `deadline=1`. One dispatch root per
driver runs into the frozen `IOCTLANCE_SOLVE_SECS=60` budget, so the point at
which exploration is cut depends on wall time, and the five repetitions do
not perform identical work (DptfDevGen: 1,365 / 1,142 / 1,380 / 1,272 / 1,333
checks; July: 603 in all five). Under ADR-0272 a gate failure is a result:
**every driver is inconclusive under this protocol.** This directory contains
no `report.json`.

Why the budget is hit now and was not in July: the warm Axeyum cell. Per
process (repetition 1, seconds summed over all checks):

| Driver | Z3 cold | Z3 warm | Axeyum cold | Axeyum warm |
|---|---:|---:|---:|---:|
| DptfDevGen | 2.3 | 0.2 | 2.1 | **37.6** |
| vwififlt | 21.2 | 3.7 | 31.9 | **54.3** |
| IntcSST | 23.2 | 2.6 | 14.8 | **36.8** |
| SurfacePen | 29.1 | 2.9 | 26.4 | **40.7** |

Retained topology cuts Z3's total by 7–13× and *raises* Axeyum's on all four
drivers. The mechanism is visible in the per-check latencies: warm Axeyum
grows with the age of the retained session. On DptfDevGen (rep 1), p90 warm
Axeyum latency is 0.1 ms in the first 50 checks after a session is created,
2.6 ms at 50–100, 22.7 ms at 250–300, and 178 ms past 500 — while the same
queries solved cold take ~2 ms at p50. On the other three drivers the growth
is milder but the same shape: warm p90 rises from 0.1–0.4 ms in a session's
first 100 checks to 6.9 / 7.7 / 14.8 ms past 600 (vwififlt / IntcSST /
SurfacePen), where cold p90 on the same queries is 4.6 / 5.1 / 14.3 ms — the
retained session's advantage is gone by then, and most checks sit past that
point (9,115 of 17,411 on vwififlt). July's pin had a warm Axeyum p99 of
0.4–2.4 ms on every driver; this pin's is 73–173 ms.

## Exploratory ratios over the common prefix (NOT preregistered)

Because the analyzer refuses, `common-prefix-analysis.py` applies the
analyzer's own functions and seeds (imported, not reimplemented) to the prefix
of check occurrences whose identity is equal in all five repetitions —
identical work, before the deadline cut. This is labelled exploratory
everywhere it appears. It is also **optimistic for Axeyum**: the prefix is the
young part of every retained session, where the degradation above is
smallest. Ratios are `numerator_nanos/denominator_nanos`; greater than one
favours Axeyum. July's column is the six-cell result at the old pin.

| Driver | Prefix checks | Cold Z3/Axeyum, July → now | Warm Z3/Axeyum, July → now |
|---|---:|---|---|
| DptfDevGen | 983 of 1,142–1,380 | 1.1577 [1.0492, 1.2774] → 1.1768 [1.1260, 1.2303] | 0.8448 [0.7368, 0.9692] → **0.1678 [0.1435, 0.1966]** |
| vwififlt | 1,842 of 17,011–17,411 | 0.6952 [0.6816, 0.7090] → 0.6484 [0.6301, 0.6670] | 1.0523 [1.0190, 1.0879] → **0.0905 [0.0808, 0.1011]** |
| IntcSST | 3,941 of 7,903–8,030 | 2.7865 [2.6976, 2.8772] → 1.4130 [1.3726, 1.4550] | 2.2321 [2.1243, 2.3408] → **0.3055 [0.2838, 0.3293]** |
| SurfacePen | 12,116 of 15,032–15,273 | 2.5811 [2.5237, 2.6400] → 1.9239 [1.8814, 1.9664] | 2.2819 [2.2213, 2.3452] → **1.2157 [1.1742, 1.2575]** |

Within-solver reuse over the same prefix: Z3 cold/warm 8.6–13.0× (July
5.6–8.2×); Axeyum cold/warm 1.53 / 1.82 / 2.07 / 5.44× (July 5.35–8.48×).
Per-process CVs of the warm pair are 3.9 % (DptfDevGen, above the 3 % gate)
and 0.6–1.2 % on the other three. An independent same-input rerun of the
exploratory analysis reproduced every `common-prefix-exploratory.json`
byte-for-byte.

Reading: cold Axeyum is where July left it — faster than cold Z3 on three
drivers, slower on vwififlt. Warm Axeyum has regressed from "beats warm Z3 on
three of four" to "6–11× slower than warm Z3 on three of four, 1.2× faster on
SurfacePen", and the loss grows with session age until the 250 ms cap.

## Files

- `registration.json` — the zero-row registration, changed pins listed
  against ADR-0272's.
- `result-summary.json` — populations, the three zero counts, per-cell sums
  and tails, the exploratory ratios, July's numbers beside them.
- `<driver>/preregistered-analyzer.{stderr,exit}` — the refusal, verbatim.
- `<driver>/common-prefix-exploratory.json` — the labelled secondary analysis.
- `logs/campaign.json` (SHA-256 in `result-summary.json`), per-process
  `stderr.log`, `launch.log`, `load-samples.tsv`.
- Raw traces (3.8 GiB) are outside git at `/data0/axeyum/scratch/sixcell/campaign`
  on s4.
