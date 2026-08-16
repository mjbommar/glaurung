# `docs/design/` — what to read, and what to write to

This directory holds 30+ documents. Three of them are live; the rest are
evidence. Without this file there is no way to tell which is which, and a reader
who opens the wrong one gets a plan that was superseded weeks ago.

## Track work here

| file | role |
|---|---|
| **[decompiler-roadmap.md](decompiler-roadmap.md)** | **The plan.** The single tracker. Every checkbox carries evidence: `[x]` done with a commit and a measurement, `[~]` partial with a stated boundary, `[ ]` open with a named blocker. |
| **decompiler-roadmap-diary-YYYY-MM-DD.md** | **The log.** One entry per increment, RED → GREEN → VERIFY, with the command output that justifies each claim. Newest file is the active one. |

Nothing else in this directory is a work queue. If a document here proposes work,
it is either already reflected in the roadmap or it is history.

### Reading the roadmap

Start with "How to use this roadmap". Four things there are load-bearing and easy
to miss:

- **Two tracks.** Correctness (fixture cells move) and architecture (a boundary
  holds, zero cells expected) are judged by different standards. Mixing them is
  what made the architecture work look stalled when it was simply losing every
  scheduling contest.
- **The Phase blocks are a VIEW of the EPIC blocks**, not additional work. The
  193 checkboxes are roughly 70 distinct items. A percentage-complete figure over
  them is bookkeeping, not evidence.
- **`[x]` requires a production caller.** "Implemented" and "connected" are
  different claims, and conflating them has cost real time here.
- **Capability census before a modelling theory.** Check whether a capability
  exists at all before attributing failures to a deep gap. Three whole missing
  ISA categories were found this way in three days.

Appendix A (DecBench and evaluation) is explicitly **on demand only**. An
untouched box there is not a defect.

## Rolling the diary

A diary file covers a working period, not all time. Roll it when it passes a few
thousand lines: start `decompiler-roadmap-diary-<today>.md`, link back to the
previous one, and keep entry numbering continuous across files so a reference to
"Entry 34" stays unambiguous.

## Everything else is evidence

The roadmap cites these where a claim needs backing. They are historical records
of what was measured and decided, not instructions. Treat any score, revision, or
plan inside them as historical unless the roadmap says otherwise.

Useful ones to know about:

- `dormant-transforms-2026-08-12.md` — carries a correction worth reading before
  trusting any table in this directory: its original attempt/fire counts were
  never produced by any run, because the instrumentation did not exist at that
  commit. Re-measured numbers are appended.
- `function-facts-and-call-facts-2026-08-15.md` — the design note for the most
  duplicated open item in the plan.
- `defect-register-2026-08-05.md`, `armv7-real-defects-2026-08-05.md` — defect
  archaeology with root causes.
- `decbench-*` — evaluation-harness history. Pairs with Appendix A.

## The habit that keeps this honest

A number in a document is not a measurement. Two tables in this directory turned
out never to have been produced by any run, and both shaped later decisions.
Write the command next to the number.
