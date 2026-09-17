# Solver ADR-034 — A scheduled shadow-split capture tier, so the next divergence is seen the week it appears

> **Kind:** decision · **Status:** maintained

**ADR status:** Implemented 2026-09-17 (`17ff0387`, capture `03a375c5`);
the weekly CI job is wired but has not yet had a scheduled run.
**Context:** Improvement-list item 7
([`development/improvement-list-2026-09-16.md`](../development/improvement-list-2026-09-16.md)):
[`solver-032`](solver-032-axeyum-pin-bump-and-shadow-corpus-prune.md) pruned
the shadow-split corpus to 107 z3-valid scripts with pinned verdicts and made
`tools/axeyum/split_verdicts.py` the gate, but nothing *produces* new captures.
The July corpus sat for two months with 735 exporter-defect scripts counted as
solver misses because capture was a one-off command in a README. A divergence
between Axeyum and z3 on a real driver query — a new capability gap, or worse a
decided disagreement — is seen only when somebody re-runs that command.

## Sizing (2026-09-17, host s4, load ~1.7)

One combined-shadow capture (`--release --example ioctlance --features
solver-z3,solver-axeyum`, `GLAURUNG_FAIR_SHADOW=1`,
`GLAURUNG_DUMP_SHADOW_SPLITS`, `IOCTLANCE_SOLVE_SECS=60`,
`IOCTLANCE_DEADLINE_SECS=600`, `IOCTLANCE_SOLVE_BUDGET=20000`,
`IOCTLANCE_MAX_ANALYZED_FUNCTIONS=100000`, default 250 ms check timeout) over
`sqfs-intel-DptfDevGen.sys`, Glaurung `3b3f2b4b`, Axeyum pin `8df853252`:

| measure | value |
|---|---|
| wall time | 59.5 s (`/usr/bin/time`; `[symbolic] 59.45 s`, 7 of 12 reachable functions analyzed, `runs=8 completed=7`) |
| checks (`[shadow-diff] queries=`) | 1,388 (agree 1,388, disagree 0) |
| split occurrences (`unknown-split=`) | 33, all z3-decided / Axeyum-unknown |
| distinct split scripts published | 15 (`shadow-splits.tsv`, all `sat`/`unknown`) |
| malformed (`malformed.tsv`) | 0 |
| max RSS | 147 MiB |
| release build, incremental over the solver-033 target | 53 s |

The wall time is the per-function ceiling, not the driver: warm Axeyum at this
pin pushes the root dispatch function into the 60 s budget
([`solver-033`](solver-033-six-cell-rerun-at-the-2026-09-16-pin.md)), so a
capture costs roughly `ceiling × dispatch roots` per driver and is bounded by
`IOCTLANCE_DEADLINE_SECS`. Four July drivers at 60 s are therefore minutes, not
hours, and the tier is a **weekly scheduled** job with a manual entry point,
not a per-push gate.

**Decision:** One command, `scripts/shadow-capture.sh`, is the tier, and
`.github/workflows/shadow-capture-weekly.yml` runs it every Tuesday at 03:29
UTC (and on dispatch). The command runs five stages in order and reports every
stage's finding before exiting: build the `solver-z3,solver-axeyum` `ioctlance`;
`tools/axeyum/shadow_capture.py` over a named driver list (default: ADR-0272's
four) at a named `--ceiling`, publishing through the existing in-process
atomic, content-addressed, z3-parse-checked publisher into the live
`tests/corpora/axeyum-qfbv/shadow-splits/<token>-<secs>s-<rev>/` and writing
the sidecars the pinned captures carry; `split_verdicts.py` (z3 classifies the
whole live root, new scripts enter `verdicts.tsv` as `unmeasured`); the Rust
replay of every row through the pinned `axeyum-solver`; and
`split_verdicts.py --axeyum-results` folding the replay back. The verdict
classes are fixed:

- a **new split z3 decides and Axeyum does not** is a finding, printed by name
  (`NEW:`) and never a failure -- a capability gap is what the tier exists to
  surface;
- a **both-decided disagreement** is a failure (soundness on one side), and
  the capture path now keeps its bytes under `<capture>/disagreements/` with
  a `disagreements.tsv` index -- until now the only trace of one was a
  counter in the process summary;
- a **malformed export** (a script the linked libz3 rejects) is a failure of
  the exporter ([`solver-016`](solver-016-enforce-declared-concat-widths.md)'s
  class), never a corpus entry;
- the **regression floor**: every row whose committed Axeyum column is decided
  must stay decided at the pinned solver, in both the Rust replay and
  `split_verdicts.py`; a committed-undecided row that comes to be decided is
  `PROMOTED` into the floor;
- a driver run that issued **zero checks**, or printed no `[shadow-diff]`
  summary, is not evidence and fails however it exited.

Each capture also records the nondecided backend's *stable reason class*
(`wall-timeout` / `resource-limit` / `other` / `error`) in
`nondecisions.tsv` -- beside the identity, never in it
([`solver-015`](solver-015-exact-shadow-unknown-split-corpus.md)) -- and the
tool histograms it. The CI job checks out LFS (drivers and corpus), installs
`libz3-dev` and `z3` from apt, uploads only the captures it created plus
`verdicts.tsv`, and **commits nothing**: a new capture is LFS bytes and a
finding, and a person lands it.

**Evidence:** The first run at head (`17ff0387`, pin `8df853252`, host s4 at
load 8-20 with other lanes building): 7 min 50 s for the four drivers,
41,493 checks, **0 disagreements, 0 malformed**, 55 split occurrences,
**27 distinct new scripts** -- DptfDevGen 21 (of 1,357 checks, 47
occurrences), IntcSST 5 (8,030 / 7), SurfacePen 1 (15,167 / 1, the one
z3-undecided split), vwififlt none (16,939 checks). Reason histogram:
`axeyum:wall-timeout` 26, `z3:wall-timeout` 1 -- every split is the 250 ms
per-check cap, none is a translation error. The replay (debug build, 30 s
wall) held all 107 floor rows and decided all 27 new scripts like z3 in
15-136 ms one-shot; the fold promoted them and the floor is now **134**
(`03a375c5`). Controls: the tier's eight tests drive the tool with a scripted
`ioctlance` stand-in (new row -> exit 0 with the row named; disagreement,
malformed, silent run, crash -> exit 1; no split -> no directory; existing
directory -> refused); deleting the floor guard in `split_verdicts.py` kills
exactly its two floor tests with the other fourteen green; the Rust
classification is a unit-tested function; four unit tests cover the new
publisher paths. The shell script was exercised end to end through stage 3
on a throwaway token (58.9 s, 1,388 checks, 20 splits, `verdicts.tsv`
restored afterwards).

**Consequences:** At this pin the "capability gaps" the tier surfaces are not
one-shot capability at all: they are warm Axeyum's session-age latency
(solver-033) crossing the 250 ms cap, which is why a second DptfDevGen
capture at the same binary shared only 8 of its 20 splits with the first.
The population is load-sensitive, so a week with more new rows is not by
itself worse; a week with a `DISAGREEMENT`, a `MALFORMED` or a `REGRESSION`
line is. Every new row is still a real driver query that joins the floor
once decided, so the floor grows with use. The CI runner's z3 (4.8.x on
ubuntu-24.04) is older than the 4.13.3 the committed `verdicts.tsv` was
classified with; the file records which, and the runner's copy is uploaded,
not committed. `manifest-v1.json` is not generated for new captures: it is
Axeyum's consumer manifest and byte identity belongs to the consumer.
`benches/ir_dataflow.rs` still breaks every `cargo check --all-targets` lane
of `scripts/feature-build-gate.sh` on master, unchanged by this record.

**Alternatives rejected:** a per-push gate (minutes per driver plus two solver
builds on every push, for a population that moves with load); failing on a
new split (turns the finding the tier exists to surface into a reason to
stop running it); committing from CI (LFS bytes and a finding land without a
reader); capturing only disagreements (a split is the population a verdict
agreement count is blind to, solver-015); recording the nondecision reason in
the split identity (an error string in identity was rejected in solver-015);
raising `GLAURUNG_CHECK_TIMEOUT_MS` so warm timeouts stop appearing (the
production cap is 250 ms; the tier measures the configuration that ships).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
