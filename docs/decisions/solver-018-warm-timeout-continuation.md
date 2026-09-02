# Solver ADR-018 — Opt-in same-session warm timeout continuation

> **Kind:** decision · **Status:** maintained

**ADR status:** Candidate retained; default deferred pending a fixed-work/repeated
gate.
**Context:** ADR-017's fresh cold retry recovers only 4/15 timeout occurrences
and raises RSS 10.46% because it reconstructs the complete snapshot. Axeyum's
incremental BatSat adapter retains the clause database after an interrupted
solve and installs a fresh deadline on each `check`, so one additional call on
the synchronized path may continue useful search without another arena/AIG/CNF
copy.
**Decision:** Add `GLAURUNG_AXEYUM_WARM_TIMEOUT_CONTINUE=1` as an opt-in
direct-lineage policy. When the first retained check returns `Unknown`, issue
exactly one more check on the same solver under a fresh 250 ms deadline before
releasing its worker-local borrow. Reuse already-translated temporary
assumptions; do not duplicate source translation or root accounting. Return a
recovered SAT/UNSAT result; otherwise preserve the original `Unknown`, including
on continuation error. Export continuations/recoveries/unknowns/errors and keep
the cold-retry flag independently off during measurement.
**Acceptance gate:** Require the exact counter partition, zero errors,
SAT/UNSAT disagreements, resets, or replay failures. Tcpip must recover more
than ADR-017's four occurrences without breaching 3% Axeyum time or 5% RSS;
dxgkrnl must perform zero continuations and preserve exact traffic. Any query or
finding drift makes the run functionality evidence only and requires repeated
gate integration before default consideration.
**Consequences:** The switch is explicit/off. A successful single process is
not a default decision; it only selects repeated policy comparison and profile
schema work. A failed result closes blind extra-time retries and redirects the
nine-formula pack to SAT-core attribution/prediction.
**Alternatives rejected:** another fresh solver repeats ADR-017's memory cost;
raising the common timeout taxes every check; unbounded continuation violates
the resource contract; re-translating temporary assumptions would corrupt the
entry-work accounting.

**Evidence:** The 60-second tcpip candidate performs 14 continuations = 6
recoveries + 8 repeated unknowns + 0 errors over 71,842 checks, with zero
SAT/UNSAT disagreements or warm resets. Axeyum nondecisions fall 15→8 while
time rises about 1.1% and RSS falls slightly against the post-fix reference.
The dxgkrnl control performs zero continuations and has zero Axeyum
nondecisions/disagreements, although both wall-time-bounded runs have traffic
drift and therefore are functionality evidence only.

A 600-second tcpip control/candidate pair removes the solver-budget truncation
but still reaches the 400-second analysis deadline. The candidate performs 14
continuations = 5 recoveries + 9 repeated unknowns + 0 errors. Axeyum
nondecisions fall 14→9; Axeyum time rises 204,294.1→208,331.4 ms (+1.98%) and
RSS rises 449,224→449,376 KiB (+0.034%), within the 3%/5% alarms. It executes
70,581 rather than 70,562 queries and reports 782 rather than 780 unique
high-confidence findings. All 780 control findings remain; the two
candidate-only findings are null dereferences in `sub_1c00738a0`. This is
consistent with deadline-limited traversal reaching two additional sinks, but
it is not an exact-output causal comparison. Keep the candidate off by default
until a fixed-work or repeated gate can distinguish policy effect from traversal
timing and require exact findings when the workload is identical.

**Fixed-work follow-up:** `IOCTLANCE_MAX_ANALYZED_FUNCTIONS=N` now stops before
opening reachable function `N+1` and reports `WORK-LIMIT-HIT`. The next tcpip
pair uses `N=156` with a generous wall deadline as a safety backstop. Admission
requires both processes to hit the work limit, not the deadline, and to preserve
exact query traffic and finding hashes before resource deltas are scored.

Both fixed-work processes hit 156/338 functions and never hit the 3,600-second
safety deadline, but the gate still rejects the live comparison. Control runs
70,592 queries with 47 Z3 / 11 Axeyum nondecisions and 782 findings; continuation
runs 70,768 queries with 46 Z3 / 8 Axeyum nondecisions and 783 findings. Their
finding sets have 781 shared rows, one control-only double fetch, and two
candidate-only read/null-deref rows. The candidate's 11 continuations partition
as 3 recoveries + 8 repeated unknowns + 0 errors. Axeyum time changes
133,279.7→135,233.6 ms (+1.47%) and RSS 440,280→441,088 KiB (+0.18%), inside
the alarms, with zero SAT/UNSAT disagreements, resets, or replay failures.

The function boundary removes global deadline drift but cannot remove
authoritative Z3 timeout steering: 47 versus 46 bounded Z3 nondecisions change
the worklist within the identical function prefix. Do not repeat live
exploration as if it were exact. Capture one ordered authoritative query stream
and replay both timeout policies over those exact occurrences; continuation
remains explicit/off until that gate exists.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
