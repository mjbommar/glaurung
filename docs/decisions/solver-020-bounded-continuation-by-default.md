# Solver ADR-020 — Default bounded continuation inside direct-delta sessions

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** ADR-018 retained one same-session check after a warm `Unknown` as
an explicit candidate, and ADR-019 made the real source-prefix/direct-delta/
serial-lease topology exactly replayable. The remaining admission gate required
repeated fixed-work control/candidate processes with independent public replay,
exact finding identity, implementation identity, and the existing correctness,
time, RSS, and variance alarms.
**Decision:** When Glaurung's separately opt-in direct-delta route is active,
enable exactly one same-session continuation after a warm `Unknown` by default.
`GLAURUNG_AXEYUM_WARM_TIMEOUT_CONTINUE=0`, `off`, or `false` remains an explicit
off control; an unrecognized value fails closed to off. Keep fresh cold retry
off and preserve the original `Unknown` after a repeated nondecision or error.
This decision does not default-enable `GLAURUNG_AXEYUM_DIRECT_DELTA` and does not
change one-shot, snapshot, or ordinary Axeyum solver construction.
**Evidence:** Clean Glaurung `33191ac` produced a complete 156/338-function
tcpip run under 4 GiB: 326,364 ordered events, 71,136 checks, 50,687 unique
queries, 10,515 public assertions and native packs, 15,501 owner releases,
7,663 owner shares, 27,940 model reads, 794 finding rows, zero shadow
disagreements, and zero warm resets. The producer validator accepted the exact
artifact. Axeyum `ddb368b7` independently validated all unique queries and
model reads; its report SHA-256 is
`3a9a6b45b2b86148c197b4f20918b65093f249fcbf523a4347d91d63b72b3387`.

Three interleaved fresh-process control/candidate pairs then replayed the same
70,656 synchronized warm checks plus 480 assertion-cap fallbacks through
Glaurung `c1a5635`. Every report matched 13,933 exact reuses, 7,067,382 prefix
assertions, 42,908 additions, 37,436 pops, the complete owner lifecycle, the
finding hash, both source revisions, and replay executable hash. All runs had
zero opposite decisions, synchronization mismatches, errors, resets, cache
replay failures, or terminal paths/owners/references. Candidates performed 29
continuations = 18 recovered decisions + 11 honest `Unknown`s + 0 errors.
Candidate/control Axeyum p50 was 100.166/98.175 seconds (+2.027%); p50 maximum
RSS was 360,484/356,840 KiB (+1.021%); Axeyum timing CV was 0.365%/0.192%.
All are inside the 3% time, 5% RSS, and 3% variance alarms. The fail-closed
comparison artifact SHA-256 is
`0f27afce0b691e977ebf9aa66b67f4bb8744e1c0cc3eb90c2f832b196d1adbc3`.
**Consequences:** Direct-delta users gain bounded decided-rate recovery without
another arena/AIG/CNF copy. Residual timeouts remain first-class `Unknown`s and
the continuation counters remain visible. Preserve explicit on/off controls in
future gates. Direct-delta product admission, wider-driver coverage, and the
zero-query `win32k` frontend gap remain separate work.
**Alternatives rejected:** enabling direct delta from this single-driver replay
would conflate two policies and bypass ADR-0205's wider admission; raising the
common timeout taxes every check; a fresh solver repeats ADR-017's RSS failure;
unbounded or multi-retry continuation violates the measured resource contract.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
