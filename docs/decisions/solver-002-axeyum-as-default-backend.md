# Solver ADR-002 — Axeyum is the default backend; z3 stays an opt-in perf backend

> **Kind:** decision · **Status:** maintained

> **Superseded by [solver-037](solver-037-axeyum-is-always-authoritative.md).**
> The historical implementation never made Axeyum a default feature: it used
> `default = ["triage-core"]` and selected among explicitly enabled backends.
> The perf gate this ADR made the default conditional on never closed; see
> [solver-014](solver-014-source-prefix-production-win.md) and
> [solver-021](solver-021-defer-wider-direct-delta-default.md).
>
> **Re-measured 2026-09-17 at the `8df853252` pin
> ([solver-033](solver-033-six-cell-rerun-at-the-2026-09-16-pin.md)):** the
> gate is not met. Cold Axeyum is at parity or faster than cold Z3 on three of
> four drivers (Z3/Axeyum 1.18 / 0.65 / 1.41 / 1.92), but in the production
> topology — retained sessions — warm Axeyum is 6–11× slower than warm Z3 on
> three of four (0.17 / 0.09 / 0.31 / 1.22; July was 0.84 / 1.05 / 2.23 / 2.28)
> and its per-check latency grows with session age. Those ratios are
> exploratory: the preregistered analyzer refused all four drivers because the
> warm cells pushed every process into the frozen 60 s solve budget and the
> work was no longer fixed. The default stays as it is.
>
> **Re-measured 2026-09-17 at the `11b895a35` pin
> ([solver-035](solver-035-warm-fix-repin-and-model-preference.md)):** the
> session-age growth is fixed upstream (Axeyum ADR-2142) and three of the
> four drivers no longer hit the 60 s budget, so ADR-0272's fixed-work
> campaign can be re-registered; the gate is still **not met** — on
> DptfDevGen's historical session measurement remains recorded below, but
> Axeyum is now the default and sole authoritative SAT/SMT backend; builds
> without it abstain. The cascade and performance rationale below describe
> historical policy rather than the current authority boundary.

**ADR status:** Proposed.
**Context:** Axeyum is pure-Rust, wheel-shippable, proof-carrying, but not
yet perf-parity with z3. z3 is fast but links libz3 (C/C++) and is kept
out of the wheel.
**Decision:** Make `solver-axeyum` a **default feature**; keep `solver-z3`
**opt-in**. Priority cascade in `solve()`:
`solver-z3` (if explicitly enabled) -> `solver-axeyum` (default) -> pipe.
**Consequences:** The shipped/default build gets a real pure-Rust
in-process solver (G1). Users who want maximum speed opt into z3. No
silent provider swap - the choice is an explicit build feature.
**Alternatives rejected:** replacing z3 outright (loses the perf escape
hatch while axeyum's perf gate is open, NG1); keeping z3 default (defeats
the pure-Rust/shippability goal).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
