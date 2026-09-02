# Solver ADR-010 — Adapt lineage capacity from sustained live-path pressure

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted as the Axeyum explorer default.
**Context:** ADR-008's second-check policy saves memory but fails the 3% time
alarm because repeated paths pay cold work before rebuilding retained state.
The corrected SurfacePen ordered trace shows that purpose alone is not enough:
address/finding/overflow admission covers 2,285/2,551 checks and retains only
20 singleton paths, but 117 branch-first paths later require warm state. A real
purpose-policy prototype is 1.140 seconds / 72,868 KiB, essentially the same
time as rejected auto and slower than fixed lineage. It was removed. Fixed cap
2 passes SurfacePen but regresses NETwtw10 18.2%, so a universal small cap is
also rejected.
**Decision:** Use pressure-adaptive lineage when
`GLAURUNG_AXEYUM_WARM_REUSE` is unset. It uses the
existing path-owned lineage solver without another query representation or
purpose field. Capacity starts at `min(configured_cap, 2)`. Each failed
low-cap reservation increments a process-wide atomic pressure counter. At 128
events, capacity expands once to the configured hard cap (currently 9); the
triggering check retries reservation immediately. Exact pressure, expansion,
initial-cap, and threshold telemetry enters the fail-closed runner contract.
`off`, `false`, or `0` selects the one-shot override; fixed `lineage` remains
the benchmark control, and explicit `auto`/`snapshot` remain diagnostic modes.
**Consequences:** Low-pressure streams can retain fewer concurrent arenas while
high-pressure streams pay at most 127 initial cap fallbacks before recovering
the proven envelope. Solver/query/model/proof semantics are unchanged: every
warm SAT model is still replayed against original terms, every fallback is the
existing one-shot path, siblings never share mutable state, and the configured
hard cap remains atomic. Single clean calibrations are encouraging but do not
authorize a default: SurfacePen is 1.095 seconds / 81,212 KiB versus a same-
binary cap-9 control at 1.079 seconds / 83,220 KiB; NETwtw10 expands once and
is 18.543 seconds / 261,648 KiB versus 18.740 seconds / 258,764 KiB. All 30,907
checks agree with Z3 with zero unknown splits or resets. Repeat both families
through the versioned runner before deciding GQ9.
**Alternatives rejected:** purpose admission is dominated by cap 1 and still
fails time; fixed cap 1 fails SurfacePen time; fixed cap 2 fails NETwtw10 time;
cap 3 restores SurfacePen time but provides no RSS improvement; formula-shape
analysis would repeat GQ4's paid-analysis failure at the wrong layer.

**Repeated gate:** The clean three-process-per-family artifact at Glaurung
`95c43cb` and Axeyum `f91fb232` repeats exact adaptive topology and all 92,721
agreements. SurfacePen averages 1.085 seconds / 79,424 KiB; NETwtw10 averages
18.558 seconds / 255,364 KiB. The explicit lineage→adaptive comparator reports
Surface Axeyum/ratio/RSS changes of +2.07%/+2.28%/-3.65% and NETwtw10 changes
of -1.03%/-0.89%/-0.88%; Z3 drift is -0.20%/-0.14%. Every 3%/3%/5% plus 2%
alarm passes. The 8,965-byte artifact SHA-256 is
`0255d0ed2a0c5bc078e478cb951561d4de1460c11333a646f3e150b15281e716`.
This accepts adaptive as the GQ9 production admission policy and the Axeyum
explorer default. The default parser and explicit one-shot override have direct
unit coverage. This downstream scheduling choice does not alter Axeyum's
framework-level solver defaults.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
