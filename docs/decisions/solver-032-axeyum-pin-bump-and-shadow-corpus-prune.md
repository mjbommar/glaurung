# Solver ADR-032 — Move the Axeyum pin to head, and keep only z3-parsed scripts in the shadow-split corpus

> **Kind:** decision · **Status:** maintained

**ADR status:** Implemented 2026-09-16; the six-cell timing rerun that decides
`solver-002` is a separate lane and has not run.
**Context:** The improvement list of 2026-09-16
([`development/improvement-list-2026-09-16.md`](../development/improvement-list-2026-09-16.md))
measured the integration against Axeyum head and found it dormant, not
broken: `Cargo.toml` pinned `c38a9515e` (2026-07-20), 11,607 commits behind
`origin/main`, and nobody had re-checked since July. The same measurement
found that `tests/corpora/axeyum-qfbv/shadow-splits/` held 842 scripts of
which most were the pre-[`solver-016`](solver-016-enforce-declared-concat-widths.md)
export shape — a 1-bit `setcc` result declared as an 8-bit `concat` half,
making the term 57 bits wide and the next `extract 63 8` out of range — which
z3's own parser rejects, so every sweep that counted files had been counting
an exporter bug as Axeyum misses.
**Decision:** Three things, on one branch.
1. *Bump the pin.* `axeyum-solver` and `axeyum-ir` move to
   `8df853252cdf49c9a27ba71c6ce62fdd1c485dfc` (Axeyum `origin/main`,
   2026-09-16), keeping `default-features = false, features = ["qfbv"]`
   ([`solver-025`](solver-025-explicit-qfbv-profile.md)). No adapter code
   changed: `cargo check --features solver-axeyum` and
   `--features solver-axeyum,solver-z3` compile with 0 errors, and the
   `IncrementalBvSolver::stats()` the list called new predates the old pin
   (Axeyum `c8ffb43d8`, 2026-07-15) and was already consumed by
   `axeyum_backend/profile.rs`. The lock file drops BatSat (Axeyum retired it
   for its own SAT core) and gains `sha2`.
2. *Prune the corpus and pin its verdicts.* Every script z3 rejects moves to
   `tests/corpora/axeyum-qfbv/malformed-exports-pre-solver-016/<capture>/`
   with its original index rows, a `malformed.tsv` of z3's error text, and a
   README — kept, because `solver-016` names these bytes as the reproducer,
   but under a name no sweep can mistake for a solver result. The valid
   scripts stay in their captures with regenerated sidecars, and
   `shadow-splits/verdicts.tsv` records, per script, z3's verdict and the
   pinned Axeyum's. `tools/axeyum/split_verdicts.py` writes that file and is
   the gate: exit 1 on any malformed or undecided script or any Axeyum/z3
   opposition; `tests/axeyum_shadow_split_verdicts.rs` (behind
   `solver-axeyum-text`, the only profile with an SMT-LIB parser) replays
   every row through the pinned crate and fails on inventory drift, a
   nondecision, or a verdict that differs from z3's.
3. *Parse with z3 at capture time.* In a `solver-z3` build,
   `GLAURUNG_DUMP_SHADOW_SPLITS` parses the exact bytes with the linked libz3
   (`z3-sys`: `Z3_solver_from_string` then `Z3_get_error_msg`; the `z3` crate
   installs a null error handler and hides its context, so it cannot report
   the error) before indexing. A script z3 rejects is published under
   `malformed/` and indexed in `malformed.tsv` with the error text, never in
   `shadow-splits.tsv`. Identity stays the content hash
   ([`solver-015`](solver-015-exact-shadow-unknown-split-corpus.md)); the
   error text is recorded beside it, not in it.
**Evidence:** z3 4.13.3 at `-T:10` over all 842 scripts: 735 malformed (733
`invalid extract application` in `tcpip-60s-a6a5cc0`, 2 `(_ BitVec 57)` sort
mismatches in `dxgkrnl-60s-a6a5cc0`) — exactly the 735 rows whose Axeyum
class was `error` — and 107 valid (94 sat, 13 unsat); both post-fix `d60ed0f`
captures are 100 % valid. The pinned Axeyum decides 107 of 107 like z3 with
0 disagreements and 0 nondecisions (median 1.34 s, max 4.70 s, debug build,
30 s wall each). The same tree at both pins runs
`cargo test --features solver-axeyum --no-fail-fast` to 5,249 passed /
1 failed / 19 ignored across 35 binaries with byte-identical per-test
outcomes; the one failure (`ir::ast::tests::an_in_place_update_of_a_coalesced_slot_…`)
is a decompiler test that fails on master at the old pin too. Controls:
`split_verdicts.py` exits 1 on the unpruned tree and on a flipped z3 column;
the Rust replay fails on a phantom row; making the capture-time parse check
always accept kills exactly its two tests. The July timings
(1.7–3.2× one-shot slower on real driver formulas, and the warm-regime
ratios) are frozen in
`docs/history/axeyum-integration-2026-07/` behind a dated banner and are
unmeasured at the new pin.
**Consequences:** The capability gap the July corpus recorded is closed on
everything it captured; what remains open is performance, which only the
six-cell campaign (Axeyum ADR-0272's harness, list item 3) can answer, and
`solver-002` stays superseded until it does. A future capture that produces a
z3-rejected script is an exporter defect to fix, not a file to add to
`malformed-exports-pre-solver-016/`. The `a6a5cc0` captures' `run.*`
statistics in `capture-v1.json` still describe the original July processes
and are not re-derived; the 973–977 split occurrences `solver-015` and
`solver-016` quote are now known to have been 735 distinct exporter-error
scripts plus the residue.
**Alternatives rejected:** deleting the 735 scripts (`solver-016` keeps the
bytes as the reproducer, and a deleted reproducer is a regression waiting to
recur unrecognized); leaving them in place with a note (the improvement list
shows a note is exactly what a file-counting sweep does not read); teaching
Axeyum to accept the mismatched sorts (`solver-016`: that hides a consumer
soundness bug); checking parseability by comparing z3's parsed assertion
count to the emitted count (detects the defect but cannot record z3's error
text, which is what makes the row diagnosable); shelling out to a `z3` binary
at capture time (a second z3 whose version may differ from the linked one).

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
