# 06 - Validation and CI

The integration is only worth shipping if axeyum's answers are provably
consistent with z3's. This mirrors a pattern glaurung already trusts: the
**Unicorn differential oracle** (`exec/oracle.rs`, `dev-oracle`) validates
the concrete emulator against Unicorn. We reuse that shape for the solver.

## The differential oracle (primary gate)

For every query in the corpus, run **both** backends and assert agreement:

```
for (pool, asserts) in corpus:
    let z3  = Z3Solver::new().check(&pool, &asserts);       // reference
    let ax  = AxeyumSolver::new().check(&pool, &asserts);   // under test
    assert verdicts_agree(z3, ax);            // Sat<->Sat, Unsat<->Unsat
    if let (Sat(mz), Sat(ma)) = (z3, ax):
        assert model_satisfies(&pool, &asserts, &mz);   // both models must
        assert model_satisfies(&pool, &asserts, &ma);   // actually satisfy
    // Unknown from either side is tolerated ONLY if the other is also
    // non-decisive OR the deciding side is re-checked (see below).
```

Rules that make this sound rather than merely green:

- **Verdict disagreement Sat-vs-Unsat = hard CI failure** with the
  reproducing formula dumped as SMT-LIB2. This is the bug class that
  matters (a wrong reachability verdict), and it must never merge.
- **Model satisfaction is checked independently**, not trusted: re-evaluate
  the formula under the returned model using glaurung's `Concrete` domain
  (`eval_expr`, already used by the explorer for `concretize_addr`). A
  model that does not satisfy is a failure even if the verdict "agreed."
- **`Unknown` asymmetry is not silently passed.** If z3 decides `Unsat`
  but axeyum returns `Unknown`, that is a coverage gap logged to the
  perf-watch list (P4/P5), not a failure - axeyum is *sound* (it did not
  claim a wrong verdict). If axeyum decides and z3 is `Unknown`, likewise
  logged. The failure condition is only a *confident disagreement*.
- **Proof cross-check (Phase 3+).** When axeyum returns `Unsat`, export the
  DRAT proof and `recheck()` it in-process; a proof that fails its own
  re-check fails CI. Optionally also run `drat-trim` externally on the
  `(dimacs, drat)` pair.

## Corpora

Layered, cheapest first:

1. **Per-operator unit formulas (P2).** One hand-built formula per `Expr`
   variant (Const/Sym/Bin x10/Un x2/Cmp x6/ZExt/SExt/Trunc/Extract/Concat/
   Ite), each at multiple widths incl. W1, W8, W64, and a non-power-of-two
   width. These pin the mapping (`02`) - especially the two flagged
   conventions (`extract` inclusivity, `concat` operand order) and the
   Bool<->BV1 bridge.
2. **Public QF_BV SMT-LIB set.** A slice of standard QF_BV benchmarks
   (axeyum already carries some under its own corpus/`bench-results`);
   run both backends, assert agreement. Bounds the "correct on real
   formulas" claim.
3. **The IOCTLance planted-bug queries.** The formulas glaurung actually
   generates while detecting the planted driver bugs (the `examples/
   ioctlance.rs` corpus). This is the *in-distribution* set - agreement
   here is what makes "axeyum detects the same bugs" true (P4 acceptance).
4. **Regression snapshots.** Every formula that ever caused a
   disagreement is frozen into the corpus so it can never regress.

## Wiring into CI

- A new dev-only feature (e.g. `diff-oracle-smt`, analogous to
  `dev-oracle`) that compiles both `solver-z3` and `solver-axeyum` and runs
  the differential harness. Never shipped; CI-only.
- Determinism: fix any solver seeds; the harness must be reproducible so a
  failure reproduces from the dumped SMT-LIB2.
- Runtime bound: the oracle runs under the same per-solve timeout as
  production (250 ms) plus a corpus-level cap, so CI stays fast; large
  benchmarks go in a nightly lane, the unit + IOCTLance sets in PR CI.

## Acceptance mapping (which corpus gates which phase)

| phase | gate |
|---|---|
| P1 | in-process bridge agrees with z3 on a fixed query set; models satisfy |
| P2 | per-operator unit formulas all agree (mapping pinned) |
| P3 | full differential CI green (corpora 1-3); one Unsat proof rechecks |
| P4 | IOCTLance parity on the default (axeyum) build == z3 detections |
| P5 | no correctness regression on corpora while perf improves |
| P6 | one real AArch64 `.ko`: reachable path Sat+model, unreachable Unsat+proof |

## Honest-status scorecard (kept in the repo, updated per phase)

A short table in this dir (or STATUS) tracking, per capability: which
corpus validated it, at what assurance (agreed-with-z3 / model-checked /
DRAT-rechecked), and the known gaps - the same "capability x assurance x
evidence" discipline axeyum applies to itself. No capability is claimed
"done" without a green corpus row behind it.
