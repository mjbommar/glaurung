# Solver ADR-037 — Axeyum is authoritative for every SAT/SMT decision

> **Kind:** decision · **Status:** maintained

**ADR status:** Held since 2026-09-17.

**Context:** Glaurung's hybrid analysis had proved its first counterfactual
gates with a Z3-authoritative build even though Axeyum is the project's own
solver and intended production reasoning substrate. That made the evidence
prove the wrong backend.

**Decision:** Every SAT/SMT problem in Glaurung is decided authoritatively by
Axeyum. This includes symbolic execution, counterfactual analysis, production
builds, tests, fixtures, and benchmarks. `solver-axeyum` is a default feature.
Enabling `solver-z3` also enables Axeyum; Z3 may execute only in an explicitly
labelled differential/comparison mode, and `solve()` still returns Axeyum's
result. Bitwuzla remains comparison-only. Development gates should additionally
exercise the current sibling checkout at `../axeyum`; committed dependencies
remain git-revision pinned so a standalone checkout is reproducible.

**Consequences:** A Z3-only success cannot establish a Glaurung SAT/SMT
capability. Solver-backed reports identify `axeyum-native`. Comparison metrics
retain separate backend outcomes, timing, and disagreement evidence, but cannot
silently change the accepted path, model, witness, or finding. Builds that
explicitly disable default features and omit Axeyum return `NoSolver`; they
never fall through to the legacy subprocess pipe.

**Supersedes:** the authority and default-status conclusions in
[`solver-002`](solver-002-axeyum-as-default-backend.md) and
[`exec-0005`](exec-0005-native-solver-first.md). Their historical integration
record remains useful; this decision controls current backend authority.
