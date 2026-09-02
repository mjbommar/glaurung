# Solver ADR-025 — Make the production Axeyum backend QF_BV-profile explicit

> **Kind:** decision · **Status:** maintained

**ADR status:** Accepted.
**Context:** The artifact review found that Glaurung's `solver-axeyum` feature
implicitly selected Axeyum's former full default, even though the production
native translator uses only the scalar QF_BV API. The same module also retained
the P1 SMT-LIB text bridge, whose `solve_smtlib` calls genuinely require the
full parser and multi-theory facade. Treating both paths as one feature made the
minimal-footprint claim false and made a direct switch to `qfbv` fail to
compile.
**Decision:** Consume `axeyum-solver` with defaults disabled and exactly the
`qfbv` feature under `solver-axeyum`. Move the reference-only text bridge behind
an additive `solver-axeyum-text` feature that explicitly enables
`axeyum-solver/full`. Compile its imports, implementation, and tests only under
that feature. Keep the native translator, warm engine, model replay, proof
export, and production selection policy unchanged.
**Evidence:** Before the split, `cargo check --features
solver-z3,solver-axeyum` failed because `solve_smtlib` and
`solve_smtlib_get_value` are absent from the QF_BV profile. After the split the
same production-profile check passes, and `cargo tree --features
solver-axeyum -e features` contains only `axeyum-solver feature "qfbv"`; no
full-only Axeyum crate is active. `cargo check --features solver-axeyum-text`
separately proves that the legacy bridge remains buildable.
**Consequences:** The wheel-facing direct backend now realizes the claimed
minimal solver surface rather than relying on a default-feature accident. The
text bridge stays available for reference tests but is visibly a full-profile
tool and cannot silently bloat production builds. This changes neither solver
authority nor benchmark semantics.
**Alternatives rejected:** delete the useful reference bridge; expand `qfbv` to
include the whole SMT-LIB/multi-theory facade; duplicate a parser in Glaurung;
or describe the dependency as minimal while continuing to activate `full`.

---

Part of the solver decision series; the index is
[`docs/decisions/README.md`](README.md). The subsystem these records
govern is described in
[`docs/architecture/solver-backends.md`](../architecture/solver-backends.md).
