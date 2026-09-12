# WP3 loop-entry coalescing requires identities

> **Kind:** record · **Date:** 2026-09-12

## Outcome

Commit `07a67892` removes loop-entry coalescing's last display-name authority.
Production had already supplied `ValueIdentities`, but the module still exposed
a no-sidecar compatibility wrapper whose fallback treated any `varN` spelling
as a semantic value role. That wrapper and parser are now deleted.

`coalesce_loop_entry_copies_with_identities` requires the sidecar in its Rust
type signature. Its sole production call passes the renderer transaction's
pipeline-owned identity snapshot, and eligibility requires an unambiguous
physical base from that snapshot. A value named `var3` with no identity now
fails closed; presentation text cannot authorize the rewrite.

The legacy tests were migrated to explicit SSA identities rather than keeping
a test-only semantic parser. Successful coalescing still returns its exact
rename map and the production caller applies that map transactionally to the
same sidecar.

## Focused evidence

- Repository search finds one production call and no call without an identity
  argument, no no-sidecar wrapper, and no `var` prefix parser in
  `src/ir/latch_predicate.rs`.
- `cargo test --lib --features python-ext ir::latch_predicate::tests -- --nocapture`
  executes and passes all 17 owning tests, including exact, coalesced,
  ambiguous, missing-identity, live-source, type, goto, and protected-local
  boundaries.
- A fresh release extension build completed with
  `TMPDIR=/home/mjbommar/.cache/glaurung/tmp uv run maturin develop --release`.
- `uv run python tools/dectest.py @loops --full` reports all 12 selected loop
  lanes passing with no scoped regression.
- Six exact GCC symbols/PIE Hello tests pass at O0 and O2 on x86-64, AArch64,
  and ARMv7.

No broad Rust/Python suite, complete fixture matrix, DecBench run, or upstream
interaction was performed. The release build included concurrent uncommitted
source-metrics and stack-local work in the shared checkout; the commit owns
only the loop-entry implementation, its tests, and the one production caller.
This closes one compatibility seam, not WP3's remaining name consumers or
universal origin coverage.
