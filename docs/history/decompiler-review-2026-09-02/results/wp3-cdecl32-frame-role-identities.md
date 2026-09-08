# WP3 cdecl32 frame-role identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `26f7fe57` removes the remaining production display-name proofs from
cdecl32 entry-realignment recognition. Stack promotion now publishes its own
name-to-parameter-slot facts into `ValueIdentities`; the frame recognizer uses
those facts plus promoted-object ownership instead of parsing `arg0` and
`stack_top`. Opaque owned roles are accepted and misleading spellings fail
closed. The explicit no-sidecar API retains compatibility behavior.

This completes the identified cdecl32 frame-role migration, not WP3 as a whole.

## Focused evidence

```text
cargo test --features python-ext --lib \
  'ir::x86_prologue::tests::identity_aware_cdecl32_frame' -- --nocapture
2 passed; 0 failed

cargo test --features python-ext --lib 'ir::x86_prologue::tests' -- --nocapture
44 passed; 0 failed

uv run maturin develop
uv run python tools/build_guard.py
fresh

uv run python tools/dectest.py \
  '11_call_shapes:gcc:O0:call_into_spill' --arch i386 --show
SCOPED: 1 lane of 3304; no regressions in scope
```

An isolated archive of the exact pushed commit passes all six census checks
and reproduces 5,166 declared Rust tests, 2,461 in `ir`, with zero outside a
gate. This avoids counting an active uncommitted native-decoder lane in the
shared checkout.

The checked-in PE32 `main` test remains red for an unrelated raw string-address
defect. Parent/tip A/B proved the parent rendered `main(void)` plus the raw
address; this increment repairs the signature to two arguments while the raw
address remains. The generated i386 execution test also remains red on its
existing redundant integer casts. Neither failure is claimed green or charged
to this identity migration.

No broad suite, corpus, DecBench, or Joern run was made. The recent four-cell
Hello checkpoint was not repeated.

## Next ordered increment

Re-run the enabled spelling-reader audit. Keep renderer naming predicates and
explicit no-sidecar compatibility paths separate from semantic production
consumers, then migrate the next sidecar-backed decision.
