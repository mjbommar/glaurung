# WP5 chained strict-guard evidence — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

## Outcome

WP5 now preserves the exact edge-local bound from chained unsigned x86 range
guards. `ja`/`jnbe` leave an inclusive fallthrough range `[0, N]`, while
`jae`/`jnb` leave the exclusive range `[0, N)`. The comparison-only proof is
carried across the guard's one-instruction block without leaking onto the
taken edge or weakening unrelated inherited facts.

The real Clang O2 `204_adjacent_dispatch_tables::adt204_guarded_control`
fixture uses `cmp edi, 7; ja ...; jae ...` before a seven-entry table adjacent
to another table. Discovery now retains exactly seven targets, values `0..6`.
The independently verified shadow-v2 tree consumes those typed cases, renders
no indirect-jump placeholder, and passes the execution differential on all 34
deterministic cases.

## Honest boundary

The default legacy structurer still fails this fixture cell. The production
gain is exact typed discovery plus a verified, executable shadow-v2 result; it
is not evidence that shadow v2 is ready to become the default. The committed
fixture baseline therefore remains unchanged. WP5 still needs the shared
case/default/provenance object, the remaining compiler and architecture cells,
and a disposition for every residual typed decline.

## Production and test surface

- `src/analysis/cfg/ctrl_flow.rs` distinguishes inclusive and exclusive
  unsigned fallthrough guards.
- `src/analysis/dispatch.rs` exports the exact comparison-derived bound and
  refuses the empty strict range.
- `src/analysis/cfg/walk.rs` transports that proof on the correct CFG edge.
- `src/analysis/dispatch/memory_guard.rs` preserves the same exact tightening
  for comparison-proved memory locations.
- `src/ir/structure_v2/mod.rs` checks the real fixture's seven successors,
  ordered case values, verified tree, parseable C, and absence of an
  unrecovered indirect jump.

Focused tests cover the branch-alias truth table, strict-bound tightening and
refusal, and the real adjacent-table fixture. The shadow-v2 execution route
then supplied the behavioral oracle: 34 of 34 deterministic cases passed.

No DecBench run or upstream interaction was performed.
