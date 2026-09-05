# WP5 production dense guarded-switch evidence — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

## Outcome

The exact typed evidence already proved in discovery and shadow v2 now reaches
the production structurer for the real Clang O2
`204_adjacent_dispatch_tables::adt204_guarded_control` fixture. Production
output contains cases `0..6` plus the guard's out-of-table default, contains no
unrecovered indirect-jump placeholder, recompiles, and matches the original on
all 34 deterministic execution cases. The committed fixture status therefore
moves from `fail` to `pass`.

The safety condition is semantic, not merely structural. The production CFG
records whether a branch condition transitively consumes an unsigned
comparison in SSA. Only that proof permits a dense dispatch's explicit
out-of-table sibling to become its formal default. A superficially similar
conditional without that unsigned range proof is refused, avoiding the false
positive that a successor-shape-only rule would introduce.

## Production and test surface

- `src/ir/structure/cfg.rs` derives and caches the SSA-transitive unsigned
  comparison fact for each branch condition.
- `src/ir/structure/switch_shape.rs` uses that fact to retain the canonical
  dense-table default and accounts for default-only blocks without duplicating
  shared case suffixes.
- `src/ir/structure.rs` has a reduced production test requiring the formal
  out-of-table default, complete typed-edge accounting, and clean structural
  verification.
- `src/ir/structure_v2/mod.rs` extends the real fixture assertion to require
  the same exact production switch and successful deterministic execution.
- `tests/decompiler_fixtures/baseline.json` records the single reviewed
  `fail` to `pass` movement.

## Validation

- The real production output has exact cases `0..6`, its default, no indirect
  placeholder, and passes 34 of 34 deterministic execution cases.
- All 20 selected fixture-204 cells pass.
- All 55 focused production-structure tests pass.
- The required `cargo test --features python-ext` gate passes at this exact
  source: 4,091 library tests passed, zero failed, and five were ignored; all
  integration and documentation targets also passed.
- The low-level full harness completed all 838 lanes: 2,950 pass, 378 known
  fail, 121 structural, zero missing, zero no-case, and zero infrastructure
  lanes. Its exit status is 1 because that command reports known failures.
- The baseline-aware full comparison reports 34 older unrecorded improvements
  and one `169_rust_slices_bounds:rustc:O0:rust_slice_get` regression. An
  isolated detached worktree at clean `55ab688b` reproduces that failure with
  identical rendered C, proving it predates this increment. No regression in
  the full comparison is attributable to the dense-switch repair.

These results establish the production repair for this host fixture. They do
now establish clean structural ownership for its shared return tail as well.
`Region::Borrowed` records that a proven return tail is rendered with the
predecessor-specific SSA value at an early-exit site without becoming a second
owner of the machine block. The cell reports neither `EdgeUnaccounted` nor
`BlockDuplicated`, and its rendered C remains unchanged.

The first attempted repair used a plain `Goto`. The full matrix correctly
rejected it: `152_deep_nesting:clang:O2:deep152_while_tower` began returning an
undefined normal-path value from its early error guards. The borrowed-region
form preserves that function's existing passing execution result. The final
838-lane rerun therefore returns to the prior evidence boundary: 34 older
unrecorded improvements and only the independently proven pre-existing
`rust_slice_get` baseline mismatch, with no regression attributable to this
repair.

WP5 is therefore not complete: discovery, accounting, both structurers, and
rendering still need one shared case/default/provenance object, and the
remaining compiler and architecture lanes still require explicit execution
evidence and decline classification.

No DecBench run or upstream interaction was performed.
