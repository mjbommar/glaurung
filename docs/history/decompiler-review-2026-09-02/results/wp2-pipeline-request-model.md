# WP2 pipeline-owned request model

Date: 2026-09-06

Behavioral commits: `d6a65779`, `5a2d6c86`

## Boundary moved

The module-level and reusable-session `decompile_at` adapters previously
passed eleven positional orchestration arguments into a function still owned
by `ir.rs`. They now construct one pipeline-owned `DecompileRequest` carrying:

- the normalized function-address request;
- an `AnalysisBudget` with function, block, instruction, per-function time,
  and whole-analysis time limits; and
- `RenderOptions` for style, typing, debug data, and analyst overlays.

`AnalysisBudget::discovery` is the single conversion to CFG discovery limits.
This prevents these two adapters from silently dropping a limit while the
remaining entry points migrate.

## Deliberate boundary

This is the first WP2 production slice, not completion. `decompile_range_at`,
`decompile_all`, and `decompile_many` still own duplicated orchestration. The
pipeline-owned structured result, completeness/provenance, fingerprint,
checked pass stages, and bounded fixpoint driver also remain open. No new
public Python API or output format is claimed.

## Exact-range convergence

The first full-text four-entry-point differential exposed a real semantic
split. For the exact 38-byte `08_indirect_dispatch::tail_dispatch` range,
address, many, and all emitted the same structured switch and preserved two
indirect-call arguments. Range synthesized one basic block, discarded the CFG,
used empty direct-callee facts, and emitted a zero-argument indirect call.

`5a2d6c86` makes a range request reuse ordinary discovered CFG and callee facts
only when every discovered block fits inside the caller's exact range. An
undiscovered or out-of-range function retains the old explicit-window fallback;
the API does not silently expand beyond the caller's bound. All four public
paths now emit the same 759-byte pseudocode for the pinned case.

The same commit routes range/all/many discovery through the pipeline-owned
`AnalysisBudget` conversion. It does not yet make those three adapters construct
`DecompileRequest`, and their remaining per-function orchestration is still
duplicated.

## Validation

- Pipeline budget field-preservation unit: passed.
- `python/tests/test_decompiler_session.py`: three passed, including exact
  equality between module-level and reusable-session output.
- Release extension rebuild: passed.
- `cargo test --features python-ext`: 4,201 library tests passed, zero failed,
  five ignored; all integration and documentation targets passed. The long
  identity-retrieval target reports 44 passed and ten ignored.
- `python/tests/test_decompiler_entrypoint_equivalence.py`: one full-text
  four-entry-point differential passed.
- Declaration authority, PDB type recovery, session reuse, and entry-point
  equivalence focused set: 22 passed.
