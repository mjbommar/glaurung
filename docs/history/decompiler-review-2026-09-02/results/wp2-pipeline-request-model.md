# WP2 pipeline-owned request model

Date: 2026-09-06

Behavioral commit: `d6a65779`

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

## Validation

- Pipeline budget field-preservation unit: passed.
- `python/tests/test_decompiler_session.py`: three passed, including exact
  equality between module-level and reusable-session output.
- Release extension rebuild: passed.
- `cargo test --features python-ext`: 4,201 library tests passed, zero failed,
  five ignored; all integration and documentation targets passed. The long
  identity-retrieval target reports 44 passed and ten ignored.
