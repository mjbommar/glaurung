# WP3 cdecl32 stack-walker expression origins

Date: 2026-09-09

Commit: `da766b86`

## Defect

The cdecl32 argument folder uses one recursive expression visitor for two
correctness decisions: refusing to hoist an argument that reads `esp`, and
rebasing surviving `esp`-relative displacements after push setup is folded.
That visitor stopped at `Expr::Origin`. Provenance could therefore hide a stack
read from the refusal and could leave a surviving address based at the wrong
slot after the machine stack decrements disappeared.

The same walker also omitted numeric conversions and expression calls. Its
stack classifier recognized ordinary `Lea` bases but not the equivalent
PDB-field address form.

## Change

`src/ir/call_args/cdecl32.rs` now descends through expression-origin carriers,
numeric conversions, and call targets/arguments in both immutable and mutable
walks. The stack-pointer classifier treats `PdbFieldAddr` and `Lea` bases
uniformly. Rewrites mutate only the enclosed displacement, leaving the origin
carrier intact.

This does not broaden call folding. An argument that observes the moving stack
pointer still causes the complete fold to decline; only metadata can no longer
hide that fact.

## Focused RED/GREEN evidence

The new contract wraps an `esp + 12` address in an integer view and an
expression owner. Before the repair the stack-read check returned false. After
the repair it refuses the unsafe classification, rebases the enclosed address
to `esp + 4`, and retains its exact owner:

```text
cargo test --features python-ext --lib \
  ir::call_args::cdecl32::tests::cdecl_stack_visitors_are_expression_origin_transparent --quiet
1 passed; 0 failed

cargo test --features python-ext --lib cdecl --quiet
31 passed; 0 failed
```

No broad Rust or Python suite ran.

## Exact release evidence

Commit `da766b86` was built in a detached clean worktree. The build guard
reported `fresh`, and Python imported the extension from that exact worktree.
The directly affected spill and execution checks pass:

```text
python tools/dectest.py '11_call_shapes:*:*:call_into_spill' \
  --arch i386 --jobs 2 --full
i386 O0 pass; i386 O2 pass; no regressions in scope

python -m pytest -q \
  python/tests/test_pe32_cdecl_roundtrip.py::test_i386_cdecl_decompile_recompile_execute_round_trip
1 passed
```

The requested periodic Hello checkpoint also passed on the exact release
build, limited to three symbols/PIE GCC-O2 cells:

```text
x86-64:  pass
AArch64: pass
ARMv7:   pass
```

This is a targeted checkpoint, not the complete 72-cell grid.

## Boundary

This closes the cdecl32 recursive stack-walker slice only. Other enabled raw
expression consumers and universal production attribution keep WP3 open.
