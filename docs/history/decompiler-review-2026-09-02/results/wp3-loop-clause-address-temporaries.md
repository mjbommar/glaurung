# WP3 loop-clause address-temporary preservation

Date: 2026-09-10

## Correctness defect

Expression reconstruction substitutes a single-use temporary into its
immediately following statement and removes the defining assignment. An
`Expr::Lea` or `Expr::PdbFieldAddr` base/index is a register slot rather than a
nested expression, so substitution intentionally cannot rewrite it. The safety
walker detected those slots in ordinary statements but did not visit `for`
initializers/steps or `throw` values.

Consequently, this shape lost its first statement and retained an undefined
`Temp(0)` in the loop initializer:

```text
t0 = base;
for (cursor = lea(t0 + 8); ...)
```

Commit `05798ef3` makes the address-register safety walker cover every
expression evaluated directly by `For` and `Throw`. It still does not inline
across a nested loop body or weaken the existing single-use and side-effect
boundaries.

## Red/green evidence

The `for` regression was observed red: the reconstructed function contained
only the `For`, whose `Lea.base` still named `Temp(0)`. After the repair:

```text
cargo test --features python-ext ir::expr_reconstruct::tests:: --lib
15 passed; 0 failed; 4762 filtered out
```

The focused module includes the `for` initializer and `throw` address
regressions, the original AArch64 address-index regression, nested-loop use
accounting, and the module's real-binary end-to-end control.

## Exact-release evidence and corrected gate

A clean detached worktree at final validation commit
`1283716a59fb7b1972cec82438708bbf4859994b` was release-built with CPython
3.12.13. `tools/build_guard.py` reported the extension fresh with SHA-256:

```text
71591eeab94a409402f7b1483b6b27337b0b54ab80006b2a2307bd435b038c92
```

The directly adjacent loop canary passed:

```text
uv run --no-sync python tools/dectest.py 03_loop_shapes:gcc:O0:for_sum --show
SCOPED: 1 lane of 838 (0%) - no regressions in scope
```

The eight-cell local-declaration invariant initially reported three failures.
Exact parent/tip comparison showed identical failures, and inspecting the
translation units proved every reported identifier occurred only in a removed
canary slot's analyst comment, for example:

```c
// stack canary: save guard to %local_8
```

There was no executable use. Commit `1283716a` removes C line comments before
collecting declared and used identifiers. This keeps the invariant strict over
compiler-resolved C while excluding prose. On the exact final release build:

```text
pytest -q test_decompiler_emission_invariants.py::test_every_local_used_is_also_declared
8 passed
```

No broad suite, corpus sweep, DecBench run, or baseline refresh was performed.
