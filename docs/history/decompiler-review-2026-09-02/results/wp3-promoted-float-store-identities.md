# WP3 promoted float-store identities

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `84099fbb` migrates the promoted-store branch of float-copy type
refinement away from `local_` and `stack_` display spelling. Stack promotion's
typed object ownership now survives presentation aliasing and explicit rename
transactions. Production type-map refinement consumes the AST-projected
identity sidecar: an opaque owned object is eligible, while a misleading
unowned `local_c` declines.

## Focused validation

```text
float_store_refinement_accepts_an_owned_opaque_stack_object: 1 passed
float_store_refinement_rejects_an_unowned_local_spelling: 1 passed
presentation_aliases_project_promoted_stack_ownership: 1 passed
python_bindings::ir::type_maps::tests: 22 passed
python/tests/test_test_census.py: 6 passed
```

The regenerated census records 5,130 declared Rust tests and zero outside
every gate. The debug extension was rebuilt and `tools/build_guard.py` reported
it fresh.

The directly relevant
`172_float_double_widths:clang:O0:accumulate_wide` fixture is red against its
baseline. A controlled source A/B rebuilt the parent, captured its rendered C,
rebuilt the tip, and compared the two files: they are byte-identical. The
failure therefore predates this increment and remains type/output baseline
debt; it is not a regression attributed to this identity migration.

No broad Rust/Python suite, fixture matrix, DecBench, or Joern lane ran.

## Periodic Hello World canary

The current `main` output for the checked-in C Hello World samples was compiled
as C for four deliberately small cells: amd64 and arm64, Clang O0 and O2. All
four pass syntax compilation. The amd64 O2 recovered executable matches the
original output and exit status when both receive the same `argv[0]`.

The canary also exposes two existing limits rather than hiding them:

- O0 `main` alone is not link-complete because it calls internal `print_sum`
  and `static_function` bodies that a single-function export does not include.
- arm64 O2 omits the value argument to the second variadic `printf` and uses a
  wide unsigned expression for `%d`. Its host-recompiled output is therefore
  behaviorally wrong. This belongs to the remaining WP6/WP9 call-value and
  target-aware type work, not to the current WP3 identity change.

This four-cell compile canary should be repeated periodically; executable
comparison must control `argv[0]`, because this program sums argument-string
lengths.
