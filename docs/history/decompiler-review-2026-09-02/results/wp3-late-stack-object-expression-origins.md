# WP3 late stack-object expression origins

Date: 2026-09-08

Commit: `0b764bc8`

## Defect and repair

Late address-taken reconciliation converts earlier promoted scalar spellings
into accesses through the final bounded stack object. It recognized only a
literal `Expr::Reg`. With an expression-origin carrier present:

- a load address fell into the general value walker and became a second nested
  dereference; and
- a store address was not converted to `StackAddr` at all.

`src/ir/stack_locals/rewrite.rs` now classifies the semantic register beneath
the carrier and mutates only that semantic node. The original origin wrapper
therefore remains intact around the recovered object address. Plain registers
outside the object map still return unchanged, which the complete owning module
protects.

## Focused validation

The combined load/store contract
`attributed_late_object_addresses_reconcile_without_double_dereference` was
observed red before the repair and green afterward. The first broader owning-
module run caught an incomplete plain-register return in the initial patch;
after correction:

```text
running 117 tests
test result: ok. 117 passed; 0 failed; 4561 filtered out
```

No repository-wide Rust or Python suite ran.

Validation used a detached clean worktree with only the owned patch, a separate
virtual environment, and cache-backed build directories:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-origin-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/dectest.py \
  218_cpp_lambdas_and_callables:gcc:O0:mixed_capture --show
```

Result:

```text
SCOPED: 1 lane of 838 (0%) - no regressions in scope
```

The fixture is the directly relevant C++ mixed-capture stack-object lane. This
proves focused non-regression only; universal expression attribution and the
remaining WP3 semantic readers remain open.
